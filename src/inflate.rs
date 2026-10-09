//! Decompression of DEFLATE (RFC 1951), zlib (RFC 1950) and gzip (RFC 1952) data, written from scratch as a push-style
//! streaming decoder with limits. It reads and writes slices and does no I/O of its own, so it works the same on a socket, a
//! file or a buffer, and it is part of the pure half of the crate.
//!
//! Compressed input from a stranger is the classic way to exhaust a machine: a megabyte of DEFLATE can stand for a gigabyte of
//! zeros (DEFLATE cannot do better than 1032 to 1, but that is plenty). So the decoder never grows anything by itself. The
//! caller hands it an output slice of a size of its own choosing, and [`Limits`] say how much it may produce in all and, if
//! wanted, how much more than the input it consumed. A stream that would pass a limit is refused with an error, not truncated:
//! a half of an archive is not a smaller archive.
//!
//! ```
//! use pratique::inflate::{decode_all, Format, Limits};
//! // "hello hello hello hello" as zlib
//! let z = [0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x27, 0x01, 0x68, 0x03, 0x08, 0xb1];
//! assert_eq!(decode_all(Format::Zlib, &z, Limits::new(1 << 20)).unwrap(), b"hello hello hello hello");
//! // the same stream with a limit that is too small
//! assert!(decode_all(Format::Zlib, &z, Limits::new(10)).is_err());
//! ```
//!
//! What it checks, beyond producing the right bytes:
//!
//! * the framing: the zlib header (method 8, a window of at most 32 KiB, the check bits, no preset dictionary) and the Adler-32
//!   at the end; the gzip header (magic, method 8, no reserved flag bits, the header CRC if there is one, a header of at most
//!   128 KiB) and the CRC-32 and the length at the end of each member;
//! * the Huffman codes: a set of code lengths that is over-subscribed is refused, and one that is incomplete is refused unless
//!   it is the single code of length one that the RFC allows (and that only for the literal/length and distance codes: the code
//!   that spells out the lengths must be complete, as in zlib); the code for the end of the block must exist; the symbols that
//!   are in the table but are not allowed (length codes 286 and 287, distance codes 30 and 31) are refused when they occur;
//! * a match never reaches back further than the output of its own stream (the window starts empty for each gzip member);
//! * a stored block's length is checked against its complement.
//!
//! Streaming: input and output may be cut anywhere, down to a byte at a time, and the result is the same. The decoder keeps a
//! window of 32 KiB and the tables of the current block, about 45 KiB in all, and allocates nothing after it is made.
//!
//! The stream ends where the format says it does. [`Format::Zlib`], [`Format::Deflate`] and [`Format::GzipMember`] report
//! [`Status::Done`] at that point and leave the bytes that follow unconsumed (or, if they were already taken into the bit buffer
//! in an earlier call, in [`Inflater::take_unused`]). [`Format::Gzip`] accepts any number of members, as `gzip` itself does, so
//! it cannot know from the data that the last one was the last: the caller says so by calling [`Inflater::finish`] when its input
//! has ended, which fails if the stream stops anywhere else than between members.

const WINDOW: usize = 32768;
const MASK: usize = WINDOW - 1;
/// Bits indexed by the first lookup table; codes longer than this take the slow path (they are rare by construction).
const FAST_BITS: u32 = 10;
const FAST_MASK: u64 = (1 << FAST_BITS) - 1;
/// The most a gzip header (with its name, comment and extra field) may take.
const MAX_GZIP_HEADER: u32 = 128 * 1024;

/// What the data is wrapped in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Bare DEFLATE (RFC 1951), as in zip entries and PNG-less raw streams.
    Deflate,
    /// DEFLATE inside a zlib wrapper (RFC 1950).
    Zlib,
    /// A zlib wrapper if the data starts like one and bare DEFLATE if not: what HTTP's `Content-Encoding: deflate` means in
    /// practice (the RFC says zlib, and some servers send the bare form).
    ZlibOrDeflate,
    /// One or more gzip members one after the other (RFC 1952), as `gzip -d` takes them.
    Gzip,
    /// Exactly one gzip member; what follows it is left alone.
    GzipMember,
}

/// What the decoder may produce. The limit on the output is the one that matters; the ratio is a second line for callers that
/// know what to expect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes the whole stream (every gzip member together) may decompress to.
    pub max_output: u64,
    /// If not zero: the output may not exceed this many times the input read so far, once it has passed `ratio_floor`. It is checked
    /// where the stream says how much output is coming (each literal, match and stored block), so the verdict is the same however the
    /// input and the output are cut. DEFLATE reaches about 1000 to 1 on runs of one byte, so a value under that refuses honest data
    /// of that kind.
    pub max_ratio: u64,
    /// The size the output may reach before the ratio is looked at (small streams have large ratios for no reason).
    pub ratio_floor: u64,
}

impl Limits {
    /// A limit on the output and nothing else.
    pub const fn new(max_output: u64) -> Limits {
        Limits { max_output, max_ratio: 0, ratio_floor: 0 }
    }

    /// No limit at all: only for data that is already trusted, or for tests.
    pub const fn unlimited() -> Limits {
        Limits { max_output: u64::MAX, max_ratio: 0, ratio_floor: 0 }
    }

    /// Adds a limit on the ratio of output to input, checked once the output has passed `floor` bytes.
    pub const fn with_ratio(mut self, max_ratio: u64, floor: u64) -> Limits {
        self.max_ratio = max_ratio;
        self.ratio_floor = floor;
        self
    }
}

/// Why a stream was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The data is not a valid stream; the reason.
    Corrupt(&'static str),
    /// The data ends before the stream does.
    Truncated,
    /// A checksum or a length at the end does not match what was decompressed (`crc32`, `adler32`, `length`, `header crc`).
    Checksum(&'static str),
    /// The stream would decompress to more than [`Limits::max_output`] bytes.
    OutputLimit { limit: u64 },
    /// The output passed [`Limits::max_ratio`] times the input.
    RatioLimit { ratio: u64 },
    /// A feature of the format that is not supported (a zlib preset dictionary).
    Unsupported(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Corrupt(m) => write!(f, "invalid compressed data: {m}"),
            Error::Truncated => f.write_str("compressed data ends too early"),
            Error::Checksum(what) => write!(f, "compressed data fails its check ({what})"),
            Error::OutputLimit { limit } => write!(f, "the data decompresses to more than the limit of {limit} bytes"),
            Error::RatioLimit { ratio } => write!(f, "the data decompresses to more than {ratio} times its size"),
            Error::Unsupported(m) => write!(f, "unsupported compressed data: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// What the decoder wants next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// All of the input was taken and the stream is not at its end: call again with more (or [`Inflater::finish`] if there is none).
    NeedInput,
    /// The output slice is full: call again with room.
    NeedOutput,
    /// The stream is complete.
    Done,
}

/// What one call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Bytes taken from the input.
    pub consumed: usize,
    /// Bytes written to the output.
    pub produced: usize,
    pub status: Status,
}

// ------------------------------------------------------------------------------------------------ checksums

const CRC_TABLES: [[u32; 256]; 8] = make_crc_tables();

const fn make_crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut c = t[0][i];
        let mut j = 1;
        while j < 8 {
            c = t[0][(c & 0xff) as usize] ^ (c >> 8);
            t[j][i] = c;
            j += 1;
        }
        i += 1;
    }
    t
}

/// The CRC-32 (IEEE 802.3, as gzip uses it) of `data` continued from `crc` (0 to start).
pub fn crc32(crc: u32, mut data: &[u8]) -> u32 {
    let t = &CRC_TABLES;
    let mut c = !crc;
    while data.len() >= 8 {
        let lo = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) ^ c;
        let hi = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        c = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
        data = &data[8..];
    }
    for &b in data {
        c = t[0][((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

/// The Adler-32 of `data` continued from `adler` (1 to start).
pub fn adler32(adler: u32, data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    // the longest run of bytes after which the sums cannot have overflowed 32 bits
    const NMAX: usize = 5552;
    let (mut a, mut b) = (adler & 0xffff, adler >> 16);
    for chunk in data.chunks(NMAX) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

// ------------------------------------------------------------------------------------------------ Huffman codes

const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// The order in which the lengths of the code length code are sent (RFC 1951, 3.2.7).
const CLEN_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// What a table lookup found.
enum Lookup {
    /// A symbol and the number of bits its code takes.
    Found(u16, u32),
    /// The bits so far are a prefix of a code, or none at all: more are needed.
    More,
    /// No code starts like this.
    Bad,
}

/// A canonical Huffman code: a table for codes of up to [`FAST_BITS`] bits, and the counts per length for the longer ones.
struct Huff {
    /// Indexed by the next FAST_BITS bits of input: `length << 9 | symbol`, or 0 if the code is longer or does not exist.
    fast: [u16; 1 << FAST_BITS],
    /// The number of codes of each length.
    count: [u16; 16],
    /// The symbols in the order of their codes (by length, then by value).
    symbol: [u16; 288],
    /// The length of the longest code (0 if there is none): bits that are not the start of any code are known to be invalid
    /// once this many have been seen, which matters for a code that is not complete.
    max_len: u32,
}

impl Huff {
    fn new() -> Huff {
        Huff { fast: [0; 1 << FAST_BITS], count: [0; 16], symbol: [0; 288], max_len: 0 }
    }

    /// Builds the code from the length of each symbol's code (0 for none). Returns whether the code is complete, or an error if
    /// it is over-subscribed.
    fn build(&mut self, lens: &[u8]) -> Result<bool, Error> {
        self.count = [0; 16];
        self.fast = [0; 1 << FAST_BITS];
        for &l in lens {
            self.count[l as usize] += 1;
        }
        self.count[0] = 0;
        self.max_len = (1..16).rev().find(|&l| self.count[l] != 0).unwrap_or(0) as u32;
        let mut left: i32 = 1;
        for len in 1..16 {
            left <<= 1;
            left -= self.count[len] as i32;
            if left < 0 {
                return Err(Error::Corrupt("over-subscribed Huffman code"));
            }
        }
        // where each length's symbols start in `symbol`, and the first code of each length
        let mut offs = [0u16; 17];
        let mut next_code = [0u32; 17];
        let mut code = 0u32;
        for len in 1..16 {
            offs[len + 1] = offs[len] + self.count[len];
            code = (code + self.count[len - 1] as u32) << 1;
            next_code[len] = code;
        }
        for (sym, &l) in lens.iter().enumerate() {
            if l != 0 {
                let o = &mut offs[l as usize];
                self.symbol[*o as usize] = sym as u16;
                *o += 1;
                let c = next_code[l as usize];
                next_code[l as usize] += 1;
                if l as u32 <= FAST_BITS {
                    // the code is sent most significant bit first, and the bit buffer is read from the least significant end
                    let rev = (c.reverse_bits() >> (32 - l as u32)) as usize;
                    let entry = (l as u16) << 9 | sym as u16;
                    let mut i = rev;
                    while i < (1 << FAST_BITS) {
                        self.fast[i] = entry;
                        i += 1 << l;
                    }
                }
            }
        }
        Ok(left == 0)
    }

    /// Looks for a code at the start of the `cnt` valid bits of `buf` (bits above them are not to be trusted).
    #[inline]
    fn lookup(&self, buf: u64, cnt: u32) -> Lookup {
        let e = self.fast[(buf & FAST_MASK) as usize];
        let l = (e >> 9) as u32;
        if l != 0 {
            // The entry was made from the first bits whatever they are; with fewer than FAST_BITS valid, a code that is longer
            // than the valid bits cannot be told from a prefix of one, but one that fits in them is the code.
            return if l <= cnt { Lookup::Found(e & 0x1ff, l) } else { Lookup::More };
        }
        self.slow(buf, cnt)
    }

    /// The canonical decoding, a bit at a time: for the codes longer than the table, and for the bits that start no code.
    fn slow(&self, buf: u64, cnt: u32) -> Lookup {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=self.max_len {
            if len > cnt {
                return Lookup::More;
            }
            code |= ((buf >> (len - 1)) & 1) as i32;
            let c = self.count[len as usize] as i32;
            if code - c < first {
                return Lookup::Found(self.symbol[(index + (code - first)) as usize], len);
            }
            index += c;
            first += c;
            first <<= 1;
            code <<= 1;
        }
        Lookup::Bad
    }
}

// ------------------------------------------------------------------------------------------------ the decoder

/// Where the decoder is in the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Before the header of a zlib or gzip stream, or the first block of a bare one.
    Start,
    GzipHeader,
    ZlibHeader,
    BlockHeader,
    StoredLength,
    /// Copying the bytes of a stored block: how many are left.
    Stored(u32),
    DynamicCounts,
    /// Reading the lengths of the code length code: how many are done.
    DynamicCodeLengths(u8),
    /// Reading the lengths of the literal/length and distance codes: how many are done.
    DynamicLengths(u16),
    /// Decoding the symbols of a Huffman block.
    Codes,
    /// A match whose copy did not fit in the output: its length left and distance.
    Copy(u16, u16),
    Trailer,
    /// The length at the end of a gzip member.
    GzipLength,
    Done,
}

/// How the stream is wrapped, once known.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrapper {
    Raw,
    Zlib,
    Gzip,
}

/// Which tables hold what, so that a run of fixed blocks builds them once.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tables {
    None,
    Fixed,
    Dynamic,
}

/// The pieces of a gzip header, read a byte at a time.
#[derive(Clone, Copy)]
struct GzHeader {
    /// 0: the ten fixed bytes; 1: the length of the extra field; 2: the extra field; 3: the name; 4: the comment; 5: the CRC-16.
    stage: u8,
    flags: u8,
    /// Bytes read of the part in progress.
    got: u32,
    /// The length of the extra field.
    extra: u32,
    /// Bytes of the whole header so far.
    total: u32,
    /// The CRC-32 of the header so far (the header CRC is its low 16 bits).
    crc: u32,
    fixed: [u8; 10],
}

/// The slices of one call.
struct Io<'a> {
    inp: &'a [u8],
    pos: usize,
    out: &'a mut [u8],
    o: usize,
    /// Where the checksum of the output has got to.
    summed: usize,
}

/// What one try at the next symbol of a Huffman block came to.
enum Step {
    Literal(u8, u32),
    End(u32),
    Match { len: u16, dist: u16, used: u32 },
    More,
}

/// A streaming decoder; see the [module documentation](self).
pub struct Inflater {
    format: Format,
    limits: Limits,
    wrapper: Wrapper,
    state: State,
    /// The bit buffer: the next bits of the stream, least significant first. Only the low `cnt` bits count.
    buf: u64,
    cnt: u32,
    window: Box<[u8]>,
    /// Bytes written to the window in all; the next goes to `wpos & MASK`.
    wpos: usize,
    /// How many bytes of the window hold output of the current member (up to its size): a match may reach back this far.
    filled: usize,
    lit: Huff,
    dist: Huff,
    tables: Tables,
    final_block: bool,
    /// Scratch for the code lengths of a dynamic block, and the sizes of its parts.
    lens: [u8; 320],
    hlit: usize,
    hdist: usize,
    hclen: usize,
    /// The code that reads the lengths of the other two.
    clen: Huff,
    gz: GzHeader,
    total_in: u64,
    total_out: u64,
    /// Output of the current member and its running check.
    member_out: u64,
    crc: u32,
    adler: u32,
    /// Members completed (gzip).
    members: u64,
    /// The error that ended the stream, if one did: it is reported again by every later call.
    failed: Option<Error>,
}

impl Inflater {
    pub fn new(format: Format, limits: Limits) -> Inflater {
        Inflater {
            format,
            limits,
            wrapper: Wrapper::Raw,
            state: State::Start,
            buf: 0,
            cnt: 0,
            window: vec![0u8; WINDOW].into_boxed_slice(),
            wpos: 0,
            filled: 0,
            lit: Huff::new(),
            dist: Huff::new(),
            tables: Tables::None,
            final_block: false,
            lens: [0; 320],
            hlit: 0,
            hdist: 0,
            hclen: 0,
            clen: Huff::new(),
            gz: GzHeader { stage: 0, flags: 0, got: 0, extra: 0, total: 0, crc: 0, fixed: [0; 10] },
            total_in: 0,
            total_out: 0,
            member_out: 0,
            crc: 0,
            adler: 1,
            members: 0,
            failed: None,
        }
    }

    /// Bytes of input taken so far, and bytes of output given so far.
    pub fn total_in(&self) -> u64 {
        self.total_in
    }

    pub fn total_out(&self) -> u64 {
        self.total_out
    }

    /// Whether the stream has ended and nothing is left to do.
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// For the caller whose input has ended: whether that is where the stream ends. For a zlib, bare or single-member stream
    /// that means it is complete; for [`Format::Gzip`] it means the data stopped between two members (and there was at least one).
    pub fn finish(&self) -> Result<(), Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        if self.state == State::Done || (self.at_member_boundary() && self.members > 0) {
            Ok(())
        } else {
            Err(Error::Truncated)
        }
    }

    fn at_member_boundary(&self) -> bool {
        self.format == Format::Gzip && self.state == State::GzipHeader && self.gz.total == 0 && self.cnt == 0
    }

    /// The bytes that were taken into the bit buffer in an earlier call and turned out to come after the end of the stream
    /// (there are few: they only exist if the stream ended within the bytes that call took, and the end was not reached in it).
    /// Empty unless the stream is done.
    pub fn take_unused(&mut self) -> Vec<u8> {
        if self.state != State::Done {
            return Vec::new();
        }
        let mut v = Vec::new();
        while self.cnt >= 8 {
            v.push((self.buf & 0xff) as u8);
            self.buf >>= 8;
            self.cnt -= 8;
        }
        v
    }

    /// Decompresses as much as `input` and the room in `output` allow.
    ///
    /// Takes input from the start of `input` and reports how much it took; the caller offers the rest again (with more after it)
    /// in the next call. The same goes for `output`. Nothing is lost whatever the sizes, so a caller can pass a byte at a time
    /// in either direction; it only has to pass a non-empty `output` whenever it wants the stream to advance.
    pub fn inflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if let Some(e) = &self.failed {
            return Err(e.clone());
        }
        let mut io = Io { inp: input, pos: 0, out: output, o: 0, summed: 0 };
        let result = self.run(&mut io);
        self.buf &= if self.cnt >= 64 { u64::MAX } else { (1u64 << self.cnt) - 1 };
        let result = result.map(|status| {
            self.fold(&mut io);
            self.total_in += io.pos as u64;
            status
        });
        match result {
            Ok(status) => Ok(Progress { consumed: io.pos, produced: io.o, status }),
            Err(e) => {
                self.failed = Some(e.clone());
                Err(e)
            }
        }
    }

    // ---- the bit buffer

    /// Takes one more byte of input into the bit buffer, if there is one.
    #[inline]
    fn pull(&mut self, io: &mut Io) -> bool {
        if io.pos >= io.inp.len() {
            return false;
        }
        // (the bits above `cnt` may hold what an earlier bulk read left there: they are not to be trusted, and are dropped)
        self.buf = (self.buf & ((1u64 << self.cnt) - 1)) | (io.inp[io.pos] as u64) << self.cnt;
        io.pos += 1;
        self.cnt += 8;
        true
    }

    /// Makes sure there are `n` (at most 56) valid bits, taking bytes one at a time; false if the input runs out first.
    #[inline]
    fn need(&mut self, io: &mut Io, n: u32) -> bool {
        while self.cnt < n {
            if !self.pull(io) {
                return false;
            }
        }
        true
    }

    /// Fills the bit buffer to 56 bits or more with one read, if the input has eight bytes left.
    #[inline]
    fn refill(&mut self, io: &mut Io) {
        if io.pos + 8 <= io.inp.len() && self.cnt < 56 {
            let w = u64::from_le_bytes([
                io.inp[io.pos],
                io.inp[io.pos + 1],
                io.inp[io.pos + 2],
                io.inp[io.pos + 3],
                io.inp[io.pos + 4],
                io.inp[io.pos + 5],
                io.inp[io.pos + 6],
                io.inp[io.pos + 7],
            ]);
            // The bits above the new `cnt` that this puts in `buf` are the bits of the bytes after the ones counted; they are
            // never looked at as valid, and whatever was above `cnt` before is dropped, so that nothing that moved the input
            // position without them (a stored block copied straight from the input) can leave a wrong bit behind.
            self.buf = (self.buf & ((1u64 << self.cnt) - 1)) | w << self.cnt;
            let bytes = (63 - self.cnt) >> 3;
            io.pos += bytes as usize;
            self.cnt += bytes * 8;
        }
    }

    #[inline]
    fn take(&mut self, n: u32) -> u32 {
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.cnt -= n;
        v
    }

    /// Drops the bits up to the next byte boundary.
    fn align(&mut self) {
        let drop = self.cnt % 8;
        self.buf >>= drop;
        self.cnt -= drop;
    }

    // ---- the output

    /// Folds the output produced since the last time into the running checksum of the member.
    fn fold(&mut self, io: &mut Io) {
        let fresh = &io.out[io.summed..io.o];
        match self.wrapper {
            Wrapper::Gzip => self.crc = crc32(self.crc, fresh),
            Wrapper::Zlib => self.adler = adler32(self.adler, fresh),
            Wrapper::Raw => {}
        }
        io.summed = io.o;
    }

    /// Refuses the output if `n` more bytes would pass the limit.
    #[inline]
    fn room_for(&self, n: u64) -> Result<(), Error> {
        if self.total_out.saturating_add(n) > self.limits.max_output {
            return Err(Error::OutputLimit { limit: self.limits.max_output });
        }
        Ok(())
    }

    /// Refuses `more` bytes of output that the stream has just said it will make, if they take the output past the ratio limit, measured
    /// against the input that has been *read* by then (the bits taken from the bit buffer, in whole bytes, and `extra` bytes more
    /// for a stored block, whose data is input as much as output). The check is made where the stream says how much output is
    /// coming (a literal, a match, the length of a stored block), which is the same place in the stream however the input and
    /// the output are cut, so the verdict is the same for every caller; a check made when a call returns would depend on the size of
    /// the caller's buffers.
    #[inline]
    fn check_ratio(&self, io: &Io, more: u64, extra: u64) -> Result<(), Error> {
        let l = &self.limits;
        if l.max_ratio == 0 {
            return Ok(());
        }
        let out = self.total_out.saturating_add(more);
        let read = ((self.total_in + io.pos as u64) * 8 - self.cnt as u64).div_ceil(8) + extra;
        if out > l.ratio_floor && out > read.saturating_mul(l.max_ratio) {
            return Err(Error::RatioLimit { ratio: l.max_ratio });
        }
        Ok(())
    }

    #[inline]
    fn put_literal(&mut self, io: &mut Io, b: u8) {
        self.window[self.wpos & MASK] = b;
        self.wpos = self.wpos.wrapping_add(1);
        if self.filled < WINDOW {
            self.filled += 1;
        }
        io.out[io.o] = b;
        io.o += 1;
        self.total_out += 1;
        self.member_out += 1;
    }

    /// Writes `n` bytes of the match at distance `dist` (already checked against the history).
    fn put_match(&mut self, io: &mut Io, n: usize, dist: usize) {
        let w = self.wpos & MASK;
        let src = self.wpos.wrapping_sub(dist) & MASK;
        if dist >= n && src + n <= WINDOW && w + n <= WINDOW {
            self.window.copy_within(src..src + n, w);
            io.out[io.o..io.o + n].copy_from_slice(&self.window[w..w + n]);
        } else {
            // overlapping (the match repeats what it has just written) or across the end of the ring: a byte at a time
            for k in 0..n {
                let b = self.window[self.wpos.wrapping_sub(dist).wrapping_add(k) & MASK];
                self.window[self.wpos.wrapping_add(k) & MASK] = b;
                io.out[io.o + k] = b;
            }
        }
        self.wpos = self.wpos.wrapping_add(n);
        self.filled = (self.filled + n).min(WINDOW);
        io.o += n;
        self.total_out += n as u64;
        self.member_out += n as u64;
    }

    // ---- the state machine

    fn run(&mut self, io: &mut Io) -> Result<Status, Error> {
        loop {
            match self.state {
                State::Done => {
                    return Ok(Status::Done);
                }
                State::Start => {
                    self.wrapper = match self.format {
                        Format::Deflate => Wrapper::Raw,
                        Format::Zlib => Wrapper::Zlib,
                        Format::Gzip | Format::GzipMember => Wrapper::Gzip,
                        Format::ZlibOrDeflate => {
                            // two bytes tell: a zlib header has method 8 in the low nibble of the first and its two bytes make a
                            // multiple of 31; a bare stream whose first byte ends in 8 would have to be a stored block with a one
                            // in its padding
                            if !self.need(io, 16) {
                                return Ok(Status::NeedInput);
                            }
                            let (cmf, flg) = ((self.buf & 0xff) as u32, ((self.buf >> 8) & 0xff) as u32);
                            if cmf & 0x0f == 8 && (cmf << 8 | flg) % 31 == 0 {
                                Wrapper::Zlib
                            } else {
                                Wrapper::Raw
                            }
                        }
                    };
                    self.state = match self.wrapper {
                        Wrapper::Raw => State::BlockHeader,
                        Wrapper::Zlib => State::ZlibHeader,
                        Wrapper::Gzip => State::GzipHeader,
                    };
                    self.reset_member();
                }
                State::ZlibHeader => {
                    if !self.need(io, 16) {
                        return Ok(Status::NeedInput);
                    }
                    let h = self.take(16);
                    let (cmf, flg) = (h & 0xff, h >> 8);
                    if cmf & 0x0f != 8 {
                        return Err(Error::Corrupt("zlib: the compression method is not deflate"));
                    }
                    if cmf >> 4 > 7 {
                        return Err(Error::Corrupt("zlib: the window is larger than 32 KiB"));
                    }
                    if (cmf << 8 | flg) % 31 != 0 {
                        return Err(Error::Corrupt("zlib: the header check bits are wrong"));
                    }
                    if flg & 0x20 != 0 {
                        return Err(Error::Unsupported("zlib: a preset dictionary"));
                    }
                    self.state = State::BlockHeader;
                }
                State::GzipHeader => {
                    if !self.gzip_header(io)? {
                        return Ok(Status::NeedInput);
                    }
                    self.state = State::BlockHeader;
                }
                State::BlockHeader => {
                    if !self.need(io, 3) {
                        return Ok(Status::NeedInput);
                    }
                    let h = self.take(3);
                    self.final_block = h & 1 != 0;
                    match h >> 1 {
                        0 => {
                            self.align();
                            self.state = State::StoredLength;
                        }
                        1 => {
                            if self.tables != Tables::Fixed {
                                self.build_fixed()?;
                            }
                            self.state = State::Codes;
                        }
                        2 => self.state = State::DynamicCounts,
                        _ => return Err(Error::Corrupt("invalid block type")),
                    }
                }
                State::StoredLength => {
                    if !self.need(io, 32) {
                        return Ok(Status::NeedInput);
                    }
                    let v = self.take(32);
                    let (len, nlen) = (v & 0xffff, v >> 16);
                    if len != !nlen & 0xffff {
                        return Err(Error::Corrupt("a stored block's length does not match its complement"));
                    }
                    self.check_ratio(io, len as u64, len as u64)?;
                    self.state = if len == 0 { self.after_block() } else { State::Stored(len) };
                }
                State::Stored(left) => {
                    let mut left = left as usize;
                    // whole bytes still in the bit buffer first, then straight from the input
                    while left > 0 && self.cnt >= 8 {
                        if io.o == io.out.len() {
                            self.state = State::Stored(left as u32);
                            return Ok(Status::NeedOutput);
                        }
                        self.room_for(1)?;
                        let b = self.take(8) as u8;
                        self.put_literal(io, b);
                        left -= 1;
                    }
                    while left > 0 {
                        let room = io.out.len() - io.o;
                        if room == 0 {
                            self.state = State::Stored(left as u32);
                            return Ok(Status::NeedOutput);
                        }
                        let avail = io.inp.len() - io.pos;
                        if avail == 0 {
                            self.state = State::Stored(left as u32);
                            return Ok(Status::NeedInput);
                        }
                        let n = left.min(room).min(avail);
                        self.room_for(n as u64)?;
                        let (src_start, src_end) = (io.pos, io.pos + n);
                        // into the window (in at most two pieces) and the output
                        let mut k = 0;
                        while k < n {
                            let w = self.wpos.wrapping_add(k) & MASK;
                            let piece = (n - k).min(WINDOW - w);
                            self.window[w..w + piece].copy_from_slice(&io.inp[src_start + k..src_start + k + piece]);
                            k += piece;
                        }
                        io.out[io.o..io.o + n].copy_from_slice(&io.inp[src_start..src_end]);
                        self.wpos = self.wpos.wrapping_add(n);
                        self.filled = (self.filled + n).min(WINDOW);
                        io.pos += n;
                        io.o += n;
                        self.total_out += n as u64;
                        self.member_out += n as u64;
                        left -= n;
                    }
                    self.state = self.after_block();
                }
                State::DynamicCounts => {
                    if !self.need(io, 14) {
                        return Ok(Status::NeedInput);
                    }
                    let h = self.take(14);
                    self.hlit = (h & 31) as usize + 257;
                    self.hdist = ((h >> 5) & 31) as usize + 1;
                    self.hclen = ((h >> 10) & 15) as usize + 4;
                    if self.hlit > 286 || self.hdist > 30 {
                        return Err(Error::Corrupt("too many length or distance codes"));
                    }
                    self.lens[..19].fill(0);
                    self.state = State::DynamicCodeLengths(0);
                }
                State::DynamicCodeLengths(i) => {
                    let mut i = i as usize;
                    while i < self.hclen {
                        if !self.need(io, 3) {
                            self.state = State::DynamicCodeLengths(i as u8);
                            return Ok(Status::NeedInput);
                        }
                        self.lens[CLEN_ORDER[i]] = self.take(3) as u8;
                        i += 1;
                    }
                    let lens: [u8; 19] = std::array::from_fn(|k| self.lens[k]);
                    let complete = self.clen.build(&lens)?;
                    if !complete && lens.iter().any(|&l| l != 0) {
                        return Err(Error::Corrupt("the code that reads the code lengths is incomplete"));
                    }
                    self.lens.fill(0);
                    self.tables = Tables::None;
                    self.state = State::DynamicLengths(0);
                }
                State::DynamicLengths(i) => {
                    let mut i = i as usize;
                    let total = self.hlit + self.hdist;
                    while i < total {
                        self.refill(io);
                        let (sym, l) = match self.clen.lookup(self.buf, self.cnt) {
                            Lookup::Found(s, l) => (s, l),
                            Lookup::More => {
                                if !self.pull(io) {
                                    self.state = State::DynamicLengths(i as u16);
                                    return Ok(Status::NeedInput);
                                }
                                continue;
                            }
                            Lookup::Bad => return Err(Error::Corrupt("invalid code length code")),
                        };
                        // the extra bits of 16, 17 and 18 come with the symbol: all or nothing
                        let (extra_bits, base) = match sym {
                            0..=15 => (0, 0),
                            16 => (2, 3),
                            17 => (3, 3),
                            _ => (7, 11),
                        };
                        if self.cnt < l + extra_bits {
                            if !self.pull(io) {
                                self.state = State::DynamicLengths(i as u16);
                                return Ok(Status::NeedInput);
                            }
                            continue;
                        }
                        let (value, repeat) = if sym < 16 {
                            (sym as u8, 1)
                        } else {
                            let r = base + ((self.buf >> l) & ((1u64 << extra_bits) - 1)) as usize;
                            match sym {
                                16 => {
                                    if i == 0 {
                                        return Err(Error::Corrupt("a repeat of a previous length with none before it"));
                                    }
                                    (self.lens[i - 1], r)
                                }
                                _ => (0, r),
                            }
                        };
                        if i + repeat > total {
                            return Err(Error::Corrupt("the code lengths run past the end of the table"));
                        }
                        self.take(l + extra_bits);
                        self.lens[i..i + repeat].fill(value);
                        i += repeat;
                    }
                    if self.lens[256] == 0 {
                        return Err(Error::Corrupt("a block with no end-of-block code"));
                    }
                    let (hlit, hdist) = (self.hlit, self.hdist);
                    let lit_lens: Vec<u8> = self.lens[..hlit].to_vec();
                    let complete = self.lit.build(&lit_lens)?;
                    if !complete && lit_lens.iter().any(|&l| l > 1) {
                        return Err(Error::Corrupt("the literal/length code is incomplete"));
                    }
                    let dist_lens: Vec<u8> = self.lens[hlit..hlit + hdist].to_vec();
                    let complete = self.dist.build(&dist_lens)?;
                    if !complete && dist_lens.iter().any(|&l| l > 1) {
                        return Err(Error::Corrupt("the distance code is incomplete"));
                    }
                    self.tables = Tables::Dynamic;
                    self.state = State::Codes;
                }
                State::Codes => {
                    let mut stalled = false;
                    loop {
                        if io.o == io.out.len() {
                            // Even an end-of-block or a match could need no room, but a full output is a stop the caller
                            // asked for, and the next call picks up here.
                            stalled = true;
                            break;
                        }
                        self.refill(io);
                        match self.step() {
                            Err(e) => return Err(e),
                            Ok(Step::Literal(b, used)) => {
                                self.room_for(1)?;
                                self.take(used);
                                self.check_ratio(io, 1, 0)?;
                                self.put_literal(io, b);
                            }
                            Ok(Step::End(used)) => {
                                self.take(used);
                                self.state = self.after_block();
                                break;
                            }
                            Ok(Step::Match { len, dist, used }) => {
                                if dist as usize > self.filled {
                                    return Err(Error::Corrupt("a match reaches back before the start of the data"));
                                }
                                self.take(used);
                                self.check_ratio(io, len as u64, 0)?;
                                self.state = State::Copy(len, dist);
                                break;
                            }
                            Ok(Step::More) => {
                                if !self.pull(io) {
                                    return Ok(Status::NeedInput);
                                }
                            }
                        }
                    }
                    if stalled {
                        return Ok(Status::NeedOutput);
                    }
                }
                State::Copy(len, dist) => {
                    let room = io.out.len() - io.o;
                    if room == 0 {
                        return Ok(Status::NeedOutput);
                    }
                    let n = (len as usize).min(room);
                    self.room_for(n as u64)?;
                    self.put_match(io, n, dist as usize);
                    self.state = if n == len as usize { State::Codes } else { State::Copy(len - n as u16, dist) };
                }
                State::Trailer => {
                    self.fold(io);
                    self.align();
                    match self.wrapper {
                        Wrapper::Raw => self.member_done(io),
                        Wrapper::Zlib => {
                            if !self.need(io, 32) {
                                return Ok(Status::NeedInput);
                            }
                            // big-endian
                            if self.take(32).swap_bytes() != self.adler {
                                return Err(Error::Checksum("adler32"));
                            }
                            self.member_done(io);
                        }
                        Wrapper::Gzip => {
                            if !self.need(io, 32) {
                                return Ok(Status::NeedInput);
                            }
                            if self.take(32) != self.crc {
                                return Err(Error::Checksum("crc32"));
                            }
                            self.state = State::GzipLength;
                        }
                    }
                }
                State::GzipLength => {
                    if !self.need(io, 32) {
                        return Ok(Status::NeedInput);
                    }
                    if self.take(32) != self.member_out as u32 {
                        return Err(Error::Checksum("length"));
                    }
                    self.member_done(io);
                }
            }
        }
    }

    /// What follows the last symbol of a block.
    fn after_block(&self) -> State {
        if self.final_block {
            State::Trailer
        } else {
            State::BlockHeader
        }
    }

    /// Starts the history, the checksum and the header of a member afresh.
    fn reset_member(&mut self) {
        self.filled = 0;
        self.member_out = 0;
        self.crc = 0;
        self.adler = 1;
        self.gz = GzHeader { stage: 0, flags: 0, got: 0, extra: 0, total: 0, crc: 0, fixed: [0; 10] };
    }

    /// A member (or the whole zlib or bare stream) is complete and its trailer has been checked.
    fn member_done(&mut self, io: &mut Io) {
        self.members += 1;
        if self.format == Format::Gzip {
            self.reset_member();
            self.state = State::GzipHeader;
            return;
        }
        // The stream is over. Whole bytes the bit buffer holds that came from this call's input go back to the caller (they follow
        // the stream); any that came from an earlier call stay, for `take_unused`.
        self.align();
        let give = ((self.cnt / 8) as usize).min(io.pos);
        io.pos -= give;
        self.cnt -= (give * 8) as u32;
        self.buf &= if self.cnt >= 64 { u64::MAX } else { (1u64 << self.cnt) - 1 };
        self.state = State::Done;
    }

    fn build_fixed(&mut self) -> Result<(), Error> {
        let mut lens = [0u8; 288];
        for (i, l) in lens.iter_mut().enumerate() {
            *l = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        self.lit.build(&lens)?;
        self.dist.build(&[5u8; 30])?;
        self.tables = Tables::Fixed;
        Ok(())
    }

    /// Reads a gzip header a byte at a time. True when it is complete, false when it needs more input.
    fn gzip_header(&mut self, io: &mut Io) -> Result<bool, Error> {
        // the stage that follows `after` among the optional parts that the flags say are there; 6 is the end
        fn next(flags: u8, after: u8) -> u8 {
            let present = |stage: u8| match stage {
                1 => flags & 4 != 0,
                3 => flags & 8 != 0,
                4 => flags & 16 != 0,
                5 => flags & 2 != 0,
                _ => false,
            };
            let from = match after {
                0 => 1,
                1 | 2 => 3,
                s => s + 1,
            };
            (from..=5).find(|&s| present(s)).unwrap_or(6)
        }
        loop {
            let mut g = self.gz;
            if g.stage == 6 {
                return Ok(true);
            }
            if !self.need(io, 8) {
                return Ok(false);
            }
            let b = self.take(8) as u8;
            g.total += 1;
            if g.total > MAX_GZIP_HEADER {
                return Err(Error::Corrupt("gzip: the header is too long"));
            }
            if g.stage != 5 {
                g.crc = crc32(g.crc, &[b]);
            }
            match g.stage {
                0 => {
                    let i = g.got as usize;
                    g.fixed[i] = b;
                    g.got += 1;
                    // each of the first four bytes is looked at as soon as it is here, so that what is not gzip (bytes after the
                    // last member, say) is called that, and not a stream that ends too early
                    match i {
                        0 | 1 if b != [0x1f, 0x8b][i] => return Err(Error::Corrupt("not gzip data (the magic number is wrong)")),
                        2 if b != 8 => return Err(Error::Corrupt("gzip: the compression method is not deflate")),
                        3 if b & 0xe0 != 0 => return Err(Error::Corrupt("gzip: reserved flag bits are set")),
                        _ => {}
                    }
                    if g.got == 10 {
                        g.flags = g.fixed[3];
                        g.got = 0;
                        g.stage = next(g.flags, 0);
                    }
                }
                1 => {
                    g.extra |= (b as u32) << (8 * g.got);
                    g.got += 1;
                    if g.got == 2 {
                        g.got = 0;
                        g.stage = if g.extra > 0 { 2 } else { next(g.flags, 2) };
                    }
                }
                2 => {
                    g.got += 1;
                    if g.got == g.extra {
                        g.got = 0;
                        g.stage = next(g.flags, 2);
                    }
                }
                3 | 4 => {
                    if b == 0 {
                        g.stage = next(g.flags, g.stage);
                    }
                }
                _ => {
                    // the CRC-16 of the header, low byte first
                    g.extra = if g.got == 0 { b as u32 } else { g.extra | (b as u32) << 8 };
                    g.got += 1;
                    if g.got == 2 {
                        if g.extra != g.crc & 0xffff {
                            return Err(Error::Checksum("header crc"));
                        }
                        g.stage = 6;
                    }
                }
            }
            self.gz = g;
        }
    }

    /// Tries the next symbol of a Huffman block against the bits there are, taking nothing: a literal, the end of the block, or a
    /// whole match (length with its extra bits, distance with its extra bits), or that more bits are needed.
    fn step(&self) -> Result<Step, Error> {
        let (buf, cnt) = (self.buf, self.cnt);
        let (sym, l) = match self.lit.lookup(buf, cnt) {
            Lookup::Found(s, l) => (s, l),
            Lookup::More => return Ok(Step::More),
            Lookup::Bad => return Err(Error::Corrupt("invalid literal/length code")),
        };
        if sym < 256 {
            return Ok(Step::Literal(sym as u8, l));
        }
        if sym == 256 {
            return Ok(Step::End(l));
        }
        if sym > 285 {
            return Err(Error::Corrupt("invalid length code"));
        }
        let li = (sym - 257) as usize;
        let eb = LEN_EXTRA[li] as u32;
        if cnt < l + eb {
            return Ok(Step::More);
        }
        let len = LEN_BASE[li] + ((buf >> l) & ((1u64 << eb) - 1)) as u16;
        let rest = buf >> (l + eb);
        let rcnt = cnt - l - eb;
        let (dsym, dl) = match self.dist.lookup(rest, rcnt) {
            Lookup::Found(s, l) => (s as usize, l),
            Lookup::More => return Ok(Step::More),
            Lookup::Bad => return Err(Error::Corrupt("invalid distance code")),
        };
        if dsym > 29 {
            return Err(Error::Corrupt("invalid distance code"));
        }
        let deb = DIST_EXTRA[dsym] as u32;
        if rcnt < dl + deb {
            return Ok(Step::More);
        }
        let dist = DIST_BASE[dsym] + ((rest >> dl) & ((1u64 << deb) - 1)) as u16;
        Ok(Step::Match { len, dist, used: l + eb + dl + deb })
    }
}

/// Decompresses all of `data`, which must be exactly one stream of `format` (a gzip stream of any number of members), within
/// `limits`. For the case of a whole body in memory; the output grows as it is produced and never past the limit.
pub fn decode_all(format: Format, data: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    let mut inf = Inflater::new(format, limits);
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 32 * 1024];
    let mut pos = 0;
    loop {
        let p = inf.inflate(&data[pos..], &mut chunk)?;
        pos += p.consumed;
        out.extend_from_slice(&chunk[..p.produced]);
        match p.status {
            Status::NeedOutput => {}
            Status::NeedInput => {
                // everything was taken
                inf.finish()?;
                return Ok(out);
            }
            Status::Done => {
                return if pos == data.len() && inf.take_unused().is_empty() { Ok(out) } else { Err(Error::Corrupt("data follows the end of the compressed stream")) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- a small deterministic generator (no dependency, and the same on every machine)

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn chance(&mut self, percent: usize) -> bool {
            self.below(100) < percent
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    // ---- decoding with chosen cuts of the input and the output

    /// Decodes `data` giving the decoder `in_chunk` bytes at a time and room for `out_chunk` bytes at a time.
    fn run_chunked(format: Format, data: &[u8], in_chunk: usize, out_chunk: usize, limits: Limits) -> Result<Vec<u8>, Error> {
        let mut inf = Inflater::new(format, limits);
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        let mut pos = 0usize;
        loop {
            let end = pos.saturating_add(in_chunk).min(data.len());
            let p = inf.inflate(&data[pos..end], &mut buf)?;
            pos += p.consumed;
            out.extend_from_slice(&buf[..p.produced]);
            match p.status {
                Status::NeedOutput => {}
                Status::NeedInput => {
                    assert_eq!(pos, end, "NeedInput means all of the input was taken");
                    if pos >= data.len() {
                        inf.finish()?;
                        return Ok(out);
                    }
                }
                Status::Done => {
                    assert!(inf.is_done());
                    assert_eq!(pos, data.len(), "the stream ended before the data did");
                    return Ok(out);
                }
            }
        }
    }

    fn all(format: Format, data: &[u8]) -> Result<Vec<u8>, Error> {
        decode_all(format, data, Limits::unlimited())
    }

    // ---- an encoder, written for these tests and nothing else: it makes streams of every shape the format allows (stored, fixed
    // and dynamic blocks; matches of every length and distance; codes up to 15 bits; the repeat codes of the code lengths), not
    // good ones, from a description, so that the decoder is checked against something that shares no code with it

    struct Bits {
        out: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl Bits {
        fn new() -> Bits {
            Bits { out: Vec::new(), acc: 0, n: 0 }
        }

        fn put(&mut self, value: u32, bits: u32) {
            self.acc |= (value as u64) << self.n;
            self.n += bits;
            while self.n >= 8 {
                self.out.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
        }

        /// A Huffman code goes most significant bit first.
        fn code(&mut self, code: u32, len: u32) {
            self.put(code.reverse_bits() >> (32 - len), len);
        }

        fn align(&mut self) {
            if self.n > 0 {
                self.put(0, 8 - self.n);
            }
        }

        fn finish(mut self) -> Vec<u8> {
            self.align();
            self.out
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Token {
        Lit(u8),
        Match(usize, usize),
    }

    /// The canonical codes for a list of lengths.
    fn codes_of(lens: &[u8]) -> Vec<u32> {
        let mut count = [0u32; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        let mut code = 0;
        for bits in 1..16 {
            code = (code + count[bits - 1]) << 1;
            next[bits] = code;
        }
        lens.iter()
            .map(|&l| {
                if l == 0 {
                    0
                } else {
                    let c = next[l as usize];
                    next[l as usize] += 1;
                    c
                }
            })
            .collect()
    }

    /// Lengths of a complete prefix code for the symbols `used` (of an alphabet of `alphabet`), none longer than `max_depth`,
    /// chosen at random and skewed towards long ones; one symbol alone gets the one-bit code the format allows.
    fn random_lengths(rng: &mut Rng, alphabet: usize, used: &[usize], max_depth: u8) -> Vec<u8> {
        let mut lens = vec![0u8; alphabet];
        if used.len() == 1 {
            lens[used[0]] = 1;
            return lens;
        }
        let mut depths: Vec<u8> = vec![0];
        while depths.len() < used.len() {
            // split a leaf: often the deepest that can be, to get long codes
            let idx = if rng.chance(60) {
                let deepest = depths.iter().copied().filter(|&d| d < max_depth).max().unwrap();
                depths.iter().position(|&d| d == deepest).unwrap()
            } else {
                loop {
                    let i = rng.below(depths.len());
                    if depths[i] < max_depth {
                        break i;
                    }
                }
            };
            let d = depths.swap_remove(idx);
            depths.push(d + 1);
            depths.push(d + 1);
        }
        // hand the lengths out in random order
        for i in (1..depths.len()).rev() {
            depths.swap(i, rng.below(i + 1));
        }
        for (k, &s) in used.iter().enumerate() {
            lens[s] = depths[k];
        }
        lens
    }

    fn length_symbol(len: usize) -> (usize, u32, u32) {
        let i = (0..29).rev().find(|&i| LEN_BASE[i] as usize <= len).unwrap();
        (257 + i, (len - LEN_BASE[i] as usize) as u32, LEN_EXTRA[i] as u32)
    }

    fn dist_symbol(dist: usize) -> (usize, u32, u32) {
        let i = (0..30).rev().find(|&i| DIST_BASE[i] as usize <= dist).unwrap();
        (i, (dist - DIST_BASE[i] as usize) as u32, DIST_EXTRA[i] as u32)
    }

    fn write_tokens(w: &mut Bits, tokens: &[Token], lit: (&[u8], &[u32]), dist: (&[u8], &[u32])) {
        for t in tokens {
            match *t {
                Token::Lit(b) => w.code(lit.1[b as usize], lit.0[b as usize] as u32),
                Token::Match(len, d) => {
                    let (ls, lextra, lbits) = length_symbol(len);
                    w.code(lit.1[ls], lit.0[ls] as u32);
                    w.put(lextra, lbits);
                    let (ds, dextra, dbits) = dist_symbol(d);
                    w.code(dist.1[ds], dist.0[ds] as u32);
                    w.put(dextra, dbits);
                }
            }
        }
        w.code(lit.1[256], lit.0[256] as u32);
    }

    fn fixed_lengths() -> Vec<u8> {
        (0..288).map(|i| match i { 0..=143 => 8, 144..=255 => 9, 256..=279 => 7, _ => 8 }).collect()
    }

    fn write_fixed(w: &mut Bits, tokens: &[Token], last: bool) {
        w.put(last as u32, 1);
        w.put(1, 2);
        let lens = fixed_lengths();
        let codes = codes_of(&lens);
        let dlens = [5u8; 30];
        let dcodes = codes_of(&dlens);
        write_tokens(w, tokens, (&lens, &codes), (&dlens, &dcodes));
    }

    fn write_stored(w: &mut Bits, data: &[u8], last: bool) {
        w.put(last as u32, 1);
        w.put(0, 2);
        w.align();
        w.put(data.len() as u32, 16);
        w.put(!(data.len() as u32) & 0xffff, 16);
        for &b in data {
            w.put(b as u32, 8);
        }
    }

    fn write_dynamic(w: &mut Bits, rng: &mut Rng, tokens: &[Token], last: bool) {
        // which symbols occur
        let mut lit_used = vec![false; 286];
        let mut dist_used = vec![false; 30];
        lit_used[256] = true;
        for t in tokens {
            match *t {
                Token::Lit(b) => lit_used[b as usize] = true,
                Token::Match(len, d) => {
                    lit_used[length_symbol(len).0] = true;
                    dist_used[dist_symbol(d).0] = true;
                }
            }
        }
        let lit_syms: Vec<usize> = (0..286).filter(|&i| lit_used[i]).collect();
        let dist_syms: Vec<usize> = (0..30).filter(|&i| dist_used[i]).collect();
        let hlit = lit_syms.last().unwrap() + 1;
        let hlit = hlit.max(257);
        let lit_lens = random_lengths(rng, 286, &lit_syms, 15);
        let (hdist, dist_lens) = if dist_syms.is_empty() {
            // no distance is used: one code of length zero says so (or, sometimes, one unused code of one bit)
            if rng.chance(50) { (1, vec![0u8; 30]) } else { let mut l = vec![0u8; 30]; l[rng.below(30)] = 1; (30, l) }
        } else {
            (dist_syms.last().unwrap() + 1, random_lengths(rng, 30, &dist_syms, 15))
        };
        let hdist = if dist_syms.is_empty() && hdist == 30 { 30 } else { hdist };
        // the lengths in one list, with repeat codes where they pay or where the dice say
        let mut all: Vec<u8> = lit_lens[..hlit].to_vec();
        all.extend_from_slice(&dist_lens[..hdist]);
        let mut items: Vec<(usize, u32, u32)> = Vec::new(); // symbol, extra value, extra bits
        let mut i = 0;
        while i < all.len() {
            let v = all[i];
            let mut run = 1;
            while i + run < all.len() && all[i + run] == v {
                run += 1;
            }
            if v == 0 && run >= 3 && rng.chance(80) {
                let n = run.min(138);
                if n >= 11 {
                    items.push((18, (n - 11) as u32, 7));
                } else {
                    items.push((17, (n - 3) as u32, 3));
                }
                i += n;
            } else if v != 0 && i > 0 && all[i - 1] == v && run >= 3 && rng.chance(80) {
                let n = run.min(6);
                items.push((16, (n - 3) as u32, 2));
                i += n;
            } else {
                items.push((v as usize, 0, 0));
                i += 1;
            }
        }
        let mut clen_used = vec![false; 19];
        for it in &items {
            clen_used[it.0] = true;
        }
        let clen_syms: Vec<usize> = (0..19).filter(|&i| clen_used[i]).collect();
        let clen_lens = random_lengths(rng, 19, &clen_syms, 7);
        let clen_codes = codes_of(&clen_lens);
        // HCLEN: as many of the lengths in transmission order as needed, at least four
        let mut hclen = 19;
        while hclen > 4 && clen_lens[CLEN_ORDER[hclen - 1]] == 0 {
            hclen -= 1;
        }
        w.put(last as u32, 1);
        w.put(2, 2);
        w.put((hlit - 257) as u32, 5);
        w.put((hdist - 1) as u32, 5);
        w.put((hclen - 4) as u32, 4);
        for k in 0..hclen {
            w.put(clen_lens[CLEN_ORDER[k]] as u32, 3);
        }
        for (sym, extra, bits) in items {
            w.code(clen_codes[sym], clen_lens[sym] as u32);
            w.put(extra, bits);
        }
        let lit_codes = codes_of(&lit_lens);
        let dcodes = codes_of(&dist_lens);
        write_tokens(w, tokens, (&lit_lens, &lit_codes), (&dist_lens, &dcodes));
    }

    /// Random tokens that make valid output on top of `history`; returns them and the bytes they stand for.
    fn random_tokens(rng: &mut Rng, history: &mut Vec<u8>, count: usize, style: usize) -> Vec<Token> {
        let mut tokens = Vec::new();
        for _ in 0..count {
            let have = history.len();
            let want_match = match style {
                0 => false,
                1 => rng.chance(50),
                _ => rng.chance(80),
            };
            if want_match && have > 0 {
                let max_dist = have.min(32768);
                let dist = match rng.below(4) {
                    0 => 1,
                    1 => max_dist,
                    2 => 1 + rng.below(max_dist.min(300)),
                    _ => 1 + rng.below(max_dist),
                };
                let len = match rng.below(4) {
                    0 => 258,
                    1 => 3,
                    _ => 3 + rng.below(256),
                };
                tokens.push(Token::Match(len, dist));
                for _ in 0..len {
                    let b = history[history.len() - dist];
                    history.push(b);
                }
            } else {
                let b = match style {
                    0 => rng.next() as u8,
                    _ => (rng.below(6) as u8) * 40,
                };
                tokens.push(Token::Lit(b));
                history.push(b);
            }
        }
        tokens
    }

    /// A random deflate stream and what it stands for. `history` starts with the bytes the stream may refer to (none, for a
    /// fresh one).
    fn random_stream(rng: &mut Rng, blocks: usize) -> (Vec<u8>, Vec<u8>) {
        let mut w = Bits::new();
        let mut expected: Vec<u8> = Vec::new();
        for b in 0..blocks {
            let last = b + 1 == blocks;
            match rng.below(3) {
                0 => {
                    let n = if rng.chance(20) { 0 } else { rng.below(3000) };
                    let data = rng.bytes(n);
                    write_stored(&mut w, &data, last);
                    expected.extend_from_slice(&data);
                }
                kind => {
                    let cap = if rng.chance(10) { 40_000 } else { 1500 };
                    let count = 1 + rng.below(cap);
                    let style = rng.below(3);
                    let mut history = expected.clone();
                    let tokens = random_tokens(rng, &mut history, count, style);
                    if kind == 1 {
                        write_fixed(&mut w, &tokens, last);
                    } else {
                        write_dynamic(&mut w, rng, &tokens, last);
                    }
                    expected = history;
                }
            }
        }
        (w.finish(), expected)
    }

    fn zlib_wrap(raw: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut v = vec![0x78, 0x9c];
        v.extend_from_slice(raw);
        v.extend_from_slice(&adler32(1, plain).to_be_bytes());
        v
    }

    fn gzip_wrap(raw: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        v.extend_from_slice(raw);
        v.extend_from_slice(&crc32(0, plain).to_le_bytes());
        v.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        v
    }

    // ---- the checksums

    #[test]
    fn checksums_match_their_published_check_values() {
        assert_eq!(crc32(0, b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(0, b""), 0);
        assert_eq!(adler32(1, b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(1, b""), 1);
        // continued in pieces
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        for cut in [0, 1, 7, 8, 9, 5551, 5552, 5553, 19_999] {
            assert_eq!(crc32(crc32(0, &data[..cut]), &data[cut..]), crc32(0, &data));
            assert_eq!(adler32(adler32(1, &data[..cut]), &data[cut..]), adler32(1, &data));
        }
        // a long run of 0xff, which is what the Adler-32 sums overflow on soonest
        assert_eq!(adler32(1, &vec![0xff; 100_000]), adler_slow(&vec![0xff; 100_000]));
        assert_eq!(adler32(1, &data), adler_slow(&data));
    }

    fn adler_slow(data: &[u8]) -> u32 {
        let (mut a, mut b) = (1u64, 0u64);
        for &x in data {
            a = (a + x as u64) % 65521;
            b = (b + a) % 65521;
        }
        ((b << 16) | a) as u32
    }

    // ---- streams made by the encoder above, decoded in every way the interface allows

    /// The ways of cutting input and output that the tests run through: (bytes of input per call, room for output per call).
    const CUTS: [(usize, usize); 8] = [(usize::MAX, 1 << 16), (1, 1 << 16), (usize::MAX, 1), (1, 1), (3, 5), (7, 1000), (4096, 3), (65536, 65536)];

    fn check_all_cuts(format: Format, stream: &[u8], expected: &[u8], what: &str) {
        for (i, o) in CUTS {
            let out = run_chunked(format, stream, i, o, Limits::unlimited()).unwrap_or_else(|e| panic!("{what}: {e} (input {i}, room {o})"));
            assert!(out == expected, "{what}: wrong output (input {i}, room {o}): {} bytes, expected {}", out.len(), expected.len());
        }
    }

    /// A random stream whose compressed size is at most `max`, for the tests that try every cut or every flipped bit.
    fn small_stream(rng: &mut Rng, max: usize) -> (Vec<u8>, Vec<u8>) {
        loop {
            let blocks = 1 + rng.below(3);
            let (raw, plain) = random_stream(rng, blocks);
            if raw.len() <= max {
                return (raw, plain);
            }
        }
    }

    /// Feeds `data` in pieces of `in_chunk` (offering what is left each time) with room for `out_chunk` until the stream is done;
    /// returns what was produced, how much input was taken, and the decoder.
    fn run_to_done(format: Format, data: &[u8], in_chunk: usize, out_chunk: usize) -> (Vec<u8>, usize, Inflater) {
        let mut inf = Inflater::new(format, Limits::unlimited());
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        let mut pos = 0usize;
        loop {
            let end = pos.saturating_add(in_chunk).min(data.len());
            let p = inf.inflate(&data[pos..end], &mut buf).unwrap();
            pos += p.consumed;
            out.extend_from_slice(&buf[..p.produced]);
            if p.status == Status::Done {
                return (out, pos, inf);
            }
            assert!(pos < data.len() || p.status == Status::NeedOutput, "the data ended before the stream did");
        }
    }

    #[test]
    fn random_streams_decode_to_what_they_stand_for() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        let mut total = 0usize;
        for round in 0..60 {
            let blocks = 1 + rng.below(5);
            let (raw, expected) = random_stream(&mut rng, blocks);
            total += expected.len();
            assert_eq!(all(Format::Deflate, &raw).unwrap(), expected, "round {round}, whole");
            assert_eq!(all(Format::ZlibOrDeflate, &raw).unwrap(), expected, "round {round}, bare, by the guesser");
            assert_eq!(all(Format::Zlib, &zlib_wrap(&raw, &expected)).unwrap(), expected, "round {round}, zlib");
            assert_eq!(all(Format::ZlibOrDeflate, &zlib_wrap(&raw, &expected)).unwrap(), expected, "round {round}, zlib, by the guesser");
            assert_eq!(all(Format::Gzip, &gzip_wrap(&raw, &expected)).unwrap(), expected, "round {round}, gzip");
            assert_eq!(all(Format::GzipMember, &gzip_wrap(&raw, &expected)).unwrap(), expected, "round {round}, one gzip member");
            // the cuts: all of them on the small ones, a few on the large
            if expected.len() < 40_000 {
                check_all_cuts(Format::Deflate, &raw, &expected, &format!("round {round} bare"));
                check_all_cuts(Format::Gzip, &gzip_wrap(&raw, &expected), &expected, &format!("round {round} gzip"));
            } else {
                for (i, o) in [(1, 4096), (4096, 1), (13, 29)] {
                    let out = run_chunked(Format::Zlib, &zlib_wrap(&raw, &expected), i, o, Limits::unlimited()).unwrap();
                    assert!(out == expected, "round {round} zlib cut ({i}, {o})");
                }
            }
        }
        assert!(total > 500_000, "the rounds made little data: {total}");
    }

    #[test]
    fn the_test_encoder_reaches_the_corners_the_tests_rely_on() {
        let mut rng = Rng(0x5eed);
        // complete codes, and codes of every length up to the longest the format has
        let mut longest = 0;
        for _ in 0..50 {
            let used: Vec<usize> = (0..286).collect();
            let lens = random_lengths(&mut rng, 286, &used, 15);
            longest = longest.max(*lens.iter().max().unwrap());
            let kraft: u64 = lens.iter().filter(|&&l| l > 0).map(|&l| 1u64 << (15 - l)).sum();
            assert_eq!(kraft, 1 << 15, "an incomplete code");
        }
        assert_eq!(longest, 15);
        // matches of the longest length, of the farthest distance and of the shortest
        let mut history = Vec::new();
        let tokens = random_tokens(&mut rng, &mut history, 40_000, 2);
        assert!(tokens.iter().any(|t| matches!(t, Token::Match(258, _))));
        assert!(tokens.iter().any(|t| matches!(t, Token::Match(_, 32768))));
        assert!(tokens.iter().any(|t| matches!(t, Token::Match(3, 1))));
    }

    /// The bytes that `tokens` stand for, appended to `out`.
    fn expand(tokens: &[Token], out: &mut Vec<u8>) {
        for t in tokens {
            match *t {
                Token::Lit(b) => out.push(b),
                Token::Match(len, dist) => {
                    for _ in 0..len {
                        out.push(out[out.len() - dist]);
                    }
                }
            }
        }
    }

    #[test]
    fn a_block_that_uses_every_symbol_of_both_alphabets_and_the_longest_codes() {
        // every literal, every length symbol (all lengths from 3 to 258), every distance symbol (the first distance of each, and
        // the last one the format has), in dynamic blocks whose codes go down to 15 bits
        let mut tokens: Vec<Token> = (0..=255u8).map(Token::Lit).collect();
        let mut rng = Rng(99);
        tokens.extend((0..33_000).map(|_| Token::Lit(rng.next() as u8)));
        for (i, &base) in DIST_BASE.iter().enumerate() {
            tokens.push(Token::Match(3 + i % 250, base as usize));
        }
        for len in 3..=258 {
            tokens.push(Token::Match(len, 1 + len % 7));
        }
        tokens.push(Token::Match(258, 32768));
        let mut expected = Vec::new();
        expand(&tokens, &mut expected);
        for seed in 0..6 {
            let mut rng = Rng(1000 + seed);
            let mut w = Bits::new();
            write_dynamic(&mut w, &mut rng, &tokens, true);
            let raw = w.finish();
            check_all_cuts(Format::Deflate, &raw, &expected, &format!("seed {seed}"));
        }
    }

    #[test]
    fn a_stream_cut_anywhere_is_truncated_and_never_complete() {
        let mut rng = Rng(77);
        for round in 0..4 {
            let (raw, plain) = small_stream(&mut rng, 1200);
            for (format, stream) in [
                (Format::Deflate, raw.clone()),
                (Format::Zlib, zlib_wrap(&raw, &plain)),
                (Format::Gzip, gzip_wrap(&raw, &plain)),
                (Format::GzipMember, gzip_wrap(&raw, &plain)),
            ] {
                for cut in 0..stream.len() {
                    // all at once for every cut, and a byte at a time for a sample of them and the last few
                    let by_byte = cut % 7 == 0 || cut + 12 > stream.len();
                    let chunks: &[usize] = if by_byte { &[usize::MAX, 1] } else { &[usize::MAX] };
                    for &chunk in chunks {
                        match run_chunked(format, &stream[..cut], chunk, 1 << 16, Limits::unlimited()) {
                            Err(Error::Truncated) => {}
                            other => panic!("round {round}, {format:?} cut at {cut} of {}: {other:?}", stream.len()),
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_flipped_bit_is_never_accepted_as_different_data() {
        let mut rng = Rng(4242);
        for round in 0..4 {
            let (raw, plain) = small_stream(&mut rng, 800);
            for (format, stream) in [(Format::Zlib, zlib_wrap(&raw, &plain)), (Format::Gzip, gzip_wrap(&raw, &plain))] {
                for bit in 0..stream.len() * 8 {
                    let mut bad = stream.clone();
                    bad[bit / 8] ^= 1 << (bit % 8);
                    // it nearly always fails; it may decode to exactly the same bytes (the modification time of a gzip header,
                    // the padding before a stored block); it may not decode to anything else
                    if let Ok(out) = all(format, &bad) {
                        assert!(out == plain, "round {round}, {format:?}, bit {bit}: accepted with different output");
                    }
                }
            }
            // a bare stream has no check, so it may decode to anything; it must not panic or run away
            for bit in 0..raw.len() * 8 {
                let mut bad = raw.clone();
                bad[bit / 8] ^= 1 << (bit % 8);
                let _ = decode_all(Format::Deflate, &bad, Limits::new(1 << 24));
            }
        }
    }

    #[test]
    fn an_empty_output_slice_is_not_a_problem() {
        let mut rng = Rng(5150);
        for _ in 0..20 {
            let (raw, plain) = small_stream(&mut rng, 2000);
            let stream = gzip_wrap(&raw, &plain);
            let mut inf = Inflater::new(Format::Gzip, Limits::unlimited());
            let first = inf.inflate(&stream, &mut []).unwrap();
            assert_eq!(first.produced, 0);
            let mut out = Vec::new();
            let mut buf = vec![0u8; 100];
            let mut pos = first.consumed;
            loop {
                let p = inf.inflate(&stream[pos..], &mut buf).unwrap();
                pos += p.consumed;
                out.extend_from_slice(&buf[..p.produced]);
                if p.status == Status::NeedInput {
                    break;
                }
            }
            inf.finish().unwrap();
            assert!(out == plain);
        }
    }

    // ---- limits

    /// A stream of `n` zero bytes the way an attacker would make it: a literal and then matches of 258 at distance one, in a
    /// dynamic block with a tiny alphabet.
    fn zeros(rng: &mut Rng, n: usize) -> Vec<u8> {
        let mut tokens = vec![Token::Lit(0)];
        let mut left = n - 1;
        while left >= 258 {
            tokens.push(Token::Match(258, 1));
            left -= 258;
        }
        while left > 0 {
            if left >= 3 {
                tokens.push(Token::Match(left, 1));
                left = 0;
            } else {
                tokens.push(Token::Lit(0));
                left -= 1;
            }
        }
        let mut w = Bits::new();
        write_dynamic(&mut w, rng, &tokens, true);
        w.finish()
    }

    #[test]
    fn the_output_limit_is_exact_and_the_decoder_never_goes_past_it() {
        let mut rng = Rng(9);
        let n = 3_000_000;
        let raw = zeros(&mut rng, n);
        assert!(raw.len() < n / 100, "the bomb should be small: {} bytes", raw.len());
        assert_eq!(decode_all(Format::Deflate, &raw, Limits::new(n as u64)).unwrap().len(), n);
        assert_eq!(decode_all(Format::Deflate, &raw, Limits::new(n as u64 - 1)), Err(Error::OutputLimit { limit: n as u64 - 1 }));
        assert_eq!(decode_all(Format::Deflate, &raw, Limits::new(0)), Err(Error::OutputLimit { limit: 0 }));
        // in small pieces, and with the refusal staying put
        for limit in [1u64, 257, 258, 259, 65_535, 1_000_000] {
            let mut inf = Inflater::new(Format::Deflate, Limits::new(limit));
            let mut buf = vec![0u8; 1000];
            let mut pos = 0;
            let mut calls = 0;
            let err = loop {
                calls += 1;
                assert!(calls < 100_000, "limit {limit}: no end in sight");
                match inf.inflate(&raw[pos..], &mut buf) {
                    Ok(p) => {
                        pos += p.consumed;
                        assert!(inf.total_out() <= limit, "limit {limit}: {} given", inf.total_out());
                        assert_ne!(p.status, Status::Done, "limit {limit}");
                    }
                    Err(e) => break e,
                }
            };
            assert_eq!(err, Error::OutputLimit { limit });
            assert!(inf.total_out() <= limit);
            assert_eq!(inf.inflate(&raw[pos..], &mut buf).unwrap_err(), err);
            assert_eq!(inf.finish().unwrap_err(), err);
        }
        // a stored block is counted too
        let stored = {
            let mut w = Bits::new();
            write_stored(&mut w, &vec![7u8; 5000], true);
            w.finish()
        };
        assert_eq!(decode_all(Format::Deflate, &stored, Limits::new(5000)).unwrap().len(), 5000);
        assert!(matches!(decode_all(Format::Deflate, &stored, Limits::new(4999)), Err(Error::OutputLimit { .. })));
        // and the limit is for the whole of a gzip stream, not for each member
        let (a, b) = (vec![1u8; 700], vec![2u8; 700]);
        let member = |data: &[u8]| {
            let mut w = Bits::new();
            write_stored(&mut w, data, true);
            gzip_wrap(&w.finish(), data)
        };
        let two = [member(&a), member(&b)].concat();
        assert_eq!(decode_all(Format::Gzip, &two, Limits::new(1400)).unwrap().len(), 1400);
        assert!(matches!(decode_all(Format::Gzip, &two, Limits::new(1399)), Err(Error::OutputLimit { .. })));
    }

    #[test]
    fn the_ratio_limit_counts_the_input_that_was_taken() {
        let mut rng = Rng(11);
        let n = 4_000_000;
        let raw = zeros(&mut rng, n);
        let ratio = (n / raw.len()) as u64;
        assert!(ratio > 100, "the stream should be a bomb: ratio {ratio}");
        // within the floor, anything goes
        assert!(decode_all(Format::Deflate, &raw, Limits::unlimited().with_ratio(10, n as u64)).is_ok());
        // beyond it, a ratio under the stream's own is refused and one over it is not
        assert_eq!(decode_all(Format::Deflate, &raw, Limits::unlimited().with_ratio(ratio / 2, 1 << 20)), Err(Error::RatioLimit { ratio: ratio / 2 }));
        assert!(decode_all(Format::Deflate, &raw, Limits::unlimited().with_ratio(ratio * 2, 1 << 20)).is_ok());
        // the refusal comes early: well before the whole bomb is out
        let mut inf = Inflater::new(Format::Deflate, Limits::unlimited().with_ratio(ratio / 2, 1 << 20));
        let mut buf = vec![0u8; 4096];
        let mut pos = 0;
        while let Ok(p) = inf.inflate(&raw[pos..], &mut buf) {
            pos += p.consumed;
        }
        assert!(inf.total_out() < n as u64 / 2, "refused only after {} bytes", inf.total_out());
        // honest data is nowhere near: no valid stream can pass 1032 to 1
        let (raw2, expected2) = random_stream(&mut rng, 3);
        assert_eq!(decode_all(Format::Deflate, &raw2, Limits::unlimited().with_ratio(1032, 0)).unwrap(), expected2);
    }

    #[test]
    fn the_ratio_limit_says_the_same_however_the_stream_is_cut() {
        // (it is checked where the stream says how much is coming, not where a call happens to return)
        let mut rng = Rng(77);
        let (mut refused, mut passed) = (0, 0);
        for round in 0..6 {
            let (raw, plain) = random_stream(&mut rng, 3);
            let ratio = (plain.len() / raw.len().max(1)).max(1) as u64;
            for r in [1, 2, ratio / 2 + 1, ratio, ratio * 2 + 1, 1032] {
                for floor in [0, 100, plain.len() as u64 / 3] {
                    let limits = Limits::unlimited().with_ratio(r, floor);
                    let whole = run_chunked(Format::Deflate, &raw, usize::MAX, 1 << 16, limits);
                    match &whole {
                        Ok(out) => {
                            assert_eq!(out, &plain);
                            passed += 1;
                        }
                        Err(e) => {
                            assert_eq!(e, &Error::RatioLimit { ratio: r });
                            refused += 1;
                        }
                    }
                    for (i, o) in CUTS {
                        assert_eq!(run_chunked(Format::Deflate, &raw, i, o, limits), whole, "round {round}, ratio {r} of {ratio}, floor {floor}, cut ({i}, {o})");
                    }
                }
            }
        }
        assert!(refused > 10 && passed > 10, "{refused} refused, {passed} passed");
        // a bomb first, and then enough data that does not compress to bring the ratio of the whole back down: a check made when a
        // call returns would refuse it when the output is taken in small pieces and pass it when it is taken in one
        let mut w = Bits::new();
        let mut tokens = vec![Token::Lit(0)];
        tokens.extend(std::iter::repeat_with(|| Token::Match(258, 1)).take(150));
        write_fixed(&mut w, &tokens, false);
        let data = rng.bytes(20_000);
        write_stored(&mut w, &data, true);
        let raw = w.finish();
        let limits = Limits::unlimited().with_ratio(10, 0);
        for (i, o) in CUTS {
            assert_eq!(run_chunked(Format::Deflate, &raw, i, o, limits), Err(Error::RatioLimit { ratio: 10 }), "cut ({i}, {o})");
        }
    }

    #[test]
    fn the_biggest_possible_ratio_is_about_a_thousand() {
        // one bit for the length code and one for the distance code per match of 258: 129 bytes of output per bit of input
        let mut rng = Rng(5);
        let mut best = 0usize;
        for _ in 0..20 {
            let raw = zeros(&mut rng, 2_000_000);
            best = best.max(2_000_000 / raw.len());
        }
        assert!(best > 500 && best <= 1032, "best ratio {best}");
    }

    // ---- the framing

    #[test]
    fn zlib_headers_are_checked() {
        let ok = zlib_wrap(&[0x03, 0x00], &[]);
        assert_eq!(all(Format::Zlib, &ok).unwrap(), Vec::<u8>::new());
        let with_header = |a: u8, b: u8| all(Format::Zlib, &[a, b, 3, 0, 0, 0, 0, 1]);
        // the method, the window, the check bits and the dictionary flag
        assert!(matches!(with_header(0x79, 0x9c), Err(Error::Corrupt(m)) if m.contains("method")));
        assert!(matches!(with_header(0x88, 0x1c), Err(Error::Corrupt(m)) if m.contains("window")));
        assert!(matches!(with_header(0x78, 0x9d), Err(Error::Corrupt(m)) if m.contains("check bits")));
        assert!(matches!(with_header(0x78, 0xbb), Err(Error::Unsupported(m)) if m.contains("dictionary")));
        // smaller windows are fine
        assert_eq!(with_header(0x48, 0x89).unwrap(), Vec::<u8>::new());
        // the Adler-32, in each of its bytes
        for i in 0..4 {
            let mut bad = ok.clone();
            let n = bad.len();
            bad[n - 1 - i] ^= 0x10;
            assert_eq!(all(Format::Zlib, &bad), Err(Error::Checksum("adler32")), "byte {i}");
        }
    }

    #[test]
    fn the_guess_between_zlib_and_bare_deflate_goes_the_right_way() {
        let mut rng = Rng(31);
        for _ in 0..200 {
            let blocks = 1 + rng.below(3);
            let (raw, expected) = random_stream(&mut rng, blocks);
            assert_eq!(all(Format::ZlibOrDeflate, &raw).unwrap(), expected);
            let z = zlib_wrap(&raw, &expected);
            assert_eq!(all(Format::ZlibOrDeflate, &z).unwrap(), expected);
            // a byte at a time too
            assert_eq!(run_chunked(Format::ZlibOrDeflate, &z, 1, 64, Limits::unlimited()).unwrap(), expected);
            assert_eq!(run_chunked(Format::ZlibOrDeflate, &raw, 1, 64, Limits::unlimited()).unwrap(), expected);
        }
        // the guess needs two bytes; fewer are a stream that stopped short
        assert_eq!(all(Format::ZlibOrDeflate, &[0x03]), Err(Error::Truncated));
        assert_eq!(all(Format::ZlibOrDeflate, &[]), Err(Error::Truncated));
        // a zlib stream that is wrong inside is an error, not a reason to try it as bare data
        let mut bad = zlib_wrap(&[0x03, 0x00], &[]);
        bad[5] ^= 1;
        assert!(matches!(all(Format::ZlibOrDeflate, &bad), Err(Error::Checksum("adler32"))));
    }

    fn gzip_header_with(flags: u8, extra: &[u8], name: &[u8], comment: &[u8], good_crc: bool) -> Vec<u8> {
        let mut h = vec![0x1f, 0x8b, 8, flags, 1, 2, 3, 4, 0, 3];
        if flags & 4 != 0 {
            h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            h.extend_from_slice(extra);
        }
        if flags & 8 != 0 {
            h.extend_from_slice(name);
            h.push(0);
        }
        if flags & 16 != 0 {
            h.extend_from_slice(comment);
            h.push(0);
        }
        if flags & 2 != 0 {
            let c = (crc32(0, &h) & 0xffff) as u16 ^ if good_crc { 0 } else { 1 };
            h.extend_from_slice(&c.to_le_bytes());
        }
        h
    }

    #[test]
    fn every_gzip_header_shape_is_read_and_checked() {
        let mut rng = Rng(8);
        let (raw, plain) = small_stream(&mut rng, 600);
        let body = {
            let mut v = raw.clone();
            v.extend_from_slice(&crc32(0, &plain).to_le_bytes());
            v.extend_from_slice(&(plain.len() as u32).to_le_bytes());
            v
        };
        let extra = vec![0xaa; 300];
        for flags in 0..32u8 {
            let mut member = gzip_header_with(flags, &extra, b"file.txt", b"a comment", true);
            member.extend_from_slice(&body);
            for (i, o) in [(usize::MAX, 1 << 16), (1, 3), (2, 1 << 16)] {
                let out = run_chunked(Format::Gzip, &member, i, o, Limits::unlimited()).unwrap_or_else(|e| panic!("flags {flags:#x}: {e}"));
                assert!(out == plain, "flags {flags:#x}, cut ({i}, {o})");
            }
            if flags & 2 != 0 {
                let mut bad = gzip_header_with(flags, &extra, b"file.txt", b"a comment", false);
                bad.extend_from_slice(&body);
                assert_eq!(all(Format::Gzip, &bad), Err(Error::Checksum("header crc")), "flags {flags:#x}");
            }
        }
        // the things that make it not gzip at all
        let start = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut m = gzip_header_with(0, &[], b"", b"", true);
            m.extend_from_slice(&body);
            edit(&mut m);
            all(Format::Gzip, &m)
        };
        assert!(matches!(start(&|m| m[0] = 0x1e), Err(Error::Corrupt(m)) if m.contains("magic")));
        assert!(matches!(start(&|m| m[1] = 0x8c), Err(Error::Corrupt(m)) if m.contains("magic")));
        assert!(matches!(start(&|m| m[2] = 7), Err(Error::Corrupt(m)) if m.contains("method")));
        for reserved in [0x20u8, 0x40, 0x80] {
            assert!(matches!(start(&|m| m[3] = reserved), Err(Error::Corrupt(m)) if m.contains("reserved")), "reserved flag {reserved:#x}");
        }
        // the modification time, the extra flags and the operating system are anybody's
        assert_eq!(
            start(&|m| {
                m[4] = 9;
                m[8] = 2;
                m[9] = 255;
            })
            .unwrap(),
            plain
        );
        // the checks at the end, in each byte
        for i in 0..8 {
            let mut m = gzip_header_with(0, &[], b"", b"", true);
            m.extend_from_slice(&body);
            let n = m.len();
            m[n - 1 - i] ^= 0x01;
            let want = if i < 4 { "length" } else { "crc32" };
            assert_eq!(all(Format::Gzip, &m), Err(Error::Checksum(want)), "trailer byte {i}");
        }
        // a header that goes on and on is refused rather than read to the end
        let long_name = vec![b'x'; 200_000];
        let mut m = gzip_header_with(8, &[], &long_name, b"", true);
        m.extend_from_slice(&body);
        assert!(matches!(all(Format::Gzip, &m), Err(Error::Corrupt(m)) if m.contains("too long")));
        // an extra field of the largest size the format has still fits
        let mut m = gzip_header_with(4, &vec![1u8; 65_535], b"", b"", true);
        m.extend_from_slice(&body);
        assert_eq!(all(Format::Gzip, &m).unwrap(), plain);
    }

    #[test]
    fn gzip_members_follow_one_another_and_the_end_is_the_callers_to_declare() {
        let mut rng = Rng(21);
        let mut stream = Vec::new();
        let mut expected = Vec::new();
        let mut member_ends = Vec::new();
        for _ in 0..4 {
            let (raw, plain) = small_stream(&mut rng, 1500);
            stream.extend_from_slice(&gzip_wrap(&raw, &plain));
            expected.extend_from_slice(&plain);
            member_ends.push(stream.len());
        }
        check_all_cuts(Format::Gzip, &stream, &expected, "four members");
        // an empty member is a member
        let with_empty = [gzip_wrap(&[0x03, 0x00], &[]), stream.clone()].concat();
        assert_eq!(all(Format::Gzip, &with_empty).unwrap(), expected);
        // stopping between two members is the end; stopping inside one, or having nothing at all, is not
        for (k, &end) in member_ends.iter().enumerate() {
            assert!(all(Format::Gzip, &stream[..end]).is_ok(), "after member {k}");
            assert_eq!(all(Format::Gzip, &stream[..end - 1]), Err(Error::Truncated), "one byte short of member {k}");
            if end < stream.len() {
                assert_eq!(all(Format::Gzip, &stream[..end + 1]), Err(Error::Truncated), "one byte into the header after member {k}");
            }
        }
        assert_eq!(all(Format::Gzip, &[]), Err(Error::Truncated));
        // garbage after the last member is not a member
        let mut garbage = stream.clone();
        garbage.extend_from_slice(b"trailing bytes");
        assert!(matches!(all(Format::Gzip, &garbage), Err(Error::Corrupt(m)) if m.contains("magic")));
        // the window does not reach into the member before: a match at the start of the second refers to nothing
        let first = {
            let mut w = Bits::new();
            write_fixed(&mut w, &[Token::Lit(b'a'), Token::Lit(b'b'), Token::Lit(b'c')], true);
            gzip_wrap(&w.finish(), b"abc")
        };
        let second = {
            let mut w = Bits::new();
            write_fixed(&mut w, &[Token::Match(3, 3)], true);
            gzip_wrap(&w.finish(), b"abc")
        };
        assert!(matches!(all(Format::Gzip, &[first, second].concat()), Err(Error::Corrupt(m)) if m.contains("before the start")));
    }

    #[test]
    fn what_follows_a_stream_is_given_back_or_kept_for_take_unused() {
        let mut rng = Rng(63);
        let mut kept = 0;
        for _ in 0..40 {
            let blocks = 1 + rng.below(3);
            let (raw, plain) = random_stream(&mut rng, blocks);
            if raw.len() > 3000 {
                continue;
            }
            for (format, stream) in [(Format::Deflate, raw.clone()), (Format::Zlib, zlib_wrap(&raw, &plain)), (Format::GzipMember, gzip_wrap(&raw, &plain))] {
                for tail in [&b""[..], &b"x"[..], &b"0123456789abcdef0123456789"[..]] {
                    let mut data = stream.clone();
                    data.extend_from_slice(tail);
                    // with room for everything, the stream ends exactly where it does and the tail is untouched
                    let (out, consumed, mut inf) = run_to_done(format, &data, usize::MAX, plain.len() + 10);
                    assert!(out == plain);
                    assert_eq!(consumed, stream.len(), "{format:?}, tail of {}", tail.len());
                    assert!(inf.take_unused().is_empty());
                    // once done it stays done, takes nothing and gives nothing
                    let mut buf = [0u8; 16];
                    let again = inf.inflate(tail, &mut buf).unwrap();
                    assert_eq!((again.consumed, again.produced, again.status), (0, 0, Status::Done));
                    // a byte at a time takes no more than the stream either
                    let (out, consumed, mut inf) = run_to_done(format, &data, 1, 4096);
                    assert!(out == plain);
                    assert_eq!(consumed, stream.len());
                    assert!(inf.take_unused().is_empty());
                    // with a byte of room, earlier calls hold input in the bit buffer when the stream ends: what they took beyond
                    // the stream is in take_unused, and is exactly the bytes after the stream
                    if plain.len() > 20_000 {
                        continue;
                    }
                    let (out, consumed, mut inf) = run_to_done(format, &data, usize::MAX, 1);
                    assert!(out == plain);
                    let unused = inf.take_unused();
                    assert_eq!(consumed, stream.len() + unused.len(), "{format:?}, tail of {}", tail.len());
                    assert_eq!(&data[stream.len()..consumed], &unused[..]);
                    kept += unused.len();
                }
            }
        }
        assert!(kept > 0, "no test left bytes in the bit buffer, so take_unused was not exercised");
    }

    // ---- codes that must be refused, written by hand

    /// The code that spells out code lengths in the hand-made blocks below: 0 → 1 bit, 1 → 2, 2 → 3, 18 → 4, 17 → 5, 16 → 5
    /// (a complete code).
    fn spelling_code() -> [u8; 19] {
        let mut l = [0u8; 19];
        l[0] = 1;
        l[1] = 2;
        l[2] = 3;
        l[18] = 4;
        l[17] = 5;
        l[16] = 5;
        l
    }

    /// The items that spell out `lens` (values 0 to 2) with `spelling_code`.
    fn spell(lens: &[u8]) -> Vec<(usize, u32, u32)> {
        let mut items = Vec::new();
        let mut i = 0;
        while i < lens.len() {
            let mut run = 1;
            while i + run < lens.len() && lens[i + run] == lens[i] {
                run += 1;
            }
            if lens[i] == 0 && run >= 11 {
                let n = run.min(138);
                items.push((18, (n - 11) as u32, 7));
                i += n;
            } else {
                items.push((lens[i] as usize, 0, 0));
                i += 1;
            }
        }
        items
    }

    /// The header of a dynamic block, by hand.
    fn hand_header(w: &mut Bits, last: bool, hlit: usize, hdist: usize, clen: &[u8; 19], items: &[(usize, u32, u32)]) {
        let codes = codes_of(clen);
        let mut hclen = 19;
        while hclen > 4 && clen[CLEN_ORDER[hclen - 1]] == 0 {
            hclen -= 1;
        }
        w.put(last as u32, 1);
        w.put(2, 2);
        w.put((hlit - 257) as u32, 5);
        w.put((hdist - 1) as u32, 5);
        w.put((hclen - 4) as u32, 4);
        for k in 0..hclen {
            w.put(clen[CLEN_ORDER[k]] as u32, 3);
        }
        for &(sym, extra, bits) in items {
            w.code(codes[sym], clen[sym] as u32);
            w.put(extra, bits);
        }
    }

    /// What a hand-made block says after its header.
    enum Sym {
        /// A literal/length symbol on its own.
        L(usize),
        /// A length symbol (257 to 264, which have no extra bits) and a distance symbol (0 to 3, likewise).
        M(usize, usize),
        /// Bits as they are.
        Raw(u32, u32),
    }

    /// A final dynamic block with the given code lengths ((symbol, length) pairs; values up to 2) and body.
    fn hand_stream(lit: &[(usize, u8)], dist: &[(usize, u8)], body: &[Sym]) -> Vec<u8> {
        let mut ll = vec![0u8; lit.iter().map(|p| p.0 + 1).max().unwrap().max(257)];
        for &(s, l) in lit {
            ll[s] = l;
        }
        let mut dl = vec![0u8; dist.iter().map(|p| p.0 + 1).max().unwrap_or(1)];
        for &(s, l) in dist {
            dl[s] = l;
        }
        let both: Vec<u8> = ll.iter().chain(dl.iter()).copied().collect();
        let mut w = Bits::new();
        hand_header(&mut w, true, ll.len(), dl.len(), &spelling_code(), &spell(&both));
        let (lc, dc) = (codes_of(&ll), codes_of(&dl));
        for s in body {
            match *s {
                Sym::L(x) => w.code(lc[x], ll[x] as u32),
                Sym::M(l, d) => {
                    w.code(lc[l], ll[l] as u32);
                    w.code(dc[d], dl[d] as u32);
                }
                Sym::Raw(v, n) => w.put(v, n),
            }
        }
        w.finish()
    }

    #[track_caller]
    fn refused_for(r: Result<Vec<u8>, Error>) -> &'static str {
        match r {
            Err(Error::Corrupt(m)) => m,
            other => panic!("expected a refusal as corrupt data, got {other:?}"),
        }
    }

    #[test]
    fn the_codes_the_format_allows_and_the_ones_it_does_not() {
        use Sym::*;
        // the single code of length one that the RFC allows, for the literals (a block of nothing) and for the distances
        assert_eq!(all(Format::Deflate, &hand_stream(&[(256, 1)], &[(0, 1)], &[L(256)])).unwrap(), b"");
        // a distance code with one code of one bit, which then serves for distance 1
        let lit = [(97, 2), (98, 2), (257, 2), (256, 2)];
        assert_eq!(all(Format::Deflate, &hand_stream(&lit, &[(0, 1)], &[L(97), M(257, 0), L(256)])).unwrap(), b"aaaa");
        // ... and the one-bit code that is not assigned is not a symbol
        let bad = hand_stream(&lit, &[(0, 1)], &[L(97), L(257), Raw(1, 1), L(256)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("distance code"));
        let bad = hand_stream(&[(256, 1)], &[(0, 1)], &[Raw(1, 1)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("literal/length code"));
        // over-subscribed
        let bad = hand_stream(&[(97, 1), (98, 1), (256, 1)], &[(0, 1)], &[L(256)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("over-subscribed"));
        let bad = hand_stream(&[(97, 1), (256, 1)], &[(0, 1), (1, 1), (2, 1)], &[L(256)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("over-subscribed"));
        // incomplete: literals, and distances
        let bad = hand_stream(&[(97, 2), (256, 2)], &[(0, 1)], &[L(256)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("literal/length code is incomplete"));
        let bad = hand_stream(&[(97, 1), (256, 1)], &[(0, 2)], &[L(256)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("distance code is incomplete"));
        // no code for the end of the block
        let bad = hand_stream(&[(97, 1), (98, 1)], &[(0, 1)], &[L(97)]);
        assert!(refused_for(all(Format::Deflate, &bad)).contains("end-of-block"));
        // the code that spells the lengths must be complete, even if it is a single code
        for clen in [{ let mut l = [0u8; 19]; l[0] = 1; l }, { let mut l = [0u8; 19]; l[0] = 2; l[1] = 2; l }] {
            let mut w = Bits::new();
            hand_header(&mut w, true, 257, 1, &clen, &[]);
            w.put(0, 32);
            assert!(refused_for(all(Format::Deflate, &w.finish())).contains("reads the code lengths"));
        }
    }

    #[test]
    fn counts_and_repeats_in_a_dynamic_header_are_checked() {
        let spelling = spelling_code();
        // more length codes than the format has (HLIT 288), and more distance codes (HDIST 32)
        for (hlit, hdist) in [(288, 1), (257, 31), (257, 32)] {
            let mut w = Bits::new();
            hand_header(&mut w, true, hlit, hdist, &spelling, &[]);
            w.put(0, 64);
            assert!(refused_for(all(Format::Deflate, &w.finish())).contains("too many"), "{hlit}, {hdist}");
        }
        // 286 and 30 are the most, and fine
        let ll: Vec<u8> = (0..286).map(|i| if i == 256 || i == 97 { 1 } else { 0 }).collect();
        let dl = [1u8; 1].iter().copied().chain(std::iter::repeat(0).take(29)).collect::<Vec<u8>>();
        let both: Vec<u8> = ll.iter().chain(dl.iter()).copied().collect();
        let mut w = Bits::new();
        hand_header(&mut w, true, 286, 30, &spelling, &spell(&both));
        let (lc, lcl) = (codes_of(&ll), &ll);
        w.code(lc[97], lcl[97] as u32);
        w.code(lc[256], lcl[256] as u32);
        assert_eq!(all(Format::Deflate, &w.finish()).unwrap(), b"a");
        // a repeat of "the previous length" with none before it
        let mut w = Bits::new();
        hand_header(&mut w, true, 257, 1, &spelling, &[(16, 0, 2)]);
        w.put(0, 64);
        assert!(refused_for(all(Format::Deflate, &w.finish())).contains("none before"));
        // runs that go past the end of the 258 lengths
        let mut w = Bits::new();
        hand_header(&mut w, true, 257, 1, &spelling, &[(18, 127, 7), (18, 127, 7)]);
        w.put(0, 64);
        assert!(refused_for(all(Format::Deflate, &w.finish())).contains("run past"));
    }

    #[test]
    fn blocks_and_symbols_that_must_be_refused() {
        // a block type that does not exist
        assert!(refused_for(all(Format::Deflate, &[0x07, 0, 0, 0])).contains("block type"));
        // a stored block whose length and its complement do not agree
        assert!(refused_for(all(Format::Deflate, &[0x01, 3, 0, 0, 0, b'a', b'b', b'c'])).contains("complement"));
        // symbols that are in the fixed table but not in the format: length codes 286 and 287, distance codes 30 and 31
        let lens = fixed_lengths();
        let codes = codes_of(&lens);
        for sym in [286usize, 287] {
            let mut w = Bits::new();
            w.put(1, 1);
            w.put(1, 2);
            w.code(codes[b'a' as usize], lens[b'a' as usize] as u32);
            w.code(codes[sym], lens[sym] as u32);
            w.put(0, 32);
            assert!(refused_for(all(Format::Deflate, &w.finish())).contains("length code"), "symbol {sym}");
        }
        for sym in [30u32, 31] {
            let mut w = Bits::new();
            w.put(1, 1);
            w.put(1, 2);
            w.code(codes[b'a' as usize], lens[b'a' as usize] as u32);
            w.code(codes[257], lens[257] as u32);
            w.code(sym, 5);
            w.put(0, 32);
            assert!(refused_for(all(Format::Deflate, &w.finish())).contains("distance code"), "symbol {sym}");
        }
        // matches that reach back past what there is
        for tokens in [vec![Token::Match(3, 1)], vec![Token::Lit(b'a'), Token::Match(3, 2)], vec![Token::Lit(b'a'), Token::Lit(b'b'), Token::Match(4, 3)]] {
            let mut w = Bits::new();
            write_fixed(&mut w, &tokens, true);
            assert!(refused_for(all(Format::Deflate, &w.finish())).contains("before the start"), "{tokens:?}");
        }
        // ... and the one that just fits, overlapping itself
        let mut w = Bits::new();
        write_fixed(&mut w, &[Token::Lit(b'a'), Token::Match(5, 1)], true);
        assert_eq!(all(Format::Deflate, &w.finish()).unwrap(), b"aaaaaa");
        // the distance is checked against the window too: 32768 is the farthest, from 32768 bytes of history
        let mut tokens: Vec<Token> = (0..32768u32).map(|i| Token::Lit(i as u8)).collect();
        tokens.push(Token::Match(3, 32768));
        let mut expected = Vec::new();
        expand(&tokens, &mut expected);
        let mut w = Bits::new();
        write_fixed(&mut w, &tokens, true);
        assert!(all(Format::Deflate, &w.finish()).unwrap() == expected);
        let mut tokens: Vec<Token> = (0..32767u32).map(|i| Token::Lit(i as u8)).collect();
        tokens.push(Token::Match(3, 32768));
        let mut w = Bits::new();
        write_fixed(&mut w, &tokens, true);
        assert!(refused_for(all(Format::Deflate, &w.finish())).contains("before the start"));
    }

    #[test]
    fn errors_are_sticky_and_the_decoder_never_panics_on_noise() {
        let mut inf = Inflater::new(Format::Deflate, Limits::unlimited());
        let mut buf = [0u8; 64];
        let err = inf.inflate(&[0x07], &mut buf).unwrap_err();
        assert_eq!(inf.inflate(&[0x03, 0x00], &mut buf).unwrap_err(), err);
        assert_eq!(inf.finish().unwrap_err(), err);
        // noise in every format, in several cuts, with limits on: whatever comes back, it comes back
        let mut rng = Rng(0xdead_beef);
        for round in 0..400 {
            let n = rng.below(300);
            let mut noise = rng.bytes(n);
            // give some of it the start of a real stream so that the decoder gets further in
            match round % 4 {
                1 if n >= 2 => noise[..2].copy_from_slice(&[0x78, 0x9c]),
                2 if n >= 3 => noise[..3].copy_from_slice(&[0x1f, 0x8b, 8]),
                3 if n >= 1 => noise[0] = (noise[0] & 0xf8) | 0x04 | (noise[0] & 1),
                _ => {}
            }
            for format in [Format::Deflate, Format::Zlib, Format::ZlibOrDeflate, Format::Gzip, Format::GzipMember] {
                for chunk in [usize::MAX, 1, 5] {
                    let _ = run_chunked(format, &noise, chunk, 97, Limits::new(1 << 20).with_ratio(2000, 1 << 16));
                }
            }
        }
    }
}
