//! HPACK (RFC 7541), the header compression of HTTP/2: an [`Encoder`] and a [`Decoder`], each with its own
//! dynamic table, and no I/O. A header block goes in as bytes and comes out as a list of fields, or the other way.
//!
//! What the decoder guards against, since it reads what a server sent:
//!
//! * integers that do not fit 32 bits, strings and indexes that point outside what was sent or what the tables
//!   hold, a table size update that comes after a field or asks for more than the decoder allowed;
//! * Huffman strings with a coded EOS or with padding that is not the beginning of EOS (see [`super::huffman`]);
//! * a header list larger than the limit it was given: the block is still decoded to its end, so that the
//!   dynamic table stays what the sender thinks it is (RFC 7540 section 4.3), but fields past the limit are not
//!   kept, and the caller is told;
//! * memory: a decoded string is at most as long as the larger of the list limit and the table size, the dynamic
//!   table never holds more than the size the decoder allowed, and the caller bounds the block itself.
//!
//! The encoder keeps to what the peer allows (it never uses more than the peer's SETTINGS_HEADER_TABLE_SIZE and
//! never more than 4096 bytes), says so in a table size update at the start of the next block when that changes,
//! codes strings with Huffman when it is shorter, and never indexes a field marked sensitive.

use super::huffman;
use std::collections::VecDeque;
use std::fmt;

/// The table size HTTP/2 starts with, and the most the encoder ever uses.
pub(crate) const DEFAULT_TABLE_SIZE: usize = 4096;

/// What an entry costs besides its name and value (RFC 7541 section 4.1).
const ENTRY_OVERHEAD: usize = 32;

/// The static table (RFC 7541, Appendix A); index 1 is the first entry.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// A header field: a name and a value. Names are lower case in HTTP/2; the decoder does not check that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Field {
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

impl Field {
    /// The size of this field for the dynamic table and for SETTINGS_MAX_HEADER_LIST_SIZE: the lengths of the name
    /// and the value and 32.
    pub(crate) fn size(&self) -> usize {
        self.name.len() + self.value.len() + ENTRY_OVERHEAD
    }
}

/// Why a header block did not decode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// The block ended inside an integer or a string.
    Truncated,
    /// An integer too large (over 32 bits), or written with too many bytes.
    Integer,
    /// An index that is zero where a field is meant, or beyond the tables.
    Index(usize),
    /// A Huffman string that does not decode.
    Huffman(huffman::Error),
    /// A string longer than the decoder takes.
    StringTooLong,
    /// A table size update after the first field of the block.
    SizeUpdateLate,
    /// A table size update to more than the decoder allowed.
    SizeUpdateTooLarge(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => f.write_str("the header block ended inside a field"),
            Error::Integer => f.write_str("a header block has an integer that is too large"),
            Error::Index(i) => write!(f, "a header block refers to table index {i}, which does not exist"),
            Error::Huffman(e) => e.fmt(f),
            Error::StringTooLong => f.write_str("a header block has a string that is too long"),
            Error::SizeUpdateLate => f.write_str("a header block has a table size update after a field"),
            Error::SizeUpdateTooLarge(n) => write!(f, "a header block sets the table size to {n}, more than was allowed"),
        }
    }
}

// ------------------------------------------------------------------------------------------------ primitives

/// An integer with an `prefix_bits`-bit prefix (RFC 7541 section 5.1); the prefix is the low bits of `buf[*pos]`.
fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u32) -> Result<usize, Error> {
    let mask = (1u64 << prefix_bits) - 1;
    let first = *buf.get(*pos).ok_or(Error::Truncated)?;
    *pos += 1;
    let mut value = first as u64 & mask;
    if value < mask {
        return Ok(value as usize);
    }
    let mut shift = 0;
    loop {
        let b = *buf.get(*pos).ok_or(Error::Truncated)?;
        *pos += 1;
        value += ((b & 0x7f) as u64) << shift;
        if value > u32::MAX as u64 {
            return Err(Error::Integer);
        }
        if b & 0x80 == 0 {
            return Ok(value as usize);
        }
        shift += 7;
        if shift > 28 {
            return Err(Error::Integer);
        }
    }
}

/// Writes `value` with a `prefix_bits`-bit prefix, `flags` being the bits above it in the first byte.
fn encode_int(out: &mut Vec<u8>, prefix_bits: u32, flags: u8, value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest & 0x7f) as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// A string literal (RFC 7541 section 5.2), at most `limit` bytes once decoded, appended to `out`.
fn decode_string(buf: &[u8], pos: &mut usize, limit: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    let huffman_coded = *buf.get(*pos).ok_or(Error::Truncated)? & 0x80 != 0;
    let len = decode_int(buf, pos, 7)?;
    let end = pos.checked_add(len).filter(|&e| e <= buf.len()).ok_or(Error::Truncated)?;
    let raw = &buf[*pos..end];
    *pos = end;
    if huffman_coded {
        huffman::decode(raw, out, limit).map_err(|e| if e == huffman::Error::TooLong { Error::StringTooLong } else { Error::Huffman(e) })
    } else if raw.len() > limit {
        Err(Error::StringTooLong)
    } else {
        out.extend_from_slice(raw);
        Ok(())
    }
}

/// Writes a string literal, Huffman coded if that is shorter.
fn encode_string(out: &mut Vec<u8>, s: &[u8]) {
    let coded = huffman::encoded_len(s);
    if coded < s.len() {
        encode_int(out, 7, 0x80, coded);
        huffman::encode(s, out);
    } else {
        encode_int(out, 7, 0, s.len());
        out.extend_from_slice(s);
    }
}

// ------------------------------------------------------------------------------------------------ the table

/// The dynamic table (RFC 7541 section 2.3.2): newest entry first, evicted from the back.
#[derive(Debug)]
struct DynamicTable {
    entries: VecDeque<Field>,
    /// The sum of the entries' sizes.
    size: usize,
    /// The most `size` may be.
    max: usize,
}

impl DynamicTable {
    fn new(max: usize) -> DynamicTable {
        DynamicTable { entries: VecDeque::new(), size: 0, max }
    }

    fn insert(&mut self, field: Field) {
        let size = field.size();
        // an entry larger than the table empties it and is not stored (RFC 7541 section 4.4)
        while self.size + size > self.max {
            match self.entries.pop_back() {
                Some(old) => self.size -= old.size(),
                None => return,
            }
        }
        self.size += size;
        self.entries.push_front(field);
    }

    fn set_max(&mut self, max: usize) {
        self.max = max;
        while self.size > max {
            let old = self.entries.pop_back().expect("a table with a size has entries");
            self.size -= old.size();
        }
    }

    /// The field at `index` of the combined address space: 1 to 61 are the static table, 62 and up the dynamic one.
    fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        if index == 0 {
            None
        } else if index <= STATIC.len() {
            let (n, v) = STATIC[index - 1];
            Some((n.as_bytes(), v.as_bytes()))
        } else {
            self.entries.get(index - STATIC.len() - 1).map(|f| (&f.name[..], &f.value[..]))
        }
    }
}

// ------------------------------------------------------------------------------------------------ decoding

/// Decodes header blocks, one connection's worth in order.
#[derive(Debug)]
pub(crate) struct Decoder {
    table: DynamicTable,
    /// The most a table size update may ask for: what this endpoint announced as SETTINGS_HEADER_TABLE_SIZE.
    allowed_table_size: usize,
    /// The largest header list kept, by the measure of [`Field::size`].
    max_list_size: usize,
}

impl Decoder {
    pub(crate) fn new(allowed_table_size: usize, max_list_size: usize) -> Decoder {
        Decoder { table: DynamicTable::new(allowed_table_size), allowed_table_size, max_list_size }
    }

    /// Decodes a whole header block (the fragments of a HEADERS frame and its CONTINUATION frames, joined) and
    /// appends its fields to `out`. `Ok(true)` if the list is within the limit; `Ok(false)` if it is not, in which
    /// case `out` has the fields up to the limit and the block has still been read to its end. An error means
    /// the connection can no longer be trusted to decode (a COMPRESSION_ERROR).
    pub(crate) fn decode(&mut self, block: &[u8], out: &mut Vec<Field>) -> Result<bool, Error> {
        let mut pos = 0;
        let mut list = 0usize;
        let mut within = true;
        let mut started = false;
        // the longest string that could matter: one that fits the list, or the table
        let string_limit = self.max_list_size.max(self.allowed_table_size);
        while pos < block.len() {
            let first = block[pos];
            let field = if first & 0x80 != 0 {
                // indexed field: measured before it is copied, so that a block of one-byte references to a large
                // entry costs nothing once the list is over the limit (an "HPACK bomb")
                let index = decode_int(block, &mut pos, 7)?;
                let (name, value) = self.table.get(index).ok_or(Error::Index(index))?;
                started = true;
                list = list.saturating_add(name.len() + value.len() + ENTRY_OVERHEAD);
                if list > self.max_list_size {
                    within = false;
                } else {
                    out.push(Field { name: name.to_vec(), value: value.to_vec() });
                }
                continue;
            } else if first & 0x40 != 0 {
                // literal field, added to the table
                let field = self.literal(block, &mut pos, 6, string_limit)?;
                self.table.insert(field.clone());
                field
            } else if first & 0x20 != 0 {
                // table size update
                if started {
                    return Err(Error::SizeUpdateLate);
                }
                let size = decode_int(block, &mut pos, 5)?;
                if size > self.allowed_table_size {
                    return Err(Error::SizeUpdateTooLarge(size));
                }
                self.table.set_max(size);
                continue;
            } else {
                // literal field, not added (0000) or never added by anyone on the way (0001)
                self.literal(block, &mut pos, 4, string_limit)?
            };
            started = true;
            list = list.saturating_add(field.size());
            if list > self.max_list_size {
                within = false;
            } else {
                out.push(field);
            }
        }
        Ok(within)
    }

    /// A literal field: the name as an index or a string, then the value as a string.
    fn literal(&self, block: &[u8], pos: &mut usize, prefix_bits: u32, string_limit: usize) -> Result<Field, Error> {
        let index = decode_int(block, pos, prefix_bits)?;
        let mut name = Vec::new();
        if index == 0 {
            decode_string(block, pos, string_limit, &mut name)?;
        } else {
            name.extend_from_slice(self.table.get(index).ok_or(Error::Index(index))?.0);
        }
        let mut value = Vec::new();
        decode_string(block, pos, string_limit, &mut value)?;
        Ok(Field { name, value })
    }

    /// The number of entries in the dynamic table and their total size.
    #[cfg(test)]
    fn table_state(&self) -> (usize, usize) {
        (self.table.entries.len(), self.table.size)
    }
}

// ------------------------------------------------------------------------------------------------ encoding

/// A field to encode.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldRef<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) value: &'a [u8],
    /// A value that is secret: it is sent as a literal that no intermediary may add to a table either, and is
    /// not added to ours (RFC 7541 section 7.1.3).
    pub(crate) sensitive: bool,
}

/// Encodes header blocks, one connection's worth in order.
#[derive(Debug)]
pub(crate) struct Encoder {
    table: DynamicTable,
    /// Table size updates still to send: the smallest size since the last block, and the last one.
    pending: Option<(usize, usize)>,
}

impl Encoder {
    pub(crate) fn new() -> Encoder {
        Encoder { table: DynamicTable::new(DEFAULT_TABLE_SIZE), pending: None }
    }

    /// The peer announced this SETTINGS_HEADER_TABLE_SIZE. The table shrinks to it if need be, and the next block
    /// says what size the table has now. (If the size changed more than once since the last block, RFC 7541 section
    /// 4.2 wants the smallest and then the last, two updates one after the other. Go's decoder, and so every Go
    /// server, accepts only one update at the start of a block once its table has entries, so the smallest is sent
    /// with this block, the table is kept at that size for it, and the last follows with the next block.)
    pub(crate) fn set_peer_table_size(&mut self, size: usize) {
        let new = size.min(DEFAULT_TABLE_SIZE);
        self.table.set_max(new);
        self.pending = Some(match self.pending {
            Some((smallest, _)) => (smallest.min(new), new),
            None => (new, new),
        });
    }

    /// Appends the encoding of one header block to `out`.
    pub(crate) fn encode(&mut self, fields: &[FieldRef<'_>], out: &mut Vec<u8>) {
        if let Some((smallest, last)) = self.pending.take() {
            encode_int(out, 5, 0x20, smallest);
            self.table.set_max(smallest);
            if last != smallest {
                self.pending = Some((last, last));
            }
        }
        for f in fields {
            self.encode_field(*f, out);
        }
    }

    fn encode_field(&mut self, f: FieldRef<'_>, out: &mut Vec<u8>) {
        let (full, named) = self.find(f.name, f.value);
        if let (Some(index), false) = (full, f.sensitive) {
            encode_int(out, 7, 0x80, index);
            return;
        }
        let size = f.name.len() + f.value.len() + ENTRY_OVERHEAD;
        // a field that would take over the table is not worth adding
        let add = !f.sensitive && size <= self.table.max / 2;
        let (prefix_bits, flags) = if f.sensitive {
            (4, 0x10)
        } else if add {
            (6, 0x40)
        } else {
            (4, 0x00)
        };
        match named {
            Some(index) => encode_int(out, prefix_bits, flags, index),
            None => {
                encode_int(out, prefix_bits, flags, 0);
                encode_string(out, f.name);
            }
        }
        encode_string(out, f.value);
        if add {
            self.table.insert(Field { name: f.name.to_vec(), value: f.value.to_vec() });
        }
    }

    /// The index of a field with this name and value, and of one with this name.
    fn find(&self, name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
        let mut named = None;
        for (i, (n, v)) in STATIC.iter().enumerate() {
            if n.as_bytes() == name {
                if v.as_bytes() == value {
                    return (Some(i + 1), Some(i + 1));
                }
                named.get_or_insert(i + 1);
            }
        }
        for (i, f) in self.table.entries.iter().enumerate() {
            if f.name == name {
                if f.value == value {
                    return (Some(STATIC.len() + 1 + i), Some(STATIC.len() + 1 + i));
                }
                named.get_or_insert(STATIC.len() + 1 + i);
            }
        }
        (None, named)
    }

    #[cfg(test)]
    fn table_state(&self) -> (usize, usize) {
        (self.table.entries.len(), self.table.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn pairs(fields: &[Field]) -> Vec<(String, String)> {
        fields.iter().map(|f| (String::from_utf8_lossy(&f.name).into_owned(), String::from_utf8_lossy(&f.value).into_owned())).collect()
    }

    fn list(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    fn decode_hex(dec: &mut Decoder, hex: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        assert_eq!(dec.decode(&unhex(hex), &mut out), Ok(true), "{hex}");
        pairs(&out)
    }

    fn decoder() -> Decoder {
        Decoder::new(4096, 1 << 20)
    }

    // ------------------------------------------------------------------------------------ integers and strings

    #[test]
    fn integers_as_in_rfc_appendix_c1() {
        // C.1.1: 10 in a 5-bit prefix; C.1.2: 1337 in a 5-bit prefix
        let mut out = Vec::new();
        encode_int(&mut out, 5, 0, 10);
        assert_eq!(out, [0x0a]);
        out.clear();
        encode_int(&mut out, 5, 0, 1337);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        let (mut pos, mut pos2) = (0, 0);
        assert_eq!(decode_int(&[0x0a], &mut pos, 5), Ok(10));
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], &mut pos2, 5), Ok(1337));
        assert_eq!(pos2, 3);
        // the flag bits above the prefix are left alone
        out.clear();
        encode_int(&mut out, 7, 0x80, 2);
        assert_eq!(out, [0x82]);
    }

    #[test]
    fn integers_round_trip_at_the_edges() {
        for prefix in 1..=7u32 {
            let max = (1usize << prefix) - 1;
            for value in [0, 1, max - 1, max, max + 1, max + 127, max + 128, 16383, 16384, 2_097_151, 2_097_152, u32::MAX as usize] {
                let mut out = Vec::new();
                encode_int(&mut out, prefix, 0, value);
                let mut pos = 0;
                assert_eq!(decode_int(&out, &mut pos, prefix), Ok(value), "prefix {prefix} value {value}");
                assert_eq!(pos, out.len());
            }
        }
    }

    #[test]
    fn integers_that_are_too_large_or_cut_short_are_errors() {
        let mut pos = 0;
        // 2^32 in a 7-bit prefix (written out: `encode_int` takes a usize, which on a 32-bit target cannot hold it)
        let big = [0x7f, 0x81, 0xff, 0xff, 0xff, 0x0f];
        assert_eq!(decode_int(&big, &mut pos, 7), Err(Error::Integer));
        #[cfg(target_pointer_width = "64")]
        {
            let mut encoded = Vec::new();
            encode_int(&mut encoded, 7, 0, 1 << 32);
            assert_eq!(encoded, big);
        }
        // written with six continuation bytes, though it is small
        pos = 0;
        assert_eq!(decode_int(&[0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], &mut pos, 7), Err(Error::Integer));
        // cut short
        pos = 0;
        assert_eq!(decode_int(&[0x7f, 0x80], &mut pos, 7), Err(Error::Truncated));
        pos = 0;
        assert_eq!(decode_int(&[], &mut pos, 7), Err(Error::Truncated));
    }

    #[test]
    fn strings_raw_and_huffman_coded() {
        let mut out = Vec::new();
        encode_string(&mut out, b"www.example.com");
        assert_eq!(hex(&out), "8cf1e3c2e5f23a6ba0ab90f4ff", "Huffman is shorter, so it is used");
        out.clear();
        encode_string(&mut out, b"{}{}{}{}");
        assert_eq!(out[0] & 0x80, 0, "these are long in Huffman (15 to 28 bits each)");
        let mut text = Vec::new();
        let mut pos = 0;
        decode_string(&out, &mut pos, 100, &mut text).unwrap();
        assert_eq!(text, b"{}{}{}{}");
    }

    // ------------------------------------------------------------------------------------ the RFC's examples

    #[test]
    fn rfc_appendix_c2_single_fields() {
        let mut d = decoder();
        // C.2.1: literal with indexing, new name; the table has 55 bytes afterwards
        assert_eq!(decode_hex(&mut d, "400a637573746f6d2d6b65790d637573746f6d2d686561646572"), list(&[("custom-key", "custom-header")]));
        assert_eq!(d.table_state(), (1, 55));
        // C.2.2: literal without indexing, name from the static table
        let mut d = decoder();
        assert_eq!(decode_hex(&mut d, "040c2f73616d706c652f70617468"), list(&[(":path", "/sample/path")]));
        assert_eq!(d.table_state(), (0, 0));
        // C.2.3: never indexed
        assert_eq!(decode_hex(&mut d, "100870617373776f726406736563726574"), list(&[("password", "secret")]));
        assert_eq!(d.table_state(), (0, 0));
        // C.2.4: indexed
        assert_eq!(decode_hex(&mut d, "82"), list(&[(":method", "GET")]));
    }

    #[test]
    fn rfc_appendix_c3_and_c4_requests() {
        // the same three requests without and with Huffman coding; the table sizes are the RFC's
        for (blocks, label) in [
            (["828684410f7777772e6578616d706c652e636f6d", "828684be58086e6f2d6361636865", "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"], "C.3"),
            (["828684418cf1e3c2e5f23a6ba0ab90f4ff", "828684be5886a8eb10649cbf", "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"], "C.4"),
        ] {
            let mut d = decoder();
            let first = list(&[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]);
            assert_eq!(decode_hex(&mut d, blocks[0]), first, "{label}.1");
            assert_eq!(d.table_state(), (1, 57), "{label}.1");
            let mut second = first.clone();
            second.push(("cache-control".into(), "no-cache".into()));
            assert_eq!(decode_hex(&mut d, blocks[1]), second, "{label}.2");
            assert_eq!(d.table_state(), (2, 110), "{label}.2");
            let third = list(&[(":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "www.example.com"), ("custom-key", "custom-value")]);
            assert_eq!(decode_hex(&mut d, blocks[2]), third, "{label}.3");
            assert_eq!(d.table_state(), (3, 164), "{label}.3");
        }
    }

    #[test]
    fn rfc_appendix_c5_and_c6_responses_with_a_small_table() {
        // a 256-byte table, so entries are evicted
        for (blocks, label) in [
            ([
                "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
                "4803333037c1c0bf",
                "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
            ], "C.5"),
            ([
                "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
                "4883640effc1c0bf",
                "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
            ], "C.6"),
        ] {
            let mut d = Decoder::new(256, 1 << 20);
            let date = "Mon, 21 Oct 2013 20:13:21 GMT";
            let location = "https://www.example.com";
            assert_eq!(decode_hex(&mut d, blocks[0]), list(&[(":status", "302"), ("cache-control", "private"), ("date", date), ("location", location)]), "{label}.1");
            assert_eq!(d.table_state(), (4, 222), "{label}.1");
            assert_eq!(decode_hex(&mut d, blocks[1]), list(&[(":status", "307"), ("cache-control", "private"), ("date", date), ("location", location)]), "{label}.2");
            assert_eq!(d.table_state(), (4, 222), "{label}.2");
            let cookie = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";
            assert_eq!(
                decode_hex(&mut d, blocks[2]),
                list(&[(":status", "200"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:22 GMT"), ("location", location), ("content-encoding", "gzip"), ("set-cookie", cookie)]),
                "{label}.3"
            );
            assert_eq!(d.table_state(), (3, 215), "{label}.3");
        }
    }

    #[test]
    fn the_encoder_makes_the_rfcs_huffman_requests() {
        // Appendix C.4: the three requests, byte for byte
        let mut e = Encoder::new();
        let want = ["828684418cf1e3c2e5f23a6ba0ab90f4ff", "828684be5886a8eb10649cbf", "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"];
        let requests: [&[(&str, &str)]; 3] = [
            &[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")],
            &[(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"), ("cache-control", "no-cache")],
            &[(":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "www.example.com"), ("custom-key", "custom-value")],
        ];
        for (request, want) in requests.iter().zip(want) {
            let fields: Vec<FieldRef> = request.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
            let mut out = Vec::new();
            e.encode(&fields, &mut out);
            assert_eq!(hex(&out), want);
        }
        assert_eq!(e.table_state(), (3, 164));
    }

    // ------------------------------------------------------------------------------------ against Python's hpack

    /// One connection's header blocks and the fields each must decode to, from a file `tools/hpack_oracle.py`
    /// reads or writes.
    struct Sequence {
        allowed: usize,
        blocks: Vec<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)>,
    }

    fn parse_corpus(text: &str) -> Vec<Sequence> {
        let mut seqs = Vec::new();
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.first().copied() {
                Some("seq") => seqs.push(Sequence { allowed: parts[1].parse().unwrap(), blocks: Vec::new() }),
                Some("block") => seqs.last_mut().unwrap().blocks.push((unhex(parts.get(1).copied().unwrap_or("")), Vec::new())),
                Some("field") => {
                    let block = seqs.last_mut().unwrap().blocks.last_mut().unwrap();
                    block.1.push((unhex(parts[1]), unhex(parts.get(2).copied().unwrap_or(""))));
                }
                _ => {}
            }
        }
        seqs
    }

    /// Decodes every block of a fixture file with a fresh decoder per sequence and checks the fields.
    fn check_fixture(text: &str, sequences: usize, blocks: usize) {
        let seqs = parse_corpus(text);
        assert_eq!(seqs.len(), sequences);
        let mut count = 0;
        for (i, seq) in seqs.iter().enumerate() {
            let mut d = Decoder::new(seq.allowed, 1 << 20);
            for (j, (block, fields)) in seq.blocks.iter().enumerate() {
                let mut out = Vec::new();
                assert_eq!(d.decode(block, &mut out), Ok(true), "sequence {i} block {j}");
                let got: Vec<(Vec<u8>, Vec<u8>)> = out.into_iter().map(|f| (f.name, f.value)).collect();
                assert_eq!(&got, fields, "sequence {i} block {j}");
                count += 1;
            }
        }
        assert_eq!(count, blocks);
    }

    #[test]
    fn decodes_what_python_encoded() {
        // tests/data/hpack_python.txt was made by `tools/hpack_oracle.py gen` with Python's hpack 4.2.0: random
        // fields, table sizes from 0 to 4096 (and changes of it between blocks, which the encoder announces),
        // Huffman coding on and off, never-indexed fields
        check_fixture(include_str!("../../../tests/data/hpack_python.txt"), 40, 152);
    }

    #[test]
    fn decodes_what_go_encoded() {
        // tests/data/hpack_go.txt: the same kind of thing from Go's encoder (`tools/hpack_oracle_go.sh gen`)
        check_fixture(include_str!("../../../tests/data/hpack_go.txt"), 40, 168);
    }

    struct Prng(u64);

    impl Prng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn bytes(&mut self, lo: usize, hi: usize, alphabet: &[u8]) -> Vec<u8> {
            let n = lo + self.below(hi - lo + 1);
            (0..n).map(|_| alphabet[self.below(alphabet.len())]).collect()
        }
    }

    /// Random fields, a good share of them repeating earlier ones, with some sensitive and some binary.
    fn random_fields(rng: &mut Prng, pool: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>, bool)> {
        const COMMON: [(&str, &str); 8] = [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("user-agent", "pratique/0.1"),
            ("accept-encoding", "gzip, deflate"),
            ("content-type", "application/json"),
            ("cache-control", "no-cache"),
            ("cookie", "a=b"),
        ];
        let lower: Vec<u8> = (b'a'..=b'z').chain([b'-']).collect();
        let text: Vec<u8> = (0x20..0x7f).collect();
        let any: Vec<u8> = (0..=255).collect();
        let mut out = Vec::new();
        for _ in 0..rng.below(13) {
            let r = rng.below(100);
            let (name, value) = if r < 40 {
                let (n, v) = COMMON[rng.below(COMMON.len())];
                (n.as_bytes().to_vec(), v.as_bytes().to_vec())
            } else if r < 60 && !pool.is_empty() {
                pool[rng.below(pool.len())].clone()
            } else if r < 85 {
                (rng.bytes(1, 14, &lower), rng.bytes(0, 40, &text))
            } else if r < 95 {
                (COMMON[rng.below(COMMON.len())].0.as_bytes().to_vec(), rng.bytes(0, 30, &text))
            } else {
                (rng.bytes(1, 6, &lower), rng.bytes(0, 20, &any))
            };
            if pool.len() < 40 {
                pool.push((name.clone(), value.clone()));
            } else {
                let i = rng.below(40);
                pool[i] = (name.clone(), value.clone());
            }
            out.push((name, value, rng.below(10) == 0));
        }
        out
    }

    /// Runs the encoder over random fields and table size changes with a decoder beside it, checking after each
    /// block that the decoder has the fields back and the same table, and returns the corpus in the file format.
    fn random_corpus(sequences: usize, seed: u64) -> String {
        let mut rng = Prng(seed);
        let mut text = String::new();
        for _ in 0..sequences {
            let mut e = Encoder::new();
            let mut d = Decoder::new(DEFAULT_TABLE_SIZE, 1 << 20);
            let mut pool = Vec::new();
            text.push_str("seq 4096\n");
            for block in 0..2 + rng.below(5) {
                if block == 0 || rng.below(4) == 0 {
                    let sizes = [0usize, 32, 64, 256, 1000, 4096, 100_000];
                    e.set_peer_table_size(sizes[rng.below(sizes.len())]);
                    if rng.below(3) == 0 {
                        e.set_peer_table_size(sizes[rng.below(sizes.len())]);
                    }
                }
                let fields = random_fields(&mut rng, &mut pool);
                let refs: Vec<FieldRef> = fields.iter().map(|(n, v, s)| FieldRef { name: n, value: v, sensitive: *s }).collect();
                let mut out = Vec::new();
                e.encode(&refs, &mut out);
                let mut got = Vec::new();
                assert_eq!(d.decode(&out, &mut got), Ok(true));
                let want: Vec<Field> = fields.iter().map(|(n, v, _)| Field { name: n.clone(), value: v.clone() }).collect();
                assert_eq!(got, want);
                assert_eq!(e.table_state(), d.table_state(), "the tables went out of step");
                text.push_str(&format!("block {}\n", hex(&out)));
                for (n, v, _) in &fields {
                    text.push_str(&format!("field {} {}\n", hex(n), hex(v)));
                }
            }
            text.push_str("end\n");
        }
        text
    }

    #[test]
    fn what_the_encoder_makes_the_decoder_reads_and_the_tables_stay_in_step() {
        let text = random_corpus(300, 0x7541);
        assert!(text.lines().filter(|l| l.starts_with("block")).count() > 900);
    }

    #[test]
    fn emit_oracle_corpus() {
        // `HPACK_ORACLE_OUT=corpus.txt cargo test --lib emit_oracle_corpus`, then `tools/hpack_oracle.py check
        // corpus.txt` has Python's decoder read what this encoder wrote
        let text = random_corpus(60, 0x0123_4567);
        if let Ok(path) = std::env::var("HPACK_ORACLE_OUT") {
            std::fs::write(path, text).unwrap();
        }
    }

    // ------------------------------------------------------------------------------------ the decoder's limits

    fn run(block: &[u8]) -> Result<Vec<(String, String)>, Error> {
        let mut d = decoder();
        let mut out = Vec::new();
        d.decode(block, &mut out)?;
        Ok(pairs(&out))
    }

    #[test]
    fn broken_blocks_are_errors() {
        assert_eq!(run(&unhex("80")), Err(Error::Index(0)));
        assert_eq!(run(&unhex("be")), Err(Error::Index(62)), "the dynamic table is empty");
        assert_eq!(run(&unhex("ff8001")), Err(Error::Index(255)));
        assert_eq!(run(&unhex("4100")).map(|_| ()), Ok(()), "index 1 is a name; its value is empty");
        assert_eq!(run(&unhex("7f8001")), Err(Error::Index(191)), "a name index past the tables");
        assert_eq!(run(&unhex("40")), Err(Error::Truncated), "a literal that ends at once");
        assert_eq!(run(&unhex("400161")), Err(Error::Truncated), "no value");
        assert_eq!(run(&unhex("400a61")), Err(Error::Truncated), "a string longer than the block");
        assert_eq!(run(&unhex("ff")), Err(Error::Truncated));
        // an index or a length that does not fit 32 bits
        assert_eq!(run(&unhex("ffffffffff1f")), Err(Error::Integer));
        assert_eq!(run(&unhex("4000ffffffffff1f")), Err(Error::Integer));
        // a table size update must come first and may not ask for more than was allowed
        assert_eq!(run(&unhex("8220")), Err(Error::SizeUpdateLate));
        let mut big = Vec::new();
        encode_int(&mut big, 5, 0x20, 5000);
        assert_eq!(run(&big), Err(Error::SizeUpdateTooLarge(5000)));
    }

    #[test]
    fn huffman_strings_are_checked() {
        // a literal with a one-byte name "a" and a Huffman value
        assert_eq!(run(&unhex("4001618161")), Err(Error::Huffman(huffman::Error::Padding)), "'/' and then 01: the padding is not ones");
        assert_eq!(run(&unhex("400161851fffffffff")), Err(Error::Huffman(huffman::Error::Eos)), "'a' then more than thirty ones");
        assert_eq!(run(&unhex("400161841fffffff")), Err(Error::Huffman(huffman::Error::Padding)), "'a' then 27 ones: far too long for padding");
        assert_eq!(run(&unhex("40016181ff")), Err(Error::Huffman(huffman::Error::Padding)), "eight bits of padding");
        assert_eq!(run(&unhex("400161811f")).unwrap(), list(&[("a", "a")]));
    }

    #[test]
    fn a_string_longer_than_the_limits_is_an_error() {
        let mut d = Decoder::new(20, 30);
        let mut long = vec![0x40, 0x01, b'a', 40];
        long.extend_from_slice(&[b'x'; 40]);
        assert_eq!(d.decode(&long, &mut Vec::new()), Err(Error::StringTooLong));
        // in Huffman too: 60 bytes of '0' are 38 bytes coded
        let mut d = Decoder::new(20, 30);
        let coded = {
            let mut c = Vec::new();
            huffman::encode(&[b'0'; 60], &mut c);
            c
        };
        let mut block = vec![0x40, 0x01, b'a', 0x80 | coded.len() as u8];
        block.extend_from_slice(&coded);
        assert_eq!(d.decode(&block, &mut Vec::new()), Err(Error::StringTooLong));
    }

    #[test]
    fn a_list_over_the_limit_is_cut_but_the_block_is_still_read_through() {
        // two fields of 32 + 1 + 1 = 34 bytes each; room for one
        let mut e = Encoder::new();
        let fields = [FieldRef { name: b"a", value: b"1", sensitive: false }, FieldRef { name: b"b", value: b"2", sensitive: false }];
        let mut block = Vec::new();
        e.encode(&fields, &mut block);
        let mut d = Decoder::new(4096, 40);
        let mut out = Vec::new();
        assert_eq!(d.decode(&block, &mut out), Ok(false));
        assert_eq!(pairs(&out), list(&[("a", "1")]));
        // both went into the table all the same: the next block can use them
        assert_eq!(d.table_state(), (2, 68));
        let mut again = Vec::new();
        e.encode(&fields[1..], &mut again);
        assert_eq!(again, [0x80 | 62], "the encoder refers to the entry both of them have");
        let mut out = Vec::new();
        assert_eq!(d.decode(&again, &mut out), Ok(true));
        assert_eq!(pairs(&out), list(&[("b", "2")]));
    }

    #[test]
    fn the_dynamic_table_evicts_and_resizes() {
        let mut d = Decoder::new(100, 1 << 20);
        let literal = |name: &str, value: &str| {
            let mut v = vec![0x40, name.len() as u8];
            v.extend_from_slice(name.as_bytes());
            v.push(value.len() as u8);
            v.extend_from_slice(value.as_bytes());
            v
        };
        let mut out = Vec::new();
        // each is 32 + 2 + 2 = 36: two fit in 100, the third evicts the first
        d.decode(&literal("aa", "11"), &mut out).unwrap();
        d.decode(&literal("bb", "22"), &mut out).unwrap();
        assert_eq!(d.table_state(), (2, 72));
        d.decode(&literal("cc", "33"), &mut out).unwrap();
        assert_eq!(d.table_state(), (2, 72));
        out.clear();
        d.decode(&[0x80 | 62, 0x80 | 63], &mut out).unwrap();
        assert_eq!(pairs(&out), list(&[("cc", "33"), ("bb", "22")]), "newest first");
        assert_eq!(d.decode(&[0x80 | 64], &mut out), Err(Error::Index(64)));
        // an entry larger than the whole table empties it and is not kept
        let huge = literal("name", &"v".repeat(90));
        d.decode(&huge, &mut Vec::new()).unwrap();
        assert_eq!(d.table_state(), (0, 0));
        // a size update to 40 evicts down to one entry; to 0, all
        d.decode(&literal("dd", "44"), &mut Vec::new()).unwrap();
        d.decode(&literal("ee", "55"), &mut Vec::new()).unwrap();
        let mut update = Vec::new();
        encode_int(&mut update, 5, 0x20, 40);
        d.decode(&update, &mut Vec::new()).unwrap();
        assert_eq!(d.table_state(), (1, 36));
        d.decode(&[0x20], &mut Vec::new()).unwrap();
        assert_eq!(d.table_state(), (0, 0));
        // several updates at the start are fine
        d.decode(&[0x20, 0x20 | 5, 0x82], &mut Vec::new()).unwrap();
    }

    #[test]
    fn random_and_damaged_blocks_never_panic_or_balloon() {
        let mut rng = Prng(0xfeed_f00d);
        let mut valid = Vec::new();
        let mut e = Encoder::new();
        let mut pool = Vec::new();
        for _ in 0..40 {
            let fields = random_fields(&mut rng, &mut pool);
            let refs: Vec<FieldRef> = fields.iter().map(|(n, v, s)| FieldRef { name: n, value: v, sensitive: *s }).collect();
            let mut out = Vec::new();
            e.encode(&refs, &mut out);
            valid.push(out);
        }
        for round in 0..6000 {
            let mut block = if round % 3 == 0 {
                (0..rng.below(60)).map(|_| rng.next() as u8).collect::<Vec<u8>>()
            } else {
                valid[rng.below(valid.len())].clone()
            };
            if round % 3 != 0 && !block.is_empty() {
                for _ in 0..1 + rng.below(3) {
                    let i = rng.below(block.len());
                    block[i] = rng.next() as u8;
                }
                if rng.below(4) == 0 {
                    block.truncate(rng.below(block.len() + 1));
                }
            }
            let mut d = Decoder::new(256, 200);
            let mut out = Vec::new();
            let _ = d.decode(&block, &mut out);
            let kept: usize = out.iter().map(|f| f.size()).sum();
            assert!(kept <= 200, "{kept} bytes of fields kept under a limit of 200");
            let (_, table) = d.table_state();
            assert!(table <= 256);
        }
    }

    // ------------------------------------------------------------------------------------ the encoder's choices

    #[test]
    fn sensitive_fields_are_never_indexed_and_never_added() {
        let mut e = Encoder::new();
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b"authorization", value: b"Bearer secret", sensitive: true }], &mut out);
        // 0001 prefix; the name is static index 23
        assert_eq!(out[0], 0x10 | 15, "never indexed, name index 23 continues past the 4-bit prefix");
        assert_eq!(e.table_state(), (0, 0));
        // the same again: still a literal, not an index
        let mut again = Vec::new();
        e.encode(&[FieldRef { name: b"authorization", value: b"Bearer secret", sensitive: true }], &mut again);
        assert_eq!(out, again);
        // a name that is nowhere is sent in full
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b"x-secret", value: b"v", sensitive: true }], &mut out);
        assert_eq!(out[0], 0x10);
        assert_eq!(run(&out).unwrap(), list(&[("x-secret", "v")]));
    }

    #[test]
    fn a_field_that_would_take_over_the_table_is_not_added() {
        let mut e = Encoder::new();
        let value = vec![b'v'; 3000];
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b"x-big", value: &value, sensitive: false }], &mut out);
        assert_eq!(out[0] & 0xf0, 0x00, "a literal without indexing");
        assert_eq!(e.table_state(), (0, 0));
    }

    #[test]
    fn the_table_size_is_announced_at_the_start_of_the_next_block() {
        let mut e = Encoder::new();
        e.set_peer_table_size(0);
        e.set_peer_table_size(100);
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b":method", value: b"GET", sensitive: false }], &mut out);
        // the smallest size since the last block is announced with this one: 0 (and the last, 100, with the next)
        assert_eq!(hex(&out), "2082");
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b":method", value: b"GET", sensitive: false }], &mut out);
        assert_eq!(hex(&out), "3f4582");
        // and then nothing more
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b":method", value: b"GET", sensitive: false }], &mut out);
        assert_eq!(hex(&out), "82");
        // a decoder takes the updates, and also both together (the RFC allows that)
        let mut d = Decoder::new(4096, 1 << 20);
        let mut fields = Vec::new();
        assert_eq!(d.decode(&unhex("2082"), &mut fields), Ok(true));
        assert_eq!(d.decode(&unhex("3f4582"), &mut fields), Ok(true));
        assert_eq!(d.decode(&unhex("203f4582"), &mut fields), Ok(true));
        // more than 4096 is not used, whatever the peer allows
        e.set_peer_table_size(1 << 20);
        let mut out = Vec::new();
        e.encode(&[], &mut out);
        let mut size = Vec::new();
        encode_int(&mut size, 5, 0x20, 4096);
        assert_eq!(out, size);
        // a smaller table evicts: fill it, then shrink it
        let mut e = Encoder::new();
        let mut out = Vec::new();
        e.encode(&[FieldRef { name: b"aa", value: b"11", sensitive: false }, FieldRef { name: b"bb", value: b"22", sensitive: false }], &mut out);
        assert_eq!(e.table_state(), (2, 72));
        e.set_peer_table_size(40);
        assert_eq!(e.table_state(), (1, 36));
    }

    #[test]
    fn repeated_fields_become_one_byte() {
        let mut e = Encoder::new();
        let f = [FieldRef { name: b"x-request-id", value: b"7f3a9c", sensitive: false }];
        let mut first = Vec::new();
        e.encode(&f, &mut first);
        assert!(first.len() > 5);
        let mut second = Vec::new();
        e.encode(&f, &mut second);
        assert_eq!(second, [0x80 | 62]);
        // static entries too
        let mut third = Vec::new();
        e.encode(&[FieldRef { name: b":method", value: b"POST", sensitive: false }, FieldRef { name: b":status", value: b"404", sensitive: false }], &mut third);
        assert_eq!(hex(&third), "838d");
    }
}
