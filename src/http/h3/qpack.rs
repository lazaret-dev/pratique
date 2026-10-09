//! QPACK (RFC 9204), the header compression of HTTP/3: an [`Encoder`] and a [`Decoder`], each with its half of the dynamic table, and
//! no I/O. Unlike HPACK, whose header blocks change the table themselves, QPACK keeps the table's changes on a stream of their own
//! (the encoder stream) and the acknowledgments on another (the decoder stream), so that a request is not held up by a header block
//! that arrived before an insertion it refers to; a block that does refer to one the decoder has not seen is *blocked* until it has.
//!
//! What the decoder guards against, since it reads what a server sent:
//!
//! * integers over 62 bits, indexes that point outside the tables, to entries that were evicted, or at or above the required insert
//!   count the block declares, a required insert count that no encoder could have made, a base below zero;
//! * more blocked streams than the decoder said it would take (SETTINGS_QPACK_BLOCKED_STREAMS), a dynamic table that grows past the
//!   capacity the decoder announced, an entry larger than the table, an instruction for the encoder stream that is cut anywhere (the
//!   rest comes later) or that is longer than any instruction the table could hold;
//! * Huffman strings with a coded EOS or with padding that is not the beginning of EOS (see [`crate::http::h2::huffman`], shared
//!   with HPACK), and a header list larger than the limit it was given: the block is still read to its end, and the caller is told.
//!
//! The encoder keeps the rules of section 2.1: it inserts only what it can fit without evicting an entry that is not acknowledged or
//! is still referred to by a block that is not, it counts the streams that could be blocked and keeps them within what the decoder
//! allows (and within what it is configured to risk: none, by default, so that it refers only to what is acknowledged), and it never
//! indexes a field marked sensitive. Streams, and what to do about their errors, are for the HTTP/3 connection above this.

use super::qpack_static::STATIC;
use crate::http::h2::hpack::{Field, FieldRef};
use crate::http::h2::huffman;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;

/// The largest integer QPACK carries (RFC 9204 section 4.1.1: at least 62 bits must be possible).
const MAX_INT: u64 = (1 << 62) - 1;

/// What an entry costs besides its name and value (RFC 9204 section 3.2.1).
const ENTRY_OVERHEAD: usize = 32;

/// The error codes of RFC 9204 section 6.
pub(crate) const DECOMPRESSION_FAILED: u64 = 0x200;
pub(crate) const ENCODER_STREAM_ERROR: u64 = 0x201;
pub(crate) const DECODER_STREAM_ERROR: u64 = 0x202;

/// Why QPACK cannot go on. Each is an error of the whole HTTP/3 connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    /// An encoded field section that cannot be decoded (QPACK_DECOMPRESSION_FAILED).
    Decompression(&'static str),
    /// An instruction on the encoder stream that cannot be carried out (QPACK_ENCODER_STREAM_ERROR).
    EncoderStream(&'static str),
    /// An instruction on the decoder stream that cannot be carried out (QPACK_DECODER_STREAM_ERROR).
    DecoderStream(&'static str),
}

impl Error {
    /// The HTTP/3 error code for closing the connection.
    pub(crate) fn code(&self) -> u64 {
        match self {
            Error::Decompression(_) => DECOMPRESSION_FAILED,
            Error::EncoderStream(_) => ENCODER_STREAM_ERROR,
            Error::DecoderStream(_) => DECODER_STREAM_ERROR,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decompression(m) => write!(f, "QPACK_DECOMPRESSION_FAILED: {m}"),
            Error::EncoderStream(m) => write!(f, "QPACK_ENCODER_STREAM_ERROR: {m}"),
            Error::DecoderStream(m) => write!(f, "QPACK_DECODER_STREAM_ERROR: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Why something that was read is not valid, before it is known which stream it was on.
#[derive(Debug, PartialEq, Eq)]
enum Bad {
    /// There is not enough of it (on a stream, the rest may still come).
    Short,
    Invalid(&'static str),
}

impl Bad {
    fn in_section(self) -> Error {
        match self {
            Bad::Short => Error::Decompression("the field section ends inside a field line"),
            Bad::Invalid(m) => Error::Decompression(m),
        }
    }
}

// ------------------------------------------------------------------------------------------------ primitives

/// An integer with a `prefix_bits`-bit prefix (RFC 7541 section 5.1, with the sizes of RFC 9204): the prefix is the low bits of
/// `buf[*pos]`. Values over 2^62 - 1 are refused.
fn get_int(buf: &[u8], pos: &mut usize, prefix_bits: u32) -> Result<u64, Bad> {
    let mask = (1u64 << prefix_bits) - 1;
    let first = *buf.get(*pos).ok_or(Bad::Short)?;
    *pos += 1;
    let mut value = u64::from(first) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(Bad::Short)?;
        *pos += 1;
        if shift > 62 {
            return Err(Bad::Invalid("an integer with too many bytes"));
        }
        let part = u64::from(b & 0x7f);
        // (a part that would not fit in 62 bits is refused before it is shifted)
        if part > (MAX_INT >> shift) {
            return Err(Bad::Invalid("an integer over 62 bits"));
        }
        value = value.checked_add(part << shift).filter(|v| *v <= MAX_INT).ok_or(Bad::Invalid("an integer over 62 bits"))?;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Writes `value` with a `prefix_bits`-bit prefix, `flags` being the bits above it in the first byte.
fn put_int(out: &mut Vec<u8>, prefix_bits: u32, flags: u8, value: u64) {
    let max = (1u64 << prefix_bits) - 1;
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

/// A string literal that starts with `prefix_bits` bits of its first byte (RFC 9204 section 4.1.2: a Huffman flag, then the length
/// in the other `prefix_bits - 1`). At most `limit` bytes once decoded are kept: `Ok(true)` if it was, `Ok(false)` if it was longer
/// (it is read past and not kept). A string whose coded length is over `wait_limit` is an error at once, whether or not the bytes
/// are there yet (on a stream, so that no one waits for ever for what could never be used).
fn get_string(buf: &[u8], pos: &mut usize, prefix_bits: u32, limit: usize, wait_limit: usize, out: &mut Vec<u8>) -> Result<bool, Bad> {
    let first = *buf.get(*pos).ok_or(Bad::Short)?;
    let coded = first & (1 << (prefix_bits - 1)) != 0;
    let len = get_int(buf, pos, prefix_bits - 1)?;
    let len = usize::try_from(len).ok().filter(|l| *l <= wait_limit).ok_or(Bad::Invalid("a string that is too long"))?;
    let end = pos.checked_add(len).filter(|e| *e <= buf.len()).ok_or(Bad::Short)?;
    let raw = &buf[*pos..end];
    *pos = end;
    if coded {
        match huffman::decode(raw, out, limit) {
            Ok(()) => Ok(true),
            Err(huffman::Error::TooLong) => Ok(false),
            Err(_) => Err(Bad::Invalid("a Huffman string that does not decode")),
        }
    } else if raw.len() > limit {
        Ok(false)
    } else {
        out.extend_from_slice(raw);
        Ok(true)
    }
}

/// Writes a string literal after `flags` (the bits of the first byte above the prefix), Huffman coded if that is shorter.
fn put_string(out: &mut Vec<u8>, prefix_bits: u32, flags: u8, s: &[u8]) {
    let coded = huffman::encoded_len(s);
    if coded < s.len() {
        put_int(out, prefix_bits - 1, flags | (1 << (prefix_bits - 1)), coded as u64);
        huffman::encode(s, out);
    } else {
        put_int(out, prefix_bits - 1, flags, s.len() as u64);
        out.extend_from_slice(s);
    }
}

// ------------------------------------------------------------------------------------------------ the tables

fn static_entry(index: u64) -> Result<(&'static [u8], &'static [u8]), Bad> {
    let i = usize::try_from(index).ok().filter(|i| *i < STATIC.len()).ok_or(Bad::Invalid("a static table index that does not exist"))?;
    Ok((STATIC[i].0.as_bytes(), STATIC[i].1.as_bytes()))
}

#[derive(Debug)]
struct Entry {
    field: Field,
    /// (The encoder's) how many field sections that are not acknowledged refer to this entry.
    refs: u32,
}

/// The dynamic table (RFC 9204 section 3.2): entries have absolute indices from 0 on, the oldest at the front here.
#[derive(Debug, Default)]
struct DynTable {
    entries: VecDeque<Entry>,
    /// The sum of the entries' sizes.
    size: usize,
    /// The most `size` may be: what the encoder last set.
    capacity: usize,
    /// How many entries were evicted: the absolute index of `entries[0]`.
    dropped: u64,
}

impl DynTable {
    /// How many entries were ever inserted (the Insert Count): the absolute index of the next one.
    fn inserted(&self) -> u64 {
        self.dropped + self.entries.len() as u64
    }

    fn get(&self, abs: u64) -> Option<&Entry> {
        let i = abs.checked_sub(self.dropped)?;
        self.entries.get(usize::try_from(i).ok()?)
    }

    fn get_mut(&mut self, abs: u64) -> Option<&mut Entry> {
        let i = abs.checked_sub(self.dropped)?;
        self.entries.get_mut(usize::try_from(i).ok()?)
    }

    fn evict_oldest(&mut self) {
        if let Some(old) = self.entries.pop_front() {
            self.size -= old.field.size();
            self.dropped += 1;
        }
    }

    /// Sets the capacity, evicting from the oldest as needed to fit it.
    fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity;
        while self.size > capacity {
            self.evict_oldest();
        }
    }

    /// Adds an entry, evicting what has to go to make room for it. The caller has seen that it fits the capacity.
    fn push(&mut self, field: Field) {
        let size = field.size();
        debug_assert!(size <= self.capacity);
        while self.size + size > self.capacity {
            self.evict_oldest();
        }
        self.size += size;
        self.entries.push_back(Entry { field, refs: 0 });
    }
}

// ------------------------------------------------------------------------------------------------ the decoder

/// What came of a field section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decoded {
    /// The fields were appended. `within_limit` is false if the list was larger than the limit (then the fields up to the limit were
    /// kept; the block was read to its end all the same).
    Done { within_limit: bool },
    /// The section refers to entries that the encoder stream has not delivered yet. Ask again, with the same bytes, when
    /// [`Decoder::insert_count`] has reached `required_insert_count`.
    Blocked { required_insert_count: u64 },
}

/// Decodes the field sections of one connection and keeps its dynamic table from the instructions of the encoder stream.
#[derive(Debug)]
pub(crate) struct Decoder {
    table: DynTable,
    /// What this endpoint announced as SETTINGS_QPACK_MAX_TABLE_CAPACITY, and SETTINGS_QPACK_BLOCKED_STREAMS.
    max_capacity: usize,
    max_blocked: usize,
    /// The largest field list kept, by the measure of [`Field::size`].
    max_list_size: usize,
    /// The bytes of an instruction of the encoder stream that has not all come.
    inbox: Vec<u8>,
    /// Decoder stream instructions that are to be sent.
    out: Vec<u8>,
    /// What the encoder has been told it can count on (Section Acknowledgments and Insert Count Increments sent).
    known_received: u64,
    /// Streams whose section is waiting for entries, and the insert count it needs.
    blocked: BTreeMap<u64, u64>,
}

impl Decoder {
    /// `max_table_capacity` and `max_blocked_streams` are the values of the two QPACK settings that are sent to the peer (0 and 0:
    /// no dynamic table); `max_list_size` is the largest field list to keep.
    pub(crate) fn new(max_table_capacity: usize, max_blocked_streams: usize, max_list_size: usize) -> Decoder {
        Decoder { table: DynTable::default(), max_capacity: max_table_capacity, max_blocked: max_blocked_streams, max_list_size, inbox: Vec::new(), out: Vec::new(), known_received: 0, blocked: BTreeMap::new() }
    }

    /// How many entries the encoder has inserted so far.
    pub(crate) fn insert_count(&self) -> u64 {
        self.table.inserted()
    }

    /// How many streams are waiting for entries.
    pub(crate) fn blocked_streams(&self) -> usize {
        self.blocked.len()
    }

    /// The number of entries in the dynamic table and their total size.
    #[cfg(test)]
    fn table_state(&self) -> (usize, usize) {
        (self.table.entries.len(), self.table.size)
    }

    /// Takes in what arrived on the encoder stream, in any pieces. Whole instructions are carried out; the end of one that is cut
    /// waits for the next call.
    pub(crate) fn encoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut inbox = std::mem::take(&mut self.inbox);
        inbox.extend_from_slice(data);
        let mut pos = 0;
        while pos < inbox.len() {
            match self.instruction(&inbox[pos..]) {
                Ok(used) => pos += used,
                Err(Bad::Short) => break,
                Err(Bad::Invalid(m)) => return Err(Error::EncoderStream(m)),
            }
        }
        inbox.drain(..pos);
        self.inbox = inbox;
        // a stream whose section has what it waited for is not blocked any longer, whether or not it has been tried again yet
        let inserted = self.table.inserted();
        self.blocked.retain(|_, required| *required > inserted);
        Ok(())
    }

    /// One instruction from the start of `buf`: how many bytes it took, if it is all there.
    fn instruction(&mut self, buf: &[u8]) -> Result<usize, Bad> {
        let mut pos = 0;
        let first = buf[0];
        // no string in an instruction can be larger than the table (a coded one is at most 30 bits a byte)
        let limit = self.table.capacity;
        let wait = limit.saturating_mul(4).saturating_add(8);
        if first & 0x80 != 0 {
            // Insert With Name Reference
            let from_static = first & 0x40 != 0;
            let index = get_int(buf, &mut pos, 6)?;
            let mut value = Vec::new();
            if !get_string(buf, &mut pos, 8, limit, wait, &mut value)? {
                return Err(Bad::Invalid("an entry larger than the table"));
            }
            let name = if from_static {
                static_entry(index)?.0.to_vec()
            } else {
                self.dynamic_relative_to_end(index)?.field.name.clone()
            };
            self.insert(Field { name, value })?;
        } else if first & 0x40 != 0 {
            // Insert With Literal Name
            let mut name = Vec::new();
            let mut value = Vec::new();
            if !get_string(buf, &mut pos, 6, limit, wait, &mut name)? || !get_string(buf, &mut pos, 8, limit, wait, &mut value)? {
                return Err(Bad::Invalid("an entry larger than the table"));
            }
            self.insert(Field { name, value })?;
        } else if first & 0x20 != 0 {
            // Set Dynamic Table Capacity
            let capacity = get_int(buf, &mut pos, 5)?;
            if capacity > self.max_capacity as u64 {
                return Err(Bad::Invalid("a table capacity over the maximum"));
            }
            self.table.set_capacity(capacity as usize);
        } else {
            // Duplicate
            let index = get_int(buf, &mut pos, 5)?;
            let field = self.dynamic_relative_to_end(index)?.field.clone();
            self.insert(field)?;
        }
        Ok(pos)
    }

    /// The entry with this relative index in an instruction (0 is the newest).
    fn dynamic_relative_to_end(&self, index: u64) -> Result<&Entry, Bad> {
        let abs = self.table.inserted().checked_sub(index).and_then(|n| n.checked_sub(1)).ok_or(Bad::Invalid("a reference to an entry that was never inserted"))?;
        self.table.get(abs).ok_or(Bad::Invalid("a reference to an entry that was evicted"))
    }

    fn insert(&mut self, field: Field) -> Result<(), Bad> {
        if field.size() > self.table.capacity {
            return Err(Bad::Invalid("an entry larger than the table"));
        }
        self.table.push(field);
        Ok(())
    }

    /// Decodes one encoded field section of `stream` (the payload of a HEADERS frame, whole) and appends its fields to `out`.
    ///
    /// A section that refers to entries that are not here yet is [`Decoded::Blocked`]: it has to be given again, from the start, after
    /// more of the encoder stream. Too many streams blocked at once is an error. An error of any kind means the connection can no
    /// longer be trusted to decode (RFC 9204 section 2.2.3).
    pub(crate) fn decode(&mut self, stream: u64, block: &[u8], out: &mut Vec<Field>) -> Result<Decoded, Error> {
        let mut pos = 0;
        let encoded_count = get_int(block, &mut pos, 8).map_err(Bad::in_section)?;
        let required = self.required_insert_count(encoded_count)?;
        let negative = block.get(pos).ok_or(Error::Decompression("the field section ends inside its prefix"))? & 0x80 != 0;
        let delta = get_int(block, &mut pos, 7).map_err(Bad::in_section)?;
        let base = if !negative {
            required.checked_add(delta).ok_or(Error::Decompression("a base that does not fit"))?
        } else {
            // (the base would be negative)
            if required <= delta {
                return Err(Error::Decompression("a negative base"));
            }
            required - delta - 1
        };
        if required > self.table.inserted() {
            if !self.blocked.contains_key(&stream) && self.blocked.len() >= self.max_blocked {
                return Err(Error::Decompression("more blocked streams than were allowed"));
            }
            self.blocked.insert(stream, required);
            return Ok(Decoded::Blocked { required_insert_count: required });
        }
        self.blocked.remove(&stream);

        let limit = self.max_list_size;
        let mut list = 0usize;
        let mut within = true;
        while pos < block.len() {
            let first = block[pos];
            // what the line spells out is borrowed from a table or read into these; nothing is copied for a line that is not kept, so
            // a long run of lines that name a large entry costs no more than the run
            let mut name_buf = Vec::new();
            let mut value_buf = Vec::new();
            let name: &[u8];
            let value: &[u8];
            let mut kept = true;
            if first & 0x80 != 0 {
                // Indexed Field Line
                let from_static = first & 0x40 != 0;
                let index = get_int(block, &mut pos, 6).map_err(Bad::in_section)?;
                (name, value) = if from_static { static_entry(index).map_err(Bad::in_section)? } else { self.entry_before_base(base, index, required)? };
            } else if first & 0x40 != 0 {
                // Literal Field Line With Name Reference
                let from_static = first & 0x10 != 0;
                let index = get_int(block, &mut pos, 4).map_err(Bad::in_section)?;
                name = if from_static { static_entry(index).map_err(Bad::in_section)?.0 } else { self.entry_before_base(base, index, required)?.0 };
                kept = get_string(block, &mut pos, 8, limit, usize::MAX, &mut value_buf).map_err(Bad::in_section)?;
                value = &value_buf;
            } else if first & 0x20 != 0 {
                // Literal Field Line With Literal Name
                kept = get_string(block, &mut pos, 4, limit, usize::MAX, &mut name_buf).map_err(Bad::in_section)?;
                kept &= get_string(block, &mut pos, 8, limit, usize::MAX, &mut value_buf).map_err(Bad::in_section)?;
                name = &name_buf;
                value = &value_buf;
            } else if first & 0x10 != 0 {
                // Indexed Field Line With Post-Base Index
                let index = get_int(block, &mut pos, 4).map_err(Bad::in_section)?;
                (name, value) = self.entry_after_base(base, index, required)?;
            } else {
                // Literal Field Line With Post-Base Name Reference
                let index = get_int(block, &mut pos, 3).map_err(Bad::in_section)?;
                name = self.entry_after_base(base, index, required)?.0;
                kept = get_string(block, &mut pos, 8, limit, usize::MAX, &mut value_buf).map_err(Bad::in_section)?;
                value = &value_buf;
            }
            if !kept {
                within = false;
                continue;
            }
            list = list.saturating_add(name.len() + value.len() + ENTRY_OVERHEAD);
            if list > limit {
                within = false;
            } else {
                out.push(Field { name: name.to_vec(), value: value.to_vec() });
            }
        }
        if required > 0 {
            // the encoder counts on being told, and may then evict what the section used
            put_int(&mut self.out, 7, 0x80, stream);
            self.known_received = self.known_received.max(required);
        }
        Ok(Decoded::Done { within_limit: within })
    }

    /// The entry that a relative index in a field section names (0 is the one before the base), as a name and a value.
    fn entry_before_base(&self, base: u64, index: u64, required: u64) -> Result<(&[u8], &[u8]), Error> {
        let abs = base.checked_sub(index).and_then(|n| n.checked_sub(1)).ok_or(Error::Decompression("a reference to an entry before the first"))?;
        self.entry_at(abs, required)
    }

    /// The entry that a post-base index names (0 is the base itself).
    fn entry_after_base(&self, base: u64, index: u64, required: u64) -> Result<(&[u8], &[u8]), Error> {
        let abs = base.checked_add(index).ok_or(Error::Decompression("a reference that does not fit"))?;
        self.entry_at(abs, required)
    }

    fn entry_at(&self, abs: u64, required: u64) -> Result<(&[u8], &[u8]), Error> {
        if abs >= required {
            return Err(Error::Decompression("a reference to an entry at or above the required insert count"));
        }
        let e = self.table.get(abs).ok_or(Error::Decompression("a reference to an entry that was evicted"))?;
        Ok((&e.field.name, &e.field.value))
    }

    /// The Required Insert Count that an encoded one stands for (RFC 9204 section 4.5.1.1).
    fn required_insert_count(&self, encoded: u64) -> Result<u64, Error> {
        if encoded == 0 {
            return Ok(0);
        }
        let max_entries = (self.max_capacity / ENTRY_OVERHEAD) as u64;
        let full_range = 2 * max_entries;
        if encoded > full_range {
            return Err(Error::Decompression("a required insert count that no encoder could have made"));
        }
        let max_value = self.table.inserted() + max_entries;
        let max_wrapped = max_value / full_range * full_range;
        let mut required = max_wrapped + encoded - 1;
        if required > max_value {
            if required <= full_range {
                return Err(Error::Decompression("a required insert count that no encoder could have made"));
            }
            required -= full_range;
        }
        if required == 0 {
            return Err(Error::Decompression("a required insert count of 0 that is not coded as 0"));
        }
        Ok(required)
    }

    /// A stream that was reset, or that will not be read, will not be decoded: the encoder is told, so that it may forget what it
    /// counted on from it. (With no dynamic table there is nothing to tell.)
    pub(crate) fn cancel_stream(&mut self, stream: u64) {
        self.blocked.remove(&stream);
        if self.max_capacity > 0 {
            put_int(&mut self.out, 6, 0x40, stream);
        }
    }

    /// What is to be sent on the decoder stream: the acknowledgments of the sections that were decoded, a cancellation for each
    /// stream that was abandoned, and one Insert Count Increment for all the entries that arrived and no section has acknowledged.
    pub(crate) fn take_output(&mut self) -> Vec<u8> {
        let inserted = self.table.inserted();
        if inserted > self.known_received {
            put_int(&mut self.out, 6, 0x00, inserted - self.known_received);
            self.known_received = inserted;
        }
        std::mem::take(&mut self.out)
    }
}

// ------------------------------------------------------------------------------------------------ the encoder

/// How the encoder uses the dynamic table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EncoderConfig {
    /// The most the encoder lets the table hold, if the peer allows that much (0: never use the dynamic table). The capacity it
    /// announces on the encoder stream is the peer's whole maximum, whatever this is, and it evicts entries itself to stay within
    /// this: the decoder keeps the ones it let go of until it needs the room, which does it no harm. (RFC 9204 lets the encoder
    /// announce less; ls-qpack, under LiteSpeed and aioquic, then reads the Required Insert Count wrongly, as if the maximum were
    /// that capacity.)
    pub(crate) table_capacity: usize,
    /// How many streams may be blocked on what the encoder inserted, if the peer allows it. 0 refers only to entries that are
    /// acknowledged, so that no stream ever waits on another; a request then sees the table's benefit from the second one on.
    pub(crate) blocked_streams: usize,
    /// Insert only the fields whose names are of little worth to someone who guesses their values (the advice of RFC 9204 section
    /// 7.1.3): what a client says about itself and what it accepts. Without this the encoder inserts any field that is not
    /// sensitive.
    pub(crate) only_safe_names: bool,
}

impl Default for EncoderConfig {
    fn default() -> EncoderConfig {
        EncoderConfig { table_capacity: 4096, blocked_streams: 0, only_safe_names: true }
    }
}

/// The most capacity the encoder announces, whatever the peer allows.
const MAX_ANNOUNCED: usize = 1 << 20;

/// Names of fields that are worth indexing and that tell little to anyone who learns that a guess of their value was right.
const SAFE_NAMES: &[&[u8]] = &[b":authority", b"user-agent", b"accept", b"accept-encoding", b"accept-language", b"content-type", b"cache-control"];

/// An encoded field section that the decoder has not acknowledged yet.
#[derive(Debug)]
struct Outstanding {
    required: u64,
    /// The absolute indices that it refers to, one each time.
    refs: Vec<u64>,
}

/// Encodes the field sections of one connection and keeps the encoder's half of the dynamic table.
#[derive(Debug)]
pub(crate) struct Encoder {
    cfg: EncoderConfig,
    table: DynTable,
    /// What the peer announced: SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS (0 and 0 until its SETTINGS).
    peer_max_capacity: usize,
    peer_max_blocked: usize,
    /// How many insertions the decoder has said it has.
    known_received: u64,
    /// Encoder stream instructions that are to be sent.
    out: Vec<u8>,
    /// The sections not acknowledged yet, by stream, oldest first.
    outstanding: HashMap<u64, VecDeque<Outstanding>>,
    /// The bytes of an instruction of the decoder stream that has not all come.
    inbox: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new(cfg: EncoderConfig) -> Encoder {
        Encoder { cfg, table: DynTable::default(), peer_max_capacity: 0, peer_max_blocked: 0, known_received: 0, out: Vec::new(), outstanding: HashMap::new(), inbox: Vec::new() }
    }

    /// The peer's SETTINGS arrived (RFC 9204 section 5). Until they do, the table is not used.
    pub(crate) fn set_peer_settings(&mut self, max_table_capacity: u64, max_blocked_streams: u64) {
        self.peer_max_capacity = usize::try_from(max_table_capacity).unwrap_or(usize::MAX);
        self.peer_max_blocked = usize::try_from(max_blocked_streams).unwrap_or(usize::MAX);
    }

    /// What is to be sent on the encoder stream (before the section that needs it is sent, or at least not after it for long).
    pub(crate) fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// How much of the encoder stream is waiting to be sent: the table is not changed while a lot is.
    pub(crate) fn pending_output(&self) -> usize {
        self.out.len()
    }

    /// The number of entries in the dynamic table and their total size.
    #[cfg(test)]
    fn table_state(&self) -> (usize, usize) {
        (self.table.entries.len(), self.table.size)
    }

    /// How many streams have a section that the decoder may be waiting on entries for.
    fn blocked_count(&self) -> usize {
        self.outstanding.values().filter(|q| q.iter().any(|s| s.required > self.known_received)).count()
    }

    /// Whether a section of `stream` may refer to entries that are not acknowledged.
    fn may_block(&self, stream: u64) -> bool {
        let allowed = self.cfg.blocked_streams.min(self.peer_max_blocked);
        if allowed == 0 {
            return false;
        }
        let already = self.outstanding.get(&stream).is_some_and(|q| q.iter().any(|s| s.required > self.known_received));
        already || self.blocked_count() < allowed
    }

    /// Appends the encoding of one field section of `stream` to `out`: the prefix and the field lines. What the section needs on the
    /// encoder stream is put in [`take_output`](Encoder::take_output)'s buffer.
    pub(crate) fn encode(&mut self, stream: u64, fields: &[FieldRef<'_>], out: &mut Vec<u8>) {
        // The base is the insert count before this section, so the entries that it inserts are the ones after the base, and are
        // referred to by post-base indices; one pass over the fields is enough (the prefix, which needs the largest index used, is
        // written after the lines are made).
        let base = self.table.inserted();
        let may_block = self.may_block(stream);
        let mut lines = Vec::new();
        let mut refs: Vec<u64> = Vec::new();
        for f in fields {
            self.field(*f, base, may_block, &mut lines, &mut refs);
        }
        let required = refs.iter().max().map_or(0, |m| m + 1);
        let encoded_count = if required == 0 { 0 } else { required % (2 * (self.peer_max_capacity / ENTRY_OVERHEAD) as u64) + 1 };
        put_int(out, 8, 0, encoded_count);
        if required == 0 {
            // (a section that needs nothing has the base 0, as in the sample algorithm of RFC 9204 appendix B: it could say more, and
            // ls-qpack, one decoder, refuses it)
            put_int(out, 7, 0, 0);
        } else if base >= required {
            put_int(out, 7, 0, base - required);
        } else {
            put_int(out, 7, 0x80, required - base - 1);
        }
        out.extend_from_slice(&lines);
        if required > 0 {
            // (the entries were counted as the lines were made, so that no insertion for a later line could evict one)
            self.outstanding.entry(stream).or_default().push_back(Outstanding { required, refs });
        }
    }

    fn field(&mut self, f: FieldRef<'_>, base: u64, may_block: bool, lines: &mut Vec<u8>, refs: &mut Vec<u64>) {
        let never = if f.sensitive { 0x20 } else { 0 };
        let (static_full, static_name) = static_lookup(f.name, f.value);
        if !f.sensitive {
            if let Some(i) = static_full {
                put_int(lines, 6, 0xc0, i as u64);
                return;
            }
            match self.find_dynamic(f.name, Some(f.value)) {
                // an entry that is there and may be used
                Some(abs) if self.referenceable(abs, may_block) => {
                    self.refer(abs, base, lines, refs);
                    return;
                }
                // one that is there but that a section may not use yet: not put there again
                Some(_) => {}
                // one that is put there for the next time, and for this one if a section may wait for it
                None => {
                    if self.try_insert(f, static_name) && may_block {
                        let abs = self.table.inserted() - 1;
                        self.refer(abs, base, lines, refs);
                        return;
                    }
                }
            }
        }
        // a literal, with the name from a table if it is in one
        if let Some(i) = static_name {
            put_int(lines, 4, 0x50 | never, i as u64);
        } else if let Some(abs) = if f.sensitive { None } else { self.find_dynamic(f.name, None).filter(|a| self.referenceable(*a, may_block) && *a < base) } {
            self.note(abs, refs);
            put_int(lines, 4, 0x40 | never, base - abs - 1);
        } else {
            put_string(lines, 4, 0x20 | if f.sensitive { 0x10 } else { 0 }, f.name);
            put_string(lines, 8, 0, f.value);
            return;
        }
        put_string(lines, 8, 0, f.value);
    }

    /// Writes an indexed field line for the entry `abs` and notes that the section refers to it.
    fn refer(&mut self, abs: u64, base: u64, lines: &mut Vec<u8>, refs: &mut Vec<u64>) {
        self.note(abs, refs);
        if abs < base {
            put_int(lines, 6, 0x80, base - abs - 1);
        } else {
            put_int(lines, 4, 0x10, abs - base);
        }
    }

    /// The section being made refers to entry `abs`: it stays until the decoder says it has the section (or gives it up).
    fn note(&mut self, abs: u64, refs: &mut Vec<u64>) {
        if let Some(e) = self.table.get_mut(abs) {
            e.refs += 1;
        }
        refs.push(abs);
    }

    /// Whether a section may refer to entry `abs`: it is there, and the decoder has it or a stream may wait for it.
    fn referenceable(&self, abs: u64, may_block: bool) -> bool {
        self.table.get(abs).is_some() && (abs < self.known_received || may_block)
    }

    /// The newest entry with this name (and this value, if given).
    fn find_dynamic(&self, name: &[u8], value: Option<&[u8]>) -> Option<u64> {
        self.table.entries.iter().enumerate().rev().find(|(_, e)| e.field.name == name && value.is_none_or(|v| e.field.value == v)).map(|(i, _)| self.table.dropped + i as u64)
    }

    /// Puts the field in the table, if it may be and it fits without evicting what must stay. Returns whether it did.
    fn try_insert(&mut self, f: FieldRef<'_>, static_name: Option<usize>) -> bool {
        // what is announced (the decoder's table is that big) and how much the encoder lets itself use of it
        let announce = self.peer_max_capacity.min(MAX_ANNOUNCED);
        let fill = self.cfg.table_capacity.min(announce);
        let size = f.name.len() + f.value.len() + ENTRY_OVERHEAD;
        if fill == 0 || size > fill / 2 || self.pending_output() > 4096 || f.value.len() > 1024 {
            return false;
        }
        if self.cfg.only_safe_names && !SAFE_NAMES.contains(&f.name) {
            return false;
        }
        if self.table.capacity > announce {
            return false;
        }
        // what would have to go for it to fit, oldest first, and whether that may be: the decoder has the entry, and no section
        // that it has not acknowledged (or that is being made) refers to it
        let mut freed = 0;
        let mut evicted = 0;
        while self.table.size - freed + size > fill {
            let Some(e) = self.table.entries.get(evicted) else { return false };
            if self.table.dropped + (evicted as u64) >= self.known_received || e.refs > 0 {
                return false;
            }
            freed += e.field.size();
            evicted += 1;
        }
        if self.table.capacity != announce {
            // (the first insertion: the table has no capacity until the encoder says so)
            put_int(&mut self.out, 5, 0x20, announce as u64);
            self.table.set_capacity(announce);
        }
        let inserted = self.table.inserted();
        match (static_name, self.find_dynamic(f.name, None)) {
            (Some(i), _) => {
                put_int(&mut self.out, 6, 0xc0, i as u64);
                put_string(&mut self.out, 8, 0, f.value);
            }
            (None, Some(abs)) => {
                put_int(&mut self.out, 6, 0x80, inserted - abs - 1);
                put_string(&mut self.out, 8, 0, f.value);
            }
            (None, None) => {
                put_string(&mut self.out, 6, 0x40, f.name);
                put_string(&mut self.out, 8, 0, f.value);
            }
        }
        // (the decoder's table is as big as announced and holds what is let go of here until it needs the room; it evicts the oldest
        // first, so what stays here is never what it evicts)
        for _ in 0..evicted {
            self.table.evict_oldest();
        }
        self.table.push(Field { name: f.name.to_vec(), value: f.value.to_vec() });
        true
    }

    /// Takes in what arrived on the decoder stream, in any pieces.
    pub(crate) fn decoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut inbox = std::mem::take(&mut self.inbox);
        inbox.extend_from_slice(data);
        let mut pos = 0;
        while pos < inbox.len() {
            let first = inbox[pos];
            let mut at = pos;
            let step = if first & 0x80 != 0 {
                get_int(&inbox, &mut at, 7).map(|stream| Instruction::Acknowledge(stream))
            } else if first & 0x40 != 0 {
                get_int(&inbox, &mut at, 6).map(|stream| Instruction::Cancel(stream))
            } else {
                get_int(&inbox, &mut at, 6).map(|n| Instruction::Increment(n))
            };
            match step {
                Ok(i) => {
                    pos = at;
                    self.instruction(i)?;
                }
                Err(Bad::Short) => break,
                Err(Bad::Invalid(m)) => return Err(Error::DecoderStream(m)),
            }
        }
        inbox.drain(..pos);
        self.inbox = inbox;
        Ok(())
    }

    fn instruction(&mut self, i: Instruction) -> Result<(), Error> {
        match i {
            Instruction::Acknowledge(stream) => {
                let section = self.outstanding.get_mut(&stream).and_then(|q| q.pop_front()).ok_or(Error::DecoderStream("an acknowledgment of a stream with no section waiting"))?;
                if self.outstanding.get(&stream).is_some_and(|q| q.is_empty()) {
                    self.outstanding.remove(&stream);
                }
                self.release(&section);
                self.known_received = self.known_received.max(section.required);
            }
            Instruction::Cancel(stream) => {
                if let Some(q) = self.outstanding.remove(&stream) {
                    for s in &q {
                        self.release(s);
                    }
                }
            }
            Instruction::Increment(n) => {
                if n == 0 {
                    return Err(Error::DecoderStream("an insert count increment of 0"));
                }
                match self.known_received.checked_add(n) {
                    Some(total) if total <= self.table.inserted() => self.known_received = total,
                    _ => return Err(Error::DecoderStream("an insert count increment beyond what was sent")),
                }
            }
        }
        Ok(())
    }

    fn release(&mut self, section: &Outstanding) {
        for abs in &section.refs {
            if let Some(e) = self.table.get_mut(*abs) {
                e.refs = e.refs.saturating_sub(1);
            }
        }
    }
}

enum Instruction {
    Acknowledge(u64),
    Cancel(u64),
    Increment(u64),
}

/// The index of the static entry with this name and value, and of the first one with this name.
fn static_lookup(name: &[u8], value: &[u8]) -> (Option<usize>, Option<usize>) {
    let mut named = None;
    for (i, (n, v)) in STATIC.iter().enumerate() {
        if n.as_bytes() == name {
            if v.as_bytes() == value {
                return (Some(i), Some(named.unwrap_or(i)));
            }
            named.get_or_insert(i);
        }
    }
    (None, named)
}

// The tests, and the model-based exchange that the tests and the fuzzer both run.
#[cfg(test)]
#[path = "qpack_tests.rs"]
mod tests;
#[cfg(any(test, pratique_fuzzing))]
#[path = "qpack_harness.rs"]
pub(crate) mod harness;
