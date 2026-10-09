//! Putting the pieces of a QUIC byte stream back in order (RFC 9000 section 2.2 and 7.5).
//!
//! STREAM and CRYPTO frames carry a range of a stream, in any order, repeated and overlapping. A [`Reassembler`] takes the ranges
//! as they come and gives the bytes back from the front, in order, once there are no holes before them. It is the receive buffer
//! of every stream and of the handshake data at each encryption level.
//!
//! What it checks: data that is already there (not yet read) must be the same bytes each time it is sent (a peer that changes
//! what it sent for an offset is broken or an attacker, and RFC 9000 section 2.2 allows closing the connection for it); nothing is
//! held beyond a window ahead of what has been read (the flow-control limit for a stream, at least 4096 bytes for handshake data,
//! RFC 9000 section 7.5); and the number of separate pieces is bounded, so that many one-byte ranges with a hole between each
//! cannot make the buffer cost much more than the bytes it holds.

use std::collections::BTreeMap;

/// The most separate pieces held (holes in what has come, plus one).
pub const MAX_PIECES: usize = 4096;

/// Why a range could not be taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// It reaches past the window, or would make too many pieces. (CRYPTO_BUFFER_EXCEEDED for handshake data, FLOW_CONTROL_ERROR
    /// for a stream.)
    Exceeded,
    /// It says other bytes for an offset than what was received before.
    Inconsistent,
}

/// A piece: bytes from `pos` on are the data, and its offset is the key it is stored under.
struct Piece {
    bytes: Vec<u8>,
    pos: usize,
}

impl Piece {
    fn data(&self) -> &[u8] {
        &self.bytes[self.pos..]
    }
}

/// The receive buffer of one stream.
#[derive(Default)]
pub struct Reassembler {
    /// How much has been read: the offset of the next byte to read.
    read: u64,
    /// Pieces that have not been read, by the offset of their first byte. They do not overlap, and none touches the next (they
    /// are merged), so every gap between two is a hole.
    pieces: BTreeMap<u64, Piece>,
    /// The bytes in `pieces`.
    held: usize,
}

impl Reassembler {
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// The offset of the next byte to read: everything before it has been read.
    pub fn read_offset(&self) -> u64 {
        self.read
    }

    /// How many bytes are held, in order or not.
    pub fn buffered(&self) -> usize {
        self.held
    }

    /// The offset just after the last byte that has come (the highest end of a range that is held, or what was read).
    pub fn end_offset(&self) -> u64 {
        self.pieces.iter().next_back().map(|(&at, p)| at + p.data().len() as u64).unwrap_or(self.read).max(self.read)
    }

    /// How many bytes can be read now: those from the read offset to the first hole.
    pub fn readable(&self) -> usize {
        match self.pieces.iter().next() {
            Some((&at, p)) if at == self.read => p.data().len(),
            _ => 0,
        }
    }

    /// Takes the range `offset..offset + data.len()`. `window` is how far past the read offset a byte may be: a range that ends
    /// beyond `read_offset() + window` is refused. A range that was read already is dropped (it is a repeat), a part of one that
    /// was read already is dropped, and what overlaps what is held must say the same.
    pub fn insert(&mut self, offset: u64, data: &[u8], window: u64) -> Result<(), Error> {
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Exceeded)?;
        if end > self.read.saturating_add(window) {
            return Err(Error::Exceeded);
        }
        if end <= self.read {
            return Ok(());
        }
        let (mut start, mut data) = if offset < self.read { (self.read, &data[(self.read - offset) as usize..]) } else { (offset, data) };
        // the piece that begins before `start`, if it reaches it: what it has of the new range has to be the same, and then the new
        // range begins where it ends
        if let Some((&at, piece)) = self.pieces.range(..=start).next_back() {
            let have = piece.data();
            let piece_end = at + have.len() as u64;
            if piece_end > start {
                let overlap = ((piece_end - start) as usize).min(data.len());
                let from = (start - at) as usize;
                if have[from..from + overlap] != data[..overlap] {
                    return Err(Error::Inconsistent);
                }
                data = &data[overlap..];
                start += overlap as u64;
            }
        }
        // the pieces that begin inside what is left of the range: the same check, and the gaps between them are what is new
        let mut new: Vec<(u64, &[u8])> = Vec::new();
        let mut cursor = start;
        let mut rest = data;
        let inside: Vec<(u64, usize)> = self.pieces.range(start..start + rest.len() as u64).map(|(&at, p)| (at, p.data().len())).collect();
        for (at, len) in inside {
            if at > cursor {
                new.push((cursor, &rest[..(at - cursor) as usize]));
            }
            let take = ((at + len as u64).min(start + data.len() as u64) - at) as usize;
            let skip = (at - start) as usize;
            if self.pieces[&at].data()[..take] != data[skip..skip + take] {
                return Err(Error::Inconsistent);
            }
            cursor = at + take as u64;
            rest = &data[(cursor - start) as usize..];
        }
        if !rest.is_empty() {
            new.push((cursor, rest));
        }
        // each new piece joins the pieces it touches, so it makes a piece of its own only if it touches none, and makes one less if
        // it touches both
        let mut pieces = self.pieces.len() as isize;
        for (at, bytes) in &new {
            let left = self.pieces.range(..*at).next_back().is_some_and(|(&b, p)| b + p.data().len() as u64 == *at);
            let right = self.pieces.contains_key(&(*at + bytes.len() as u64));
            pieces += if left && right { -1 } else if left || right { 0 } else { 1 };
        }
        if pieces > MAX_PIECES as isize {
            return Err(Error::Exceeded);
        }
        for (at, bytes) in new {
            self.add(at, bytes);
        }
        Ok(())
    }

    /// Adds bytes that overlap nothing held, joining the pieces they touch.
    fn add(&mut self, at: u64, bytes: &[u8]) {
        self.held += bytes.len();
        let end = at + bytes.len() as u64;
        let before = self.pieces.range(..at).next_back().filter(|(&b, p)| b + p.data().len() as u64 == at).map(|(&b, _)| b);
        let (key, mut joined) = match before.and_then(|b| self.pieces.remove(&b).map(|p| (b, p))) {
            Some(found) => found,
            None => (at, Piece { bytes: Vec::with_capacity(bytes.len()), pos: 0 }),
        };
        // what was read from the front of a piece that goes on growing is given back once it is as much as what is left
        if joined.pos > 0 && joined.pos >= joined.data().len() {
            joined.bytes.drain(..joined.pos);
            joined.pos = 0;
        }
        joined.bytes.extend_from_slice(bytes);
        if let Some(next) = self.pieces.remove(&end) {
            joined.bytes.extend_from_slice(next.data());
        }
        self.pieces.insert(key, joined);
    }

    /// Reads bytes from the front into `buf`; returns how many (nothing if there is a hole at the read offset).
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let Some(mut entry) = self.pieces.first_entry() else { return 0 };
        if *entry.key() != self.read {
            return 0;
        }
        let piece = entry.get_mut();
        let n = piece.data().len().min(buf.len());
        buf[..n].copy_from_slice(&piece.data()[..n]);
        piece.pos += n;
        let emptied = piece.data().is_empty();
        let at = *entry.key();
        if emptied {
            entry.remove();
        } else {
            let piece = entry.remove();
            self.pieces.insert(at + n as u64, piece);
        }
        self.read += n as u64;
        self.held -= n;
        n
    }

    /// Throws away what can be read now, without copying it out (a stream that nobody wants any more); returns how many bytes.
    pub fn discard(&mut self) -> usize {
        let Some(entry) = self.pieces.first_entry() else { return 0 };
        if *entry.key() != self.read {
            return 0;
        }
        let n = entry.get().data().len();
        entry.remove();
        self.read += n as u64;
        self.held -= n;
        n
    }

    /// Takes everything that can be read now.
    pub fn take(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; self.readable()];
        let n = self.read(&mut out);
        debug_assert_eq!(n, out.len());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(from: u64, to: u64) -> Vec<u8> {
        (from..to).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn data_in_order_is_read_in_order() {
        let mut r = Reassembler::new();
        r.insert(0, &bytes(0, 10), 100).unwrap();
        r.insert(10, &bytes(10, 25), 100).unwrap();
        assert_eq!(r.readable(), 25);
        assert_eq!(r.take(), bytes(0, 25));
        assert_eq!((r.read_offset(), r.buffered(), r.readable()), (25, 0, 0));
    }

    #[test]
    fn data_out_of_order_waits_for_the_hole_to_be_filled() {
        let mut r = Reassembler::new();
        r.insert(10, &bytes(10, 20), 100).unwrap();
        r.insert(30, &bytes(30, 40), 100).unwrap();
        assert_eq!((r.readable(), r.buffered(), r.end_offset()), (0, 20, 40));
        r.insert(0, &bytes(0, 10), 100).unwrap();
        assert_eq!(r.readable(), 20);
        assert_eq!(r.take(), bytes(0, 20));
        r.insert(20, &bytes(20, 30), 100).unwrap();
        assert_eq!(r.take(), bytes(20, 40));
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn a_repeat_or_an_overlap_that_agrees_changes_nothing() {
        let mut r = Reassembler::new();
        r.insert(5, &bytes(5, 15), 100).unwrap();
        r.insert(5, &bytes(5, 15), 100).unwrap(); // the same again
        r.insert(7, &bytes(7, 12), 100).unwrap(); // inside
        r.insert(3, &bytes(3, 8), 100).unwrap(); // across the start
        r.insert(12, &bytes(12, 20), 100).unwrap(); // across the end
        r.insert(0, &bytes(0, 30), 100).unwrap(); // across everything
        assert_eq!(r.buffered(), 30);
        assert_eq!(r.take(), bytes(0, 30));
        // what was read is dropped, wholly or in part
        r.insert(0, &bytes(0, 10), 100).unwrap();
        r.insert(20, &bytes(20, 40), 100).unwrap();
        assert_eq!(r.buffered(), 10);
        assert_eq!(r.take(), bytes(30, 40));
    }

    #[test]
    fn bytes_that_disagree_with_what_is_held_are_refused() {
        for (offset, len) in [(5u64, 10u64), (3, 5), (12, 8), (0, 30), (9, 1), (14, 1)] {
            let mut r = Reassembler::new();
            r.insert(5, &bytes(5, 15), 100).unwrap();
            let mut other = bytes(offset, offset + len);
            // wrong in the part that overlaps what is held
            let overlap_at = (offset.max(5) - offset) as usize;
            other[overlap_at] ^= 0x55;
            assert_eq!(r.insert(offset, &other, 100), Err(Error::Inconsistent), "{offset}+{len}");
            // and nothing of it was kept
            assert_eq!(r.buffered(), 10);
            assert_eq!(r.end_offset(), 15);
        }
        // a hole between two pieces and a range that agrees with one and not the other
        let mut r = Reassembler::new();
        r.insert(0, &bytes(0, 5), 100).unwrap();
        r.insert(10, &bytes(10, 15), 100).unwrap();
        let mut across = bytes(3, 12);
        across[8] ^= 1;
        assert_eq!(r.insert(3, &across, 100), Err(Error::Inconsistent));
        assert_eq!(r.buffered(), 10);
        r.insert(3, &bytes(3, 12), 100).unwrap();
        assert_eq!(r.take(), bytes(0, 15));
    }

    #[test]
    fn nothing_is_held_beyond_the_window() {
        let mut r = Reassembler::new();
        assert_eq!(r.insert(4090, &bytes(4090, 4097), 4096), Err(Error::Exceeded));
        assert_eq!(r.buffered(), 0);
        r.insert(4090, &bytes(4090, 4096), 4096).unwrap();
        assert_eq!(r.insert(0, &bytes(0, 5000), 4096), Err(Error::Exceeded));
        // the window moves with what is read
        r.insert(0, &bytes(0, 4090), 4096).unwrap();
        assert_eq!(r.take(), bytes(0, 4096));
        r.insert(4096, &bytes(4096, 8192), 4096).unwrap();
        assert_eq!(r.insert(8192, &bytes(8192, 8193), 4096), Err(Error::Exceeded));
        // an offset so large that it overflows is refused, not wrapped
        assert_eq!(r.insert(u64::MAX - 2, &[0; 5], u64::MAX), Err(Error::Exceeded));
        // an empty range at the edge is fine, and past it is not
        r.insert(8192, &[], 4096).unwrap();
        assert_eq!(r.insert(8193, &[], 4096), Err(Error::Exceeded));
    }

    #[test]
    fn a_stream_cannot_be_made_into_many_small_pieces() {
        let mut r = Reassembler::new();
        // one byte at every other offset: each is a piece of its own
        for i in 0..MAX_PIECES as u64 {
            r.insert(2 * i + 1, &[1], u64::MAX).unwrap();
        }
        assert_eq!(r.buffered(), MAX_PIECES);
        assert_eq!(r.insert(2 * MAX_PIECES as u64 + 1, &[1], u64::MAX), Err(Error::Exceeded));
        // a byte that joins two pieces is not a new one
        r.insert(0, &[9], u64::MAX).unwrap();
        r.insert(2, &[1], u64::MAX).unwrap();
        assert_eq!(r.readable(), 4);
    }

    #[test]
    fn reading_in_small_pieces_gives_the_same_bytes() {
        let mut r = Reassembler::new();
        r.insert(0, &bytes(0, 1000), 4096).unwrap();
        r.insert(1000, &bytes(1000, 1500), 4096).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = r.read(&mut buf);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            assert_eq!(r.read_offset(), got.len() as u64);
            assert_eq!(r.buffered(), 1500 - got.len());
        }
        assert_eq!(got, bytes(0, 1500));
        // a range that arrives while a piece is part read
        r.insert(1500, &bytes(1500, 1600), 4096).unwrap();
        r.insert(1550, &bytes(1550, 1700), 4096).unwrap();
        assert_eq!(r.read(&mut buf[..10]), 10);
        r.insert(1590, &bytes(1590, 1800), 4096).unwrap();
        assert_eq!(r.take(), bytes(1510, 1800));
    }

    /// A model that has the whole stream as an array, to compare what the buffer does with random ranges.
    #[test]
    fn it_does_what_a_plain_array_does_with_random_ranges() {
        let mut seed = 0x2545f4914f6cdd1du64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..300 {
            let total = 1 + next(600);
            let window = 100 + next(700);
            let mut r = Reassembler::new();
            let mut have = vec![false; total as usize];
            let mut out = Vec::new();
            for _ in 0..80 {
                let offset = next(total);
                let len = next(60);
                let end = (offset + len).min(total);
                if end > r.read_offset() + window {
                    assert_eq!(r.insert(offset, &bytes(offset, end), window), Err(Error::Exceeded), "round {round}");
                    continue;
                }
                r.insert(offset, &bytes(offset, end), window).unwrap();
                for i in offset..end {
                    have[i as usize] = true;
                }
                // sometimes read, sometimes a part
                if next(3) == 0 {
                    let mut buf = vec![0u8; 1 + next(50) as usize];
                    let n = r.read(&mut buf);
                    out.extend_from_slice(&buf[..n]);
                }
                // what the buffer says it can read is what the array has from the read offset on without a hole
                let from = r.read_offset() as usize;
                let run = have[from..].iter().take_while(|&&h| h).count();
                assert_eq!(r.readable(), run, "round {round}");
                let held = have[from..].iter().filter(|&&h| h).count();
                assert_eq!(r.buffered(), held, "round {round}");
            }
            out.extend(r.take());
            assert_eq!(out, bytes(0, out.len() as u64), "round {round}");
        }
    }
}
