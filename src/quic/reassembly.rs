//! Putting the pieces of a QUIC byte stream back in order (RFC 9000 section 2.2 and 7.5).
//!
//! STREAM and CRYPTO frames carry a range of a stream, in any order, repeated and overlapping. A [`Reassembler`] takes the ranges
//! as they come and gives the bytes back from the front, in order, once there are no holes before them. It is the receive buffer
//! of every stream and of the handshake data at each encryption level.
//!
//! What it checks: data that is already there (not yet read) must be the same bytes each time it is sent (a peer that changes
//! what it sent for an offset is broken or an attacker, and RFC 9000 section 2.2 allows closing the connection for it); nothing is
//! held beyond a window ahead of what has been read (the flow-control limit for a stream, at least 4096 bytes for handshake data,
//! RFC 9000 section 7.5); and the number of separate received ranges is bounded, so that many one-byte ranges with a hole between
//! each cannot make the buffer cost much more than the bytes it holds. Bytes live in fixed pages rather than being copied when
//! two received ranges meet: a stream sent in reverse order therefore copies each byte into storage once.

use super::rangeset::RangeSet;
use std::collections::BTreeMap;

/// The most separate received ranges held (holes in what has come, plus one).
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

/// Storage is sparse by this much: a distant range allocates only the pages it touches, while adjacent small frames share a page.
const PAGE: usize = 4096;
const PAGE_U64: u64 = PAGE as u64;

/// The receive buffer of one stream.
#[derive(Default)]
pub struct Reassembler {
    /// How much has been read: the offset of the next byte to read.
    read: u64,
    /// The ranges that have arrived and have not been read. Touching ranges are one, so every gap is a hole.
    received: RangeSet,
    /// Fixed pages that hold the bytes in `received`, by their aligned stream offset. A page can include holes; `received` says
    /// which bytes in it are meaningful.
    pages: BTreeMap<u64, Box<[u8; PAGE]>>,
    /// The bytes in `received`.
    held: usize,
    /// Bytes copied into storage, for the cost invariant in tests and the buffer fuzz model.
    #[cfg(any(test, pratique_fuzzing))]
    copied: usize,
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
        self.received
            .max()
            .map(|last| last + 1)
            .unwrap_or(self.read)
            .max(self.read)
    }

    /// How many bytes can be read now: those from the read offset to the first hole.
    pub fn readable(&self) -> usize {
        match self.received.first() {
            Some(range) if range.start == self.read => (range.end - range.start) as usize,
            _ => 0,
        }
    }

    /// Takes the range `offset..offset + data.len()`. `window` is how far past the read offset a byte may be: a range that ends
    /// beyond `read_offset() + window` is refused. A range that was read already is dropped (it is a repeat), a part of one that
    /// was read already is dropped, and what overlaps what is held must say the same.
    pub fn insert(&mut self, offset: u64, data: &[u8], window: u64) -> Result<(), Error> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::Exceeded)?;
        if end > self.read.saturating_add(window) {
            return Err(Error::Exceeded);
        }
        if end <= self.read {
            return Ok(());
        }
        let (start, data) = if offset < self.read {
            (self.read, &data[(self.read - offset) as usize..])
        } else {
            (offset, data)
        };
        let end = start + data.len() as u64;
        let overlaps = self.received.within(start..end);
        for range in &overlaps {
            let from = (range.start - start) as usize;
            let len = (range.end - range.start) as usize;
            if !self.equals(range.start, &data[from..from + len]) {
                return Err(Error::Inconsistent);
            }
        }
        let mut received = self.received.clone();
        received.insert(start..end);
        if received.range_count() > MAX_PIECES {
            return Err(Error::Exceeded);
        }
        let mut cursor = start;
        for range in overlaps {
            if cursor < range.start {
                let from = (cursor - start) as usize;
                let to = (range.start - start) as usize;
                self.store(cursor, &data[from..to]);
                self.held += to - from;
            }
            cursor = range.end;
        }
        if cursor < end {
            let from = (cursor - start) as usize;
            self.store(cursor, &data[from..]);
            self.held += data.len() - from;
        }
        self.received = received;
        Ok(())
    }

    fn page(offset: u64) -> u64 {
        offset / PAGE_U64 * PAGE_U64
    }

    /// Whether storage already has these bytes at `at`.
    fn equals(&self, mut at: u64, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let page_at = Self::page(at);
            let Some(page) = self.pages.get(&page_at) else {
                return false;
            };
            let within = (at - page_at) as usize;
            let n = bytes.len().min(PAGE - within);
            if page[within..within + n] != bytes[..n] {
                return false;
            }
            bytes = &bytes[n..];
            at += n as u64;
        }
        true
    }

    /// Copies new bytes into their pages. No received byte is moved when later ranges touch it.
    fn store(&mut self, mut at: u64, mut bytes: &[u8]) {
        #[cfg(any(test, pratique_fuzzing))]
        {
            self.copied += bytes.len();
        }
        while !bytes.is_empty() {
            let page_at = Self::page(at);
            let within = (at - page_at) as usize;
            let n = bytes.len().min(PAGE - within);
            let page = self
                .pages
                .entry(page_at)
                .or_insert_with(|| Box::new([0; PAGE]));
            page[within..within + n].copy_from_slice(&bytes[..n]);
            bytes = &bytes[n..];
            at += n as u64;
        }
    }

    fn copy_out(&self, mut at: u64, mut out: &mut [u8]) {
        while !out.is_empty() {
            let page_at = Self::page(at);
            let page = self.pages.get(&page_at).expect("received bytes have storage");
            let within = (at - page_at) as usize;
            let n = out.len().min(PAGE - within);
            out[..n].copy_from_slice(&page[within..within + n]);
            out = &mut out[n..];
            at += n as u64;
        }
    }

    fn free_read_pages(&mut self) {
        while self
            .pages
            .keys()
            .next()
            .is_some_and(|at| at.saturating_add(PAGE_U64) <= self.read)
        {
            self.pages.pop_first();
        }
    }

    /// Bytes copied into storage, for deterministic complexity checks.
    #[cfg(any(test, pratique_fuzzing))]
    #[doc(hidden)]
    pub fn copy_work(&self) -> usize {
        self.copied
    }

    /// Reads bytes from the front into `buf`; returns how many (nothing if there is a hole at the read offset).
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = self.readable().min(buf.len());
        self.copy_out(self.read, &mut buf[..n]);
        self.received.remove(self.read..self.read + n as u64);
        self.read += n as u64;
        self.held -= n;
        self.free_read_pages();
        n
    }

    /// Throws away what can be read now, without copying it out (a stream that nobody wants any more); returns how many bytes.
    pub fn discard(&mut self) -> usize {
        let n = self.readable();
        self.received.remove(self.read..self.read + n as u64);
        self.read += n as u64;
        self.held -= n;
        self.free_read_pages();
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
    fn data_in_reverse_order_is_stored_with_linear_copy_work() {
        const N: u64 = 64 * 1024;
        let mut r = Reassembler::new();
        for at in (0..N).rev() {
            r.insert(at, &bytes(at, at + 1), N).unwrap();
        }
        assert_eq!(r.copy_work(), N as usize, "a received byte was copied again");
        assert_eq!((r.buffered(), r.readable()), (N as usize, N as usize));
        assert_eq!(r.take(), bytes(0, N));
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
            assert_eq!(
                r.insert(offset, &other, 100),
                Err(Error::Inconsistent),
                "{offset}+{len}"
            );
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
        assert_eq!(
            r.insert(4090, &bytes(4090, 4097), 4096),
            Err(Error::Exceeded)
        );
        assert_eq!(r.buffered(), 0);
        r.insert(4090, &bytes(4090, 4096), 4096).unwrap();
        assert_eq!(r.insert(0, &bytes(0, 5000), 4096), Err(Error::Exceeded));
        // the window moves with what is read
        r.insert(0, &bytes(0, 4090), 4096).unwrap();
        assert_eq!(r.take(), bytes(0, 4096));
        r.insert(4096, &bytes(4096, 8192), 4096).unwrap();
        assert_eq!(
            r.insert(8192, &bytes(8192, 8193), 4096),
            Err(Error::Exceeded)
        );
        // an offset so large that it overflows is refused, not wrapped
        assert_eq!(
            r.insert(u64::MAX - 2, &[0; 5], u64::MAX),
            Err(Error::Exceeded)
        );
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
        assert_eq!(
            r.insert(2 * MAX_PIECES as u64 + 1, &[1], u64::MAX),
            Err(Error::Exceeded)
        );
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
                    assert_eq!(
                        r.insert(offset, &bytes(offset, end), window),
                        Err(Error::Exceeded),
                        "round {round}"
                    );
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
