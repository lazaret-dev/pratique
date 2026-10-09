//! What QUIC puts on the wire at the lowest level (RFC 9000 sections 16 and 17.1 and appendix A): variable-length integers, and
//! packet numbers, which are sent truncated and recovered from the largest one received.
//!
//! There is no state and no I/O here.

/// The largest value a variable-length integer holds: 2^62 - 1.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// How many bytes `v` takes as a variable-length integer (the shortest way; one or two, four or eight).
///
/// Panics if `v` is more than [`MAX_VARINT`]: nothing that is sent is.
pub fn varint_len(v: u64) -> usize {
    assert!(v <= MAX_VARINT, "{v} is not a QUIC variable-length integer");
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Appends `v` as a variable-length integer, the shortest way.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    put_varint_len(out, v, varint_len(v));
}

/// Appends `v` as a variable-length integer of `len` bytes (1, 2, 4 or 8), which may be more than it needs: a length that is
/// written before what it measures is known is written with room for it, and then filled in (see [`patch_length`]).
///
/// Panics if `v` does not fit in `len` bytes or `len` is not one of those four.
pub fn put_varint_len(out: &mut Vec<u8>, v: u64, len: usize) {
    assert!(matches!(len, 1 | 2 | 4 | 8), "a variable-length integer is 1, 2, 4 or 8 bytes, not {len}");
    assert!(varint_len(v) <= len, "{v} does not fit in {len} bytes");
    let tag: u64 = match len {
        1 => 0,
        2 => 1,
        4 => 2,
        _ => 3,
    };
    let word = v | (tag << (len * 8 - 2));
    out.extend_from_slice(&word.to_be_bytes()[8 - len..]);
}

/// Fills in a two-byte length (as [`put_varint_len`] wrote it, with value 0) that is at `at` in `buf`.
///
/// Panics if `v` does not fit in two bytes (16,383).
pub fn patch_length(buf: &mut [u8], at: usize, v: u64) {
    assert!(v <= 16_383, "{v} does not fit in a two-byte length");
    buf[at] = 0x40 | (v >> 8) as u8;
    buf[at + 1] = v as u8;
}

/// Reads a variable-length integer from the start of `buf`: its value and how many bytes it took. `None` if `buf` ends first.
/// (A value written with more bytes than it needs is read all the same; where the rules forbid that, see [`Reader::varint_minimal`].)
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for b in &buf[1..len] {
        v = (v << 8) | *b as u64;
    }
    Some((v, len))
}

/// A cursor over bytes that were received. Every read says whether there was enough to read; nothing here panics on input.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// The input ended before a field did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Truncated;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    /// How far into the input the reader is.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// What has not been read.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn u8(&mut self) -> Result<u8, Truncated> {
        let b = *self.buf.get(self.pos).ok_or(Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn u32(&mut self) -> Result<u32, Truncated> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        if self.buf.len() - self.pos < n {
            return Err(Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads a variable-length integer.
    pub fn varint(&mut self) -> Result<u64, Truncated> {
        let (v, n) = get_varint(self.rest()).ok_or(Truncated)?;
        self.pos += n;
        Ok(v)
    }

    /// Reads a variable-length integer and says whether it was written the shortest way, which a frame type must be
    /// (RFC 9000 section 12.4).
    pub fn varint_minimal(&mut self) -> Result<(u64, bool), Truncated> {
        let (v, n) = get_varint(self.rest()).ok_or(Truncated)?;
        self.pos += n;
        Ok((v, varint_len(v) == n))
    }

    /// Reads a variable-length integer that says how many bytes follow, and those bytes.
    /// Like every read here, one that fails reads nothing.
    pub fn length_prefixed(&mut self) -> Result<&'a [u8], Truncated> {
        let start = self.pos;
        let n = self.varint()?;
        if n > (self.buf.len() - self.pos) as u64 {
            self.pos = start;
            return Err(Truncated);
        }
        self.bytes(n as usize)
    }
}

/// The most bytes a packet number takes on the wire (RFC 9000 section 17.1).
pub const MAX_PACKET_NUMBER_LEN: usize = 4;

/// How many bytes to send the packet number `pn` in, when the largest packet number that the peer has acknowledged is
/// `largest_acked` (`None` if it has acknowledged none): enough to tell it from any packet number that might be in flight,
/// which is a range of twice the number sent and not yet acknowledged (RFC 9000 appendix A.2). `None` if even four bytes are
/// not enough (a connection must not get so far ahead of what is acknowledged).
pub fn packet_number_len(pn: u64, largest_acked: Option<u64>) -> Option<usize> {
    let unacked = match largest_acked {
        Some(acked) => pn.saturating_sub(acked),
        None => pn.saturating_add(1),
    };
    let range = unacked.saturating_mul(2);
    (1..=MAX_PACKET_NUMBER_LEN).find(|&n| range < (1u64 << (8 * n)))
}

/// The packet number that a peer meant by sending `truncated`, in `nbytes` bytes (1 to 4), when the largest packet number
/// that this endpoint has received in this space is `largest` (`None` if none): the one nearest to the next one expected
/// (RFC 9000 appendix A.3).
pub fn decode_packet_number(largest: Option<u64>, truncated: u64, nbytes: usize) -> u64 {
    assert!((1..=MAX_PACKET_NUMBER_LEN).contains(&nbytes));
    let expected = largest.map_or(0, |l| l.saturating_add(1));
    let win = 1u64 << (8 * nbytes);
    let half = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | (truncated & mask);
    if candidate.saturating_add(half) <= expected && candidate < (1u64 << 62) - win {
        return candidate + win;
    }
    if candidate > expected.saturating_add(half) && candidate >= win {
        return candidate - win;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, v);
        out
    }

    #[test]
    fn the_variable_length_integers_of_the_rfc() {
        // RFC 9000 appendix A.1
        assert_eq!(get_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]), Some((151_288_809_941_952_652, 8)));
        assert_eq!(get_varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
        assert_eq!(get_varint(&[0x7b, 0xbd]), Some((15_293, 2)));
        assert_eq!(get_varint(&[0x25]), Some((37, 1)));
        // the same value, written with more bytes than it needs
        assert_eq!(get_varint(&[0x40, 0x25]), Some((37, 2)));
        assert_eq!(encoded(151_288_809_941_952_652), [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(encoded(494_878_333), [0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(encoded(15_293), [0x7b, 0xbd]);
        assert_eq!(encoded(37), [0x25]);
    }

    #[test]
    fn varints_change_length_at_the_boundaries() {
        for (v, n) in [(0u64, 1usize), (63, 1), (64, 2), (16_383, 2), (16_384, 4), (1_073_741_823, 4), (1_073_741_824, 8), (MAX_VARINT, 8)] {
            let e = encoded(v);
            assert_eq!(e.len(), n, "{v}");
            assert_eq!(varint_len(v), n);
            assert_eq!(get_varint(&e), Some((v, n)));
            // and with room for more
            let mut longer = Vec::new();
            put_varint_len(&mut longer, v, 8);
            assert_eq!(longer.len(), 8);
            assert_eq!(get_varint(&longer), Some((v, 8)));
        }
    }

    #[test]
    fn a_varint_that_is_cut_short_is_not_read() {
        assert_eq!(get_varint(&[]), None);
        assert_eq!(get_varint(&[0x40]), None);
        assert_eq!(get_varint(&[0x80, 0, 0]), None);
        assert_eq!(get_varint(&[0xc0, 0, 0, 0, 0, 0, 0]), None);
        let mut r = Reader::new(&[0x80, 0, 0]);
        assert_eq!(r.varint(), Err(Truncated));
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn a_length_that_is_written_first_is_patched_in() {
        let mut buf = Vec::new();
        put_varint_len(&mut buf, 0, 2);
        buf.extend_from_slice(&[1, 2, 3]);
        patch_length(&mut buf, 0, 3);
        assert_eq!(buf, [0x40, 0x03, 1, 2, 3]);
        assert_eq!(get_varint(&buf), Some((3, 2)));
        patch_length(&mut buf, 0, 16_383);
        assert_eq!(&buf[..2], [0x7f, 0xff]);
    }

    #[test]
    fn the_reader_reads_what_is_there_and_no_more() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 0x03, 9, 8, 7, 0x05, 1]);
        assert_eq!(r.u8(), Ok(1));
        assert_eq!(r.u32(), Ok(0x0203_0405));
        assert_eq!(r.length_prefixed(), Ok(&[9u8, 8, 7][..]));
        // a length that is more than what is left
        assert_eq!(r.length_prefixed(), Err(Truncated));
        assert_eq!(r.rest(), [0x05, 1]);
        assert_eq!(r.bytes(3), Err(Truncated));
        assert_eq!(r.bytes(2), Ok(&[0x05u8, 1][..]));
        assert!(r.is_empty());
        assert_eq!(r.u8(), Err(Truncated));
    }

    #[test]
    fn a_varint_that_is_longer_than_it_needs_to_be_is_told() {
        let mut r = Reader::new(&[0x25, 0x40, 0x25, 0x7b, 0xbd]);
        assert_eq!(r.varint_minimal(), Ok((37, true)));
        assert_eq!(r.varint_minimal(), Ok((37, false)));
        assert_eq!(r.varint_minimal(), Ok((15_293, true)));
    }

    #[test]
    fn packet_numbers_are_recovered_as_the_rfc_says() {
        // RFC 9000 appendix A.3
        assert_eq!(decode_packet_number(Some(0xa82f30ea), 0x9b32, 2), 0xa82f9b32);
        // the nearest to the next one expected, either side of the window
        assert_eq!(decode_packet_number(Some(0xff), 0x00, 1), 0x100);
        assert_eq!(decode_packet_number(Some(0x100), 0xff, 1), 0xff);
        assert_eq!(decode_packet_number(None, 0, 1), 0);
        assert_eq!(decode_packet_number(None, 5, 1), 5);
        assert_eq!(decode_packet_number(Some(0), 1, 4), 1);
        // not past the largest packet number that exists
        assert_eq!(decode_packet_number(Some((1 << 62) - 1 - 5), 0xffff_ffff, 4), (1 << 62) - 1);
        // (and nothing a peer sends makes it fail)
        assert_eq!(decode_packet_number(Some(u64::MAX), 7, 1) & 0xff, 7);
    }

    #[test]
    fn packet_numbers_are_sent_in_enough_bytes() {
        // RFC 9000 appendix A.2: 0xabe8b3 acknowledged, 0xac5c02 sent: 29,519 in flight, twice that is 59,038: 16 bits
        assert_eq!(packet_number_len(0xac5c02, Some(0xabe8b3)), Some(2));
        // a first packet
        assert_eq!(packet_number_len(0, None), Some(1));
        // (nothing acknowledged, so the first packet number sent is 0 and 127 is the 128th: twice that fills 8 bits)
        assert_eq!(packet_number_len(126, None), Some(1));
        assert_eq!(packet_number_len(127, None), Some(2));
        assert_eq!(packet_number_len(1000, Some(999)), Some(1));
        assert_eq!(packet_number_len(1000 + 127, Some(1000)), Some(1));
        assert_eq!(packet_number_len(1000 + 128, Some(1000)), Some(2));
        assert_eq!(packet_number_len((1 << 23) - 1, Some(0)), Some(3));
        assert_eq!(packet_number_len(1 << 23, Some(0)), Some(4));
        assert_eq!(packet_number_len((1 << 31) - 1, Some(0)), Some(4));
        assert_eq!(packet_number_len(1 << 31, Some(0)), None);
    }

    #[test]
    fn what_is_sent_is_what_the_peer_recovers() {
        // for every packet number sent with the length chosen for it, the peer, which has received everything up to some
        // packet number within the window, gets the packet number back
        for pn in [0u64, 1, 2, 63, 64, 127, 128, 255, 256, 1000, 65_535, 65_536, 70_000, 0x7f_ffff, 0x80_0000, 1 << 30] {
            for behind in [0u64, 1, 2, 10, 100, 1000, 30_000] {
                let acked = pn.checked_sub(behind);
                let Some(n) = packet_number_len(pn, acked) else { continue };
                let truncated = pn & ((1u64 << (8 * n)) - 1);
                // the peer has received up to a packet number between the acknowledged one and this one
                for largest in [acked, pn.checked_sub(1), pn.checked_sub(behind / 2)] {
                    assert_eq!(decode_packet_number(largest, truncated, n), pn, "pn {pn} acked {acked:?} largest {largest:?} in {n} bytes");
                }
            }
        }
    }
}
