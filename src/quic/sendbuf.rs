//! What a QUIC endpoint has to send on one stream (or on the crypto stream of one encryption level), kept until it is
//! acknowledged: the bytes written, which of them have been sent, which are lost and wait to be sent again, which are acknowledged
//! and can be forgotten.
//!
//! A frame carries a range of the stream. The buffer says what range the next frame is to carry ([`SendBuf::next_chunk`]: lost
//! data before new data, no more than the room and the flow control credit allow) and is told what became of each one it gave out
//! ([`SendBuf::on_acked`], [`SendBuf::on_lost`]). The end of the stream (FIN) is counted as one more position after the last byte,
//! so that it is sent, lost, resent and acknowledged like a byte, and a frame with FIN and no data is no special case.

use super::rangeset::RangeSet;
use std::collections::VecDeque;
use std::ops::Range;

/// A range of the stream to put in a frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chunk {
    pub offset: u64,
    /// How many bytes of data (which [`SendBuf::copy`] gives).
    pub len: usize,
    /// The frame ends the stream.
    pub fin: bool,
    /// How many of the bytes were never sent before (what counts against flow control, which does not count a resend).
    pub new: u64,
}

#[derive(Clone, Default, Debug)]
pub struct SendBuf {
    /// The bytes from `base` on.
    data: VecDeque<u8>,
    /// The offset of `data[0]`: everything below it is acknowledged.
    base: u64,
    /// No more data will be written; the position after the last byte is the end of the stream.
    fin: bool,
    /// The first position never sent.
    next: u64,
    /// Positions at `base` and above that are acknowledged.
    acked: RangeSet,
    /// Positions that were sent, were lost, and have not been sent again or acknowledged since.
    lost: RangeSet,
}

impl SendBuf {
    pub fn new() -> SendBuf {
        SendBuf::default()
    }

    /// The offset after the last byte written: how many bytes the stream has so far.
    pub fn written(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    /// One more than `written` once the end is set: the position after the last that there is to send.
    fn end(&self) -> u64 {
        self.written() + u64::from(self.fin)
    }

    /// How many bytes are held (written and not yet forgotten): what a sender that limits its buffer looks at.
    pub fn buffered(&self) -> usize {
        self.data.len()
    }

    pub fn is_finished(&self) -> bool {
        self.fin
    }

    /// Appends data. Panics after [`finish`](SendBuf::finish).
    pub fn write(&mut self, data: &[u8]) {
        assert!(!self.fin, "data written after the end of the stream");
        self.data.extend(data);
    }

    /// Ends the stream after what has been written.
    pub fn finish(&mut self) {
        self.fin = true;
    }

    /// Whether there is anything to put in a frame: lost data, or data (or the end) never sent.
    pub fn has_pending(&self) -> bool {
        !self.lost.is_empty() || self.next < self.end()
    }

    /// Whether there is anything that [`next_chunk`](SendBuf::next_chunk) could give for new data up to `limit` (as the flow control
    /// allows): lost data, or new data below the limit, or the end if all of the data has been sent.
    pub fn has_pending_within(&self, limit: u64) -> bool {
        !self.lost.is_empty() || self.next < self.written().min(limit) || (self.fin && self.next == self.written())
    }

    /// Everything is acknowledged, the end too: nothing more will be sent.
    pub fn is_fully_acked(&self) -> bool {
        self.fin && self.base == self.written() && self.acked.contains(self.written())
    }

    /// The offset of the first byte or of the end that the next chunk will carry.
    pub fn next_offset(&self) -> Option<u64> {
        if let Some(l) = self.lost.min() {
            return Some(l);
        }
        (self.next < self.end()).then_some(self.next)
    }

    /// The offset after the last byte sent for the first time (the end of the stream, if all of it has been sent): what flow control
    /// counts against the peer's limit.
    pub fn sent(&self) -> u64 {
        self.next.min(self.written())
    }

    /// How many bytes of data the next chunk would have if `max_len` did not limit it (new data goes no further than `limit`, as in
    /// [`next_chunk`](SendBuf::next_chunk)): 0 if it is only the end of the stream, or if there is nothing.
    pub fn peek_len(&self, limit: u64) -> usize {
        let written = self.written();
        if let Some(r) = self.lost.first() {
            return if r.start < written { (r.end.min(written) - r.start) as usize } else { 0 };
        }
        written.min(limit).saturating_sub(self.next) as usize
    }

    /// Chooses what the next frame carries, at most `max_len` bytes of data, and counts it as sent. Lost data goes first, the
    /// lowest first; new data after, up to the offset `limit` (flow control: no new byte at `limit` or above is sent, though a
    /// resend is, and so is the end of the stream when its offset is the limit).
    pub fn next_chunk(&mut self, max_len: usize, limit: u64) -> Option<Chunk> {
        if let Some(first) = self.lost.min() {
            let written = self.written();
            let mut end_of_data = first.min(written);
            let len = if first < written {
                let (s, e) = self.lost.first().map(|r| (r.start, r.end)).expect("a lost range");
                end_of_data = e.min(written).min(s + max_len as u64);
                (end_of_data - s) as usize
            } else {
                0
            };
            let mut fin = false;
            if self.fin && end_of_data == written && self.lost.contains(written) {
                fin = true;
                self.lost.remove(written..written + 1);
            }
            if len == 0 && !fin {
                return None;
            }
            self.lost.remove(first..first + len as u64);
            return Some(Chunk { offset: first, len, fin, new: 0 });
        }
        let written = self.written();
        let offset = self.next;
        let room = written.min(limit).saturating_sub(offset);
        let len = room.min(max_len as u64);
        let fin = self.fin && offset + len == written;
        if len == 0 && !fin {
            return None;
        }
        self.next = offset + len + u64::from(fin);
        Some(Chunk { offset, len: len as usize, fin, new: len })
    }

    /// Appends the `len` bytes at `offset` to `out` (for a chunk that was given out and is not acknowledged).
    pub fn copy(&self, offset: u64, len: usize, out: &mut Vec<u8>) {
        if len == 0 {
            return;
        }
        assert!(offset >= self.base && offset + len as u64 <= self.written(), "copying what is not held");
        let from = (offset - self.base) as usize;
        let (a, b) = self.data.as_slices();
        if from < a.len() {
            let take = len.min(a.len() - from);
            out.extend_from_slice(&a[from..from + take]);
            out.extend_from_slice(&b[..len - take]);
        } else {
            out.extend_from_slice(&b[from - a.len()..from - a.len() + len]);
        }
    }

    /// A frame with this range arrived at the peer.
    pub fn on_acked(&mut self, offset: u64, len: usize, fin: bool) {
        // (a range that is acknowledged again, in the frame of a resend that was not needed after all, may be below what is forgotten)
        let r = offset.max(self.base)..offset + len as u64 + u64::from(fin);
        if r.start >= r.end {
            return;
        }
        self.lost.remove(r.clone());
        self.acked.insert(r);
        // forget what is acknowledged from the bottom
        if let Some(first) = self.acked.first() {
            if first.start <= self.base {
                let new_base = first.end.min(self.written());
                let drop = (new_base - self.base) as usize;
                self.data.drain(..drop);
                self.base = new_base;
                self.acked.remove_below(self.base);
                // (the end of the stream, if acknowledged, stays in `acked`, above `written`)
            }
        }
        // nothing that is below the base needs to be sent again
        self.lost.remove_below(self.base);
    }

    /// A frame with this range was lost: send it again unless it was acknowledged in another frame in the meantime.
    pub fn on_lost(&mut self, offset: u64, len: usize, fin: bool) {
        let r = offset.max(self.base)..(offset + len as u64 + u64::from(fin)).min(self.next);
        if r.start >= r.end {
            return;
        }
        self.lost.insert(r.clone());
        for a in self.acked.within(r) {
            self.lost.remove(a);
        }
    }

    /// Everything sent and not acknowledged is lost (the connection starts over: after a Retry).
    pub fn mark_all_lost(&mut self) {
        self.on_lost(self.base, (self.next - self.base) as usize, false);
    }

    /// Drops everything: nothing more is to be sent (the stream was reset, or its encryption level is discarded).
    pub fn clear(&mut self) {
        *self = SendBuf { base: self.written(), next: self.written(), ..SendBuf::default() };
    }

    /// The offset of the first byte not acknowledged in sequence: where the buffer starts.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The ranges (of positions) that are waiting to be sent again.
    pub fn lost_ranges(&self) -> Vec<Range<u64>> {
        self.lost.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::reassembly::Reassembler;
    use super::*;

    fn pattern(n: u64) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

    fn chunk(b: &mut SendBuf, max: usize, limit: u64) -> Option<(u64, Vec<u8>, bool, u64)> {
        let c = b.next_chunk(max, limit)?;
        let mut v = Vec::new();
        b.copy(c.offset, c.len, &mut v);
        Some((c.offset, v, c.fin, c.new))
    }

    #[test]
    fn new_data_goes_out_in_order_in_pieces() {
        let mut b = SendBuf::new();
        b.write(&pattern(25));
        assert_eq!(chunk(&mut b, 10, u64::MAX), Some((0, pattern(25)[..10].to_vec(), false, 10)));
        assert_eq!(chunk(&mut b, 10, u64::MAX), Some((10, pattern(25)[10..20].to_vec(), false, 10)));
        assert_eq!(chunk(&mut b, 10, u64::MAX), Some((20, pattern(25)[20..].to_vec(), false, 5)));
        assert_eq!(chunk(&mut b, 10, u64::MAX), None);
        assert!(!b.has_pending());
        b.write(&pattern(3));
        assert!(b.has_pending());
        assert_eq!(chunk(&mut b, 10, u64::MAX), Some((25, pattern(3), false, 3)));
    }

    #[test]
    fn the_end_of_the_stream_goes_with_the_last_data_or_alone() {
        let mut b = SendBuf::new();
        b.write(&pattern(5));
        b.finish();
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((0, pattern(5), true, 5)));
        assert_eq!(chunk(&mut b, 100, u64::MAX), None);
        // a stream that ends with the data all sent
        let mut b = SendBuf::new();
        b.write(&pattern(5));
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((0, pattern(5), false, 5)));
        b.finish();
        assert!(b.has_pending());
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((5, vec![], true, 0)));
        assert!(!b.has_pending());
        // an empty stream
        let mut b = SendBuf::new();
        b.finish();
        assert_eq!(chunk(&mut b, 0, 0), Some((0, vec![], true, 0)));
    }

    #[test]
    fn the_end_waits_for_the_data_when_the_room_is_short() {
        let mut b = SendBuf::new();
        b.write(&pattern(10));
        b.finish();
        assert_eq!(chunk(&mut b, 4, u64::MAX), Some((0, pattern(10)[..4].to_vec(), false, 4)));
        assert_eq!(chunk(&mut b, 6, u64::MAX), Some((4, pattern(10)[4..].to_vec(), true, 6)));
    }

    #[test]
    fn new_data_stops_at_the_flow_control_limit_but_the_end_does_not() {
        let mut b = SendBuf::new();
        b.write(&pattern(10));
        assert_eq!(chunk(&mut b, 100, 6), Some((0, pattern(10)[..6].to_vec(), false, 6)));
        assert_eq!(chunk(&mut b, 100, 6), None);
        assert!(!b.has_pending_within(6));
        assert!(b.has_pending());
        assert!(b.has_pending_within(7));
        assert_eq!(chunk(&mut b, 100, 8), Some((6, pattern(10)[6..8].to_vec(), false, 2)));
        // the limit is the length of the stream: the end goes
        b.finish();
        assert_eq!(chunk(&mut b, 100, 10), Some((8, pattern(10)[8..].to_vec(), true, 2)));
        let mut b = SendBuf::new();
        b.write(&pattern(4));
        b.finish();
        assert_eq!(chunk(&mut b, 100, 4), Some((0, pattern(4), true, 4)));
    }

    #[test]
    fn lost_data_goes_again_before_new_data_and_is_not_new() {
        let mut b = SendBuf::new();
        b.write(&pattern(30));
        for _ in 0..3 {
            chunk(&mut b, 10, u64::MAX).unwrap();
        }
        b.write(&pattern(10));
        b.on_lost(10, 10, false);
        b.on_lost(0, 5, false);
        assert_eq!(b.next_offset(), Some(0));
        assert_eq!(chunk(&mut b, 3, u64::MAX), Some((0, pattern(30)[..3].to_vec(), false, 0)));
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((3, pattern(30)[3..5].to_vec(), false, 0)));
        assert_eq!(chunk(&mut b, 100, 0), Some((10, pattern(30)[10..20].to_vec(), false, 0)), "a resend needs no credit");
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((30, pattern(10), false, 10)));
    }

    #[test]
    fn what_was_acknowledged_in_the_meantime_is_not_sent_again() {
        let mut b = SendBuf::new();
        b.write(&pattern(30));
        for _ in 0..3 {
            chunk(&mut b, 10, u64::MAX).unwrap();
        }
        b.on_acked(10, 10, false);
        b.on_lost(0, 30, false);
        assert_eq!(b.lost_ranges(), vec![0..10, 20..30]);
        // acknowledged after it was declared lost (the loss was not one)
        b.on_acked(0, 10, false);
        assert_eq!(b.lost_ranges(), vec![20..30]);
        assert_eq!(b.base(), 20, "what is acknowledged from the start is forgotten");
        assert_eq!(b.buffered(), 10);
        b.on_acked(20, 10, false);
        assert!(b.lost_ranges().is_empty());
        assert_eq!((b.base(), b.buffered()), (30, 0));
    }

    #[test]
    fn a_lost_end_is_sent_again_alone_or_with_the_data() {
        let mut b = SendBuf::new();
        b.write(&pattern(10));
        b.finish();
        let c = b.next_chunk(100, u64::MAX).unwrap();
        assert!(c.fin);
        b.on_lost(c.offset, c.len, c.fin);
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((0, pattern(10), true, 0)));
        // the data was acknowledged, only the end was lost
        b.on_lost(0, 10, true);
        b.on_acked(0, 10, false);
        assert_eq!(b.lost_ranges(), vec![10..11]);
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((10, vec![], true, 0)));
        assert!(!b.is_fully_acked());
        b.on_acked(10, 0, true);
        assert!(b.is_fully_acked());
        assert!(!b.has_pending());
    }

    #[test]
    fn the_end_is_lost_but_the_room_only_fits_some_of_the_data() {
        let mut b = SendBuf::new();
        b.write(&pattern(10));
        b.finish();
        b.next_chunk(100, u64::MAX).unwrap();
        b.on_lost(0, 10, true);
        assert_eq!(chunk(&mut b, 4, u64::MAX), Some((0, pattern(10)[..4].to_vec(), false, 0)));
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((4, pattern(10)[4..].to_vec(), true, 0)));
    }

    #[test]
    fn everything_unacknowledged_can_be_made_lost_at_once() {
        let mut b = SendBuf::new();
        b.write(&pattern(30));
        b.finish();
        b.next_chunk(20, u64::MAX).unwrap();
        b.on_acked(5, 5, false);
        b.mark_all_lost();
        assert_eq!(b.lost_ranges(), vec![0..5, 10..20]);
        assert_eq!(chunk(&mut b, 100, u64::MAX), Some((0, pattern(30)[..5].to_vec(), false, 0)));
    }

    #[test]
    fn copy_reads_across_the_wrap_of_the_buffer() {
        // the ring wraps when the front is forgotten and more is written: try every size of what is forgotten
        for forgotten in 0..120u64 {
            let mut b = SendBuf::new();
            b.write(&pattern(120));
            let c = b.next_chunk(forgotten as usize, u64::MAX);
            if let Some(c) = c {
                b.on_acked(c.offset, c.len, c.fin);
            }
            b.write(&pattern(240)[120..]);
            assert_eq!(b.written(), 240);
            for (from, len) in [(forgotten, 240 - forgotten), (forgotten, 1), (200, 40), (119, 2), (120, 1)] {
                if from < b.base() || from + len > 240 || len == 0 {
                    continue;
                }
                let mut v = Vec::new();
                b.copy(from, len as usize, &mut v);
                assert_eq!(v, pattern(240)[from as usize..(from + len) as usize], "forgotten {forgotten} from {from} len {len}");
            }
        }
    }

    /// The sender and a network that loses, reorders and delays frames, and a receiver: whatever happens, the stream is read
    /// complete, with the end where it is, once everything is acknowledged.
    #[test]
    fn it_delivers_the_stream_through_a_lossy_network() {
        let mut seed = 0xdeadbeefcafef00du64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..200 {
            let total = next(3000);
            let finish_early = next(2) == 0;
            let mut b = SendBuf::new();
            let mut rx = Reassembler::new();
            let mut fin_seen: Option<u64> = None;
            let mut out = Vec::new();
            let mut written = 0u64;
            let mut in_flight: Vec<Chunk> = Vec::new();
            let mut limit = 200 + next(500);
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 100_000, "round {round}: no progress");
                // the application writes some, and ends the stream when all is written
                if written < total && next(3) == 0 {
                    let n = (1 + next(300)).min(total - written);
                    b.write(&pattern(total)[written as usize..(written + n) as usize]);
                    written += n;
                }
                if written == total && !b.is_finished() && (finish_early || next(4) == 0) {
                    b.finish();
                }
                // the receiver gives credit as it reads
                if next(4) == 0 {
                    limit += next(400);
                }
                // send
                if next(2) == 0 {
                    if let Some(c) = b.next_chunk(1 + next(200) as usize, limit) {
                        assert!(c.offset + c.len as u64 <= limit || c.new == 0, "round {round}: new data past the limit");
                        in_flight.push(c);
                    }
                }
                // the network takes one: delivers it (and its ack) or loses it (and the sender finds out)
                if !in_flight.is_empty() && next(2) == 0 {
                    let i = next(in_flight.len() as u64) as usize;
                    let c = in_flight.swap_remove(i);
                    match next(4) {
                        0 => b.on_lost(c.offset, c.len, c.fin),
                        1 => {
                            // delivered, but the sender thinks it lost it and finds out later it was not
                            deliver(&b, &mut rx, &mut fin_seen, &c);
                            b.on_lost(c.offset, c.len, c.fin);
                            b.on_acked(c.offset, c.len, c.fin);
                        }
                        _ => {
                            deliver(&b, &mut rx, &mut fin_seen, &c);
                            b.on_acked(c.offset, c.len, c.fin);
                        }
                    }
                    out.extend(rx.take());
                }
                if b.is_fully_acked() {
                    break;
                }
                // a sender that has nothing in flight and no pending data would wait for a timer: model it as the loss of
                // whatever was sent and is not acknowledged
                if in_flight.is_empty() && !b.has_pending_within(limit) && next(5) == 0 {
                    b.mark_all_lost();
                }
            }
            out.extend(rx.take());
            assert_eq!(out, pattern(total), "round {round}");
            assert_eq!(fin_seen, Some(total), "round {round}");
        }
    }

    #[test]
    fn what_has_been_sent_and_how_much_the_next_chunk_could_hold() {
        let mut b = SendBuf::new();
        assert_eq!((b.sent(), b.peek_len(100)), (0, 0));
        b.write(&pattern(100));
        assert_eq!(b.peek_len(u64::MAX), 100);
        assert_eq!(b.peek_len(40), 40, "flow control limits new data");
        assert_eq!(b.peek_len(0), 0);
        let c = b.next_chunk(30, u64::MAX).unwrap();
        assert_eq!((c.offset, c.len, b.sent()), (0, 30, 30));
        assert_eq!(b.peek_len(u64::MAX), 70);
        assert_eq!(b.peek_len(50), 20);
        // lost data comes first, whole range, whatever the limit
        let c2 = b.next_chunk(20, u64::MAX).unwrap();
        b.on_lost(c.offset, c.len, false);
        assert_eq!(b.peek_len(0), 30);
        assert_eq!(b.sent(), 50, "a resend is not new");
        let r = b.next_chunk(10, u64::MAX).unwrap();
        assert_eq!((r.offset, r.len, r.new), (0, 10, 0));
        assert_eq!(b.peek_len(0), 20);
        let _ = c2;
        // the end of the stream on its own is no data
        let mut e = SendBuf::new();
        e.write(&pattern(5));
        e.finish();
        let c = e.next_chunk(5, u64::MAX).unwrap();
        assert!(c.fin);
        assert_eq!((e.sent(), e.peek_len(u64::MAX)), (5, 0), "the end counts for no byte of flow control");
        e.on_lost(c.offset, c.len, true);
        assert_eq!(e.peek_len(0), 5);
    }

    #[test]
    fn a_range_that_is_acknowledged_twice_changes_nothing_the_second_time() {
        let mut b = SendBuf::new();
        b.write(&pattern(3000));
        b.finish();
        let a = b.next_chunk(1000, u64::MAX).unwrap();
        let c = b.next_chunk(1000, u64::MAX).unwrap();
        let d = b.next_chunk(1000, u64::MAX).unwrap();
        assert!(d.fin);
        // the first is thought lost, and sent again, and both copies arrive
        b.on_lost(a.offset, a.len, false);
        let a2 = b.next_chunk(1000, u64::MAX).unwrap();
        assert_eq!((a2.offset, a2.len), (0, 1000));
        b.on_acked(a2.offset, a2.len, false);
        b.on_acked(c.offset, c.len, false);
        assert_eq!(b.base(), 2000);
        // the first copy is acknowledged after the data is forgotten, wholly below what is held and partly
        b.on_acked(a.offset, a.len, false);
        b.on_acked(1500, 1000, false);
        assert_eq!((b.base(), b.buffered()), (2500, 500));
        b.on_acked(d.offset, d.len, true);
        assert!(b.is_fully_acked());
        b.on_acked(0, 3000, true);
        assert!(b.is_fully_acked() && !b.has_pending());
    }

    fn deliver(b: &SendBuf, rx: &mut Reassembler, fin_seen: &mut Option<u64>, c: &Chunk) {
        let mut v = Vec::new();
        // (a copy of data that the sender has already forgotten is the receiver's to have had: use the pattern)
        if c.offset >= b.base() {
            b.copy(c.offset, c.len, &mut v);
        } else {
            v = pattern(c.offset + c.len as u64)[c.offset as usize..].to_vec();
        }
        rx.insert(c.offset, &v, u64::MAX / 2).unwrap();
        if c.fin {
            let end = c.offset + c.len as u64;
            assert!(fin_seen.map_or(true, |f| f == end));
            *fin_seen = Some(end);
        }
    }
}
