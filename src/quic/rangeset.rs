//! A set of numbers kept as ranges: the packet numbers received (which an ACK frame says), and the parts of a stream that are
//! acknowledged or lost. Numbers go in and out one at a time or by range; what is kept is as few ranges as there can be (two
//! ranges that touch are one), in order.

use std::collections::BTreeMap;
use std::ops::Range;

/// A set of `u64` as the fewest ranges (`start..end`, `end` not in the set) that hold it.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct RangeSet {
    /// start -> end, with a number that is in none of them between one range and the next (they do not touch).
    ranges: BTreeMap<u64, u64>,
}

impl RangeSet {
    pub fn new() -> RangeSet {
        RangeSet::default()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// How many ranges there are.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// How many numbers are in the set.
    pub fn count(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }

    /// The smallest number in the set.
    pub fn min(&self) -> Option<u64> {
        self.ranges.keys().next().copied()
    }

    /// The largest number in the set.
    pub fn max(&self) -> Option<u64> {
        self.ranges.values().next_back().map(|e| e - 1)
    }

    /// The lowest range.
    pub fn first(&self) -> Option<Range<u64>> {
        self.ranges.iter().next().map(|(&s, &e)| s..e)
    }

    /// The ranges from the lowest up.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Range<u64>> + '_ {
        self.ranges.iter().map(|(&s, &e)| s..e)
    }

    /// The range that holds `v`, if there is one.
    fn containing(&self, v: u64) -> Option<(u64, u64)> {
        self.ranges.range(..=v).next_back().filter(|(_, &e)| v < e).map(|(&s, &e)| (s, e))
    }

    pub fn contains(&self, v: u64) -> bool {
        self.containing(v).is_some()
    }

    /// Whether every number of `r` is in the set (an empty range is).
    pub fn covers(&self, r: Range<u64>) -> bool {
        r.start >= r.end || self.containing(r.start).is_some_and(|(_, e)| r.end <= e)
    }

    /// Whether any number of `r` is in the set.
    pub fn intersects(&self, r: Range<u64>) -> bool {
        if r.start >= r.end {
            return false;
        }
        if self.containing(r.start).is_some() {
            return true;
        }
        self.ranges.range(r.start..r.end).next().is_some()
    }

    /// The parts of the ranges that lie within `r`, from the lowest up.
    pub fn within(&self, r: Range<u64>) -> Vec<Range<u64>> {
        if r.start >= r.end {
            return Vec::new();
        }
        let first = self.containing(r.start).map(|(s, _)| s).unwrap_or(r.start);
        self.ranges
            .range(first..r.end)
            .map(|(&s, &e)| s.max(r.start)..e.min(r.end))
            .filter(|x| x.start < x.end)
            .collect()
    }

    /// Puts `r` in. Returns whether the set grew.
    pub fn insert(&mut self, r: Range<u64>) -> bool {
        if r.start >= r.end {
            return false;
        }
        if self.covers(r.clone()) {
            return false;
        }
        let (mut start, mut end) = (r.start, r.end);
        // a range that ends where this one begins, or reaches into it
        if let Some((s, e)) = self.ranges.range(..=start).next_back().map(|(&s, &e)| (s, e)) {
            if e >= start {
                start = s;
                end = end.max(e);
                self.ranges.remove(&s);
            }
        }
        // the ranges that begin inside this one or where it ends
        loop {
            let Some((s, e)) = self.ranges.range(start..=end).next().map(|(&s, &e)| (s, e)) else { break };
            end = end.max(e);
            self.ranges.remove(&s);
        }
        self.ranges.insert(start, end);
        true
    }

    /// Puts `v` in. Returns whether it was not there.
    pub fn insert_one(&mut self, v: u64) -> bool {
        self.insert(v..v + 1)
    }

    /// Takes `r` out.
    pub fn remove(&mut self, r: Range<u64>) {
        if r.start >= r.end {
            return;
        }
        let touching: Vec<(u64, u64)> =
            self.ranges.range(..r.end).rev().take_while(|(_, &e)| e > r.start).map(|(&s, &e)| (s, e)).collect();
        for (s, e) in touching {
            self.ranges.remove(&s);
            if s < r.start {
                self.ranges.insert(s, r.start);
            }
            if e > r.end {
                self.ranges.insert(r.end, e);
            }
        }
    }

    /// Takes out everything below `v`.
    pub fn remove_below(&mut self, v: u64) {
        self.remove(0..v);
    }

    /// Takes the lowest numbers out, up to `max` of them: `Some(range)` of what was taken, which is the start of the lowest range
    /// and no more than `max` long, or None if the set is empty (or `max` is 0).
    pub fn pop_first(&mut self, max: u64) -> Option<Range<u64>> {
        if max == 0 {
            return None;
        }
        let (&s, &e) = self.ranges.iter().next()?;
        let end = e.min(s.saturating_add(max));
        self.ranges.remove(&s);
        if end < e {
            self.ranges.insert(end, e);
        }
        Some(s..end)
    }

    /// Keeps only the `n` highest ranges (the lowest are dropped: what an ACK frame that is limited in size is to say).
    pub fn keep_highest(&mut self, n: usize) {
        while self.ranges.len() > n {
            let first = *self.ranges.keys().next().expect("more than n ranges");
            self.ranges.remove(&first);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn numbers_that_touch_become_one_range() {
        let mut s = RangeSet::new();
        assert!(s.insert_one(5));
        assert!(s.insert_one(7));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![5..6, 7..8]);
        assert!(s.insert_one(6));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![5..8]);
        assert!(!s.insert_one(6));
        assert!(s.insert_one(4));
        assert!(s.insert_one(8));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![4..9]);
        assert_eq!((s.min(), s.max(), s.count(), s.range_count()), (Some(4), Some(8), 5, 1));
    }

    #[test]
    fn a_range_that_spans_several_takes_them_in() {
        let mut s = RangeSet::new();
        for r in [2..4, 6..8, 10..12, 20..22] {
            s.insert(r);
        }
        assert!(s.insert(3..11));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![2..12, 20..22]);
        assert!(!s.insert(5..9)); // inside
        assert!(!s.insert(5..5)); // empty
        assert!(s.insert(12..20));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![2..22]);
    }

    #[test]
    fn removing_cuts_a_range_in_two_or_takes_it_away() {
        let mut s = RangeSet::new();
        s.insert(0..10);
        s.remove(3..5);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![0..3, 5..10]);
        s.remove(2..6);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![0..2, 6..10]);
        s.remove(0..2);
        s.remove(9..100);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![6..9]);
        s.remove(0..6);
        s.remove(7..7);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![6..9]);
        s.remove_below(8);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![8..9]);
        s.remove(8..9);
        assert!(s.is_empty());
        assert_eq!((s.min(), s.max()), (None, None));
    }

    #[test]
    fn the_questions() {
        let mut s = RangeSet::new();
        s.insert(10..20);
        s.insert(30..40);
        assert!(s.contains(10) && s.contains(19) && !s.contains(20) && !s.contains(9) && s.contains(30));
        assert!(s.covers(12..18) && s.covers(10..20) && !s.covers(10..21) && !s.covers(15..35) && s.covers(25..25));
        assert!(s.intersects(0..11) && s.intersects(19..31) && !s.intersects(20..30) && !s.intersects(0..10) && !s.intersects(40..50));
        assert!(s.intersects(15..16) && s.intersects(0..100) && !s.intersects(5..5));
    }

    #[test]
    fn within_cuts_the_ranges_to_a_window() {
        let mut s = RangeSet::new();
        s.insert(10..20);
        s.insert(30..40);
        s.insert(50..60);
        assert_eq!(s.within(15..55), vec![15..20, 30..40, 50..55]);
        assert_eq!(s.within(0..10), Vec::<Range<u64>>::new());
        assert_eq!(s.within(12..14), vec![12..14]);
        assert_eq!(s.within(20..30), Vec::<Range<u64>>::new());
        assert_eq!(s.within(35..35), Vec::<Range<u64>>::new());
    }

    #[test]
    fn pop_first_takes_from_the_bottom() {
        let mut s = RangeSet::new();
        s.insert(10..20);
        s.insert(30..32);
        assert_eq!(s.pop_first(4), Some(10..14));
        assert_eq!(s.pop_first(100), Some(14..20));
        assert_eq!(s.pop_first(0), None);
        assert_eq!(s.pop_first(1), Some(30..31));
        assert_eq!(s.pop_first(1), Some(31..32));
        assert_eq!(s.pop_first(1), None);
        s.insert(0..u64::MAX);
        assert_eq!(s.pop_first(u64::MAX), Some(0..u64::MAX));
    }

    #[test]
    fn keep_highest_drops_the_lowest_ranges() {
        let mut s = RangeSet::new();
        for i in 0..10 {
            s.insert(i * 10..i * 10 + 5);
        }
        s.keep_highest(3);
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![70..75, 80..85, 90..95]);
        s.keep_highest(5);
        assert_eq!(s.range_count(), 3);
        s.keep_highest(0);
        assert!(s.is_empty());
    }

    #[test]
    fn it_does_what_a_set_of_numbers_does() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..400 {
            let mut s = RangeSet::new();
            let mut model = BTreeSet::new();
            for step in 0..60 {
                let a = next(80);
                let len = next(12);
                let r = a..a + len;
                match next(6) {
                    0 | 1 | 2 => {
                        let grew = s.insert(r.clone());
                        let had = r.clone().all(|v| model.contains(&v));
                        model.extend(r.clone());
                        assert_eq!(grew, !had && len > 0, "round {round} step {step}");
                    }
                    3 => {
                        s.remove(r.clone());
                        for v in r.clone() {
                            model.remove(&v);
                        }
                    }
                    4 => {
                        let max = next(10);
                        let got = s.pop_first(max);
                        let first = model.iter().next().copied();
                        match (got, first) {
                            (None, f) => assert!(max == 0 || f.is_none(), "round {round} step {step}"),
                            (Some(g), Some(f)) => {
                                assert_eq!(g.start, f);
                                assert!(g.end - g.start <= max);
                                for v in g {
                                    assert!(model.remove(&v));
                                }
                            }
                            (Some(_), None) => panic!("popped from an empty set"),
                        }
                    }
                    _ => {
                        let v = next(100);
                        s.remove_below(v);
                        model.retain(|&m| m >= v);
                    }
                }
                // the same numbers, as the fewest ranges
                let from_set: Vec<u64> = s.iter().flatten().collect();
                let from_model: Vec<u64> = model.iter().copied().collect();
                assert_eq!(from_set, from_model, "round {round} step {step}");
                let ranges: Vec<_> = s.iter().collect();
                for w in ranges.windows(2) {
                    assert!(w[0].end < w[1].start, "ranges touch or are out of order: {ranges:?}");
                }
                assert!(ranges.iter().all(|r| r.start < r.end));
                assert_eq!(s.count(), model.len() as u64);
                assert_eq!(s.min(), model.iter().next().copied());
                assert_eq!(s.max(), model.iter().next_back().copied());
                let probe = next(100);
                assert_eq!(s.contains(probe), model.contains(&probe));
                let q = probe..probe + next(8);
                assert_eq!(s.covers(q.clone()), q.clone().all(|v| model.contains(&v)));
                assert_eq!(s.intersects(q.clone()), q.clone().any(|v| model.contains(&v)));
                let within: Vec<u64> = s.within(q.clone()).into_iter().flatten().collect();
                assert_eq!(within, q.clone().filter(|v| model.contains(v)).collect::<Vec<_>>());
            }
        }
    }
}
