//! Congestion control and pacing (RFC 9002 section 7): how many bytes may be in flight, and when the next packet may go.
//!
//! [`NewReno`] is the controller RFC 9002 describes: slow start until the first loss, then a halving of the window at each
//! congestion event (one per round trip of losses) and growth of one packet per window of acknowledgments. A controller is told
//! what happens to packets ([`on_sent`](NewReno::on_sent), [`on_acked`](NewReno::on_acked), [`on_lost`](NewReno::on_lost)) and says how
//! much may be sent ([`available`](NewReno::available)); it does not look at a clock, the callers give it the time.
//! [`Pacer`] spreads the packets that the window allows over the round trip instead of sending them back to back.

use std::time::{Duration, Instant};

/// The congestion window in bytes that a connection starts with (RFC 9002 section 7.2): ten packets, but not more than 14720
/// bytes and not fewer than two packets.
pub fn initial_window(max_datagram_size: usize) -> usize {
    (10 * max_datagram_size).min((2 * max_datagram_size).max(14720))
}

/// The smallest congestion window: two packets.
pub fn minimum_window(max_datagram_size: usize) -> usize {
    2 * max_datagram_size
}

/// A window with room for no more than this many packets more is in use.
const LIMITED_BY_PACKETS: usize = 3;

/// The window is cut to this fraction when a congestion event is detected: 1/2.
const LOSS_REDUCTION_NUM: usize = 1;
const LOSS_REDUCTION_DEN: usize = 2;

#[derive(Clone, Debug)]
pub struct NewReno {
    max_datagram_size: usize,
    window: usize,
    ssthresh: usize,
    in_flight: usize,
    /// When the present recovery period began: packets sent up to then do not make another congestion event, or grow the window.
    recovery_start: Option<Instant>,
    /// What was acknowledged in congestion avoidance that has not yet added up to a window.
    acked_in_avoidance: usize,
}

impl NewReno {
    pub fn new(max_datagram_size: usize) -> NewReno {
        NewReno {
            max_datagram_size,
            window: initial_window(max_datagram_size),
            ssthresh: usize::MAX,
            in_flight: 0,
            recovery_start: None,
            acked_in_avoidance: 0,
        }
    }

    pub fn window(&self) -> usize {
        self.window
    }

    pub fn ssthresh(&self) -> usize {
        self.ssthresh
    }

    pub fn bytes_in_flight(&self) -> usize {
        self.in_flight
    }

    pub fn max_datagram_size(&self) -> usize {
        self.max_datagram_size
    }

    pub fn in_slow_start(&self) -> bool {
        self.window < self.ssthresh
    }

    /// How many bytes may be sent now: nothing once the window is full (a packet that is sent while there is room may take the
    /// window past its size by what is left of the packet).
    pub fn available(&self) -> usize {
        self.window.saturating_sub(self.in_flight)
    }

    /// Whether the window is full to the point that a packet cannot be sent.
    pub fn blocked(&self) -> bool {
        self.in_flight >= self.window
    }

    /// The path's datagram size changed (it never goes below 1200 bytes).
    pub fn set_max_datagram_size(&mut self, size: usize) {
        self.max_datagram_size = size;
        self.window = self.window.max(minimum_window(size));
    }

    /// A packet that counts toward the bytes in flight (it has an ack-eliciting or PADDING frame) was sent.
    pub fn on_sent(&mut self, bytes: usize) {
        self.in_flight += bytes;
    }

    /// Whether the window was in use when `in_flight` bytes were in flight: the sender is held back by it, or by little else. The
    /// window is not grown if it was not (RFC 9002 section 7.8), for a window that grows without being used lets a burst out that the
    /// network has not been shown to take. In slow start the window is in use if half of it is (it doubles every round trip).
    fn is_limited(&self, in_flight: usize) -> bool {
        if in_flight >= self.window {
            return true;
        }
        (self.in_slow_start() && in_flight > self.window / 2) || self.window - in_flight <= LIMITED_BY_PACKETS * self.max_datagram_size
    }

    fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|start| sent <= start)
    }

    /// A packet of `bytes` bytes that counted toward the bytes in flight and was sent at `sent` has been acknowledged. `in_flight_before`
    /// is how many bytes were in flight before the acknowledgment that this is part of took any off.
    pub fn on_acked(&mut self, bytes: usize, sent: Instant, in_flight_before: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        if !self.is_limited(in_flight_before) || self.in_recovery(sent) {
            return;
        }
        if self.in_slow_start() {
            self.window += bytes;
        } else {
            // a packet's worth of growth for each window of data acknowledged
            self.acked_in_avoidance += bytes;
            if self.acked_in_avoidance >= self.window {
                self.acked_in_avoidance -= self.window;
                self.window += self.max_datagram_size;
            }
        }
    }

    /// A packet that counted toward the bytes in flight was declared lost.
    pub fn on_lost(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    /// Packets that counted toward the bytes in flight are gone without being acknowledged or lost (their keys were discarded).
    pub fn on_discarded(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }

    /// Packets were lost (or an ECN mark was seen), the newest of them sent at `sent`: a congestion event, unless one began since
    /// `sent`, in which case this is a loss that was part of it. Returns whether the window was cut.
    pub fn on_congestion_event(&mut self, now: Instant, sent: Instant) -> bool {
        if self.in_recovery(sent) {
            return false;
        }
        self.recovery_start = Some(now);
        self.ssthresh = (self.window / LOSS_REDUCTION_DEN * LOSS_REDUCTION_NUM).max(minimum_window(self.max_datagram_size));
        self.window = self.ssthresh;
        self.acked_in_avoidance = 0;
        true
    }

    /// Everything sent over a long time was lost: the window goes to its minimum (RFC 9002 section 7.6).
    pub fn on_persistent_congestion(&mut self) {
        self.window = minimum_window(self.max_datagram_size);
        self.recovery_start = None;
        self.acked_in_avoidance = 0;
    }
}

/// Spreads packets over the round trip: a bucket of bytes that fills at the rate the window allows over a round trip, and from which
/// a packet takes its size. The bucket holds a burst of ten packets, as RFC 9002 section 7.7 allows ("limit bursts to the initial
/// congestion window"); it may go below empty by as much as a millisecond of sending, since a timer is no finer than that, and a
/// packet is not sent while it is below that.
#[derive(Clone, Debug)]
pub struct Pacer {
    /// Bytes that may be sent now, as of `last` (negative: bytes that were sent ahead of the rate).
    tokens: f64,
    last: Option<Instant>,
    max_datagram_size: usize,
}

/// How many packets the bucket holds.
const BURST_PACKETS: f64 = 10.0;

/// The finest delay between packets that a timer can be asked for, in seconds.
const GRANULARITY: f64 = 0.001;

impl Pacer {
    pub fn new(max_datagram_size: usize) -> Pacer {
        Pacer { tokens: BURST_PACKETS * max_datagram_size as f64, last: None, max_datagram_size }
    }

    pub fn set_max_datagram_size(&mut self, size: usize) {
        self.max_datagram_size = size;
    }

    /// The rate in bytes per second for a window of `window` bytes over a round trip of `rtt`: faster than the window per round
    /// trip, so that a round trip that is longer or a window that grows does not leave the window unused (twice as fast in slow
    /// start, where the window doubles each round trip, and a quarter more after it).
    pub fn rate(window: usize, rtt: Duration, slow_start: bool) -> f64 {
        let factor = if slow_start { 2.0 } else { 1.25 };
        factor * window as f64 / rtt.as_secs_f64().max(1e-6)
    }

    fn refill(&mut self, now: Instant, rate: f64) {
        if let Some(last) = self.last {
            let elapsed = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * rate).min(BURST_PACKETS * self.max_datagram_size as f64);
        }
        self.last = Some(now);
    }

    /// When the next packet may be sent: `None` is now.
    pub fn next_send_time(&mut self, now: Instant, rate: f64) -> Option<Instant> {
        self.refill(now, rate);
        let floor = -rate * GRANULARITY;
        if self.tokens >= floor {
            return None;
        }
        // (not so long that a rate gone wrong stops the connection)
        let wait = ((floor - self.tokens) / rate).clamp(0.000_001, 1.0);
        Some(now + Duration::from_secs_f64(wait))
    }

    /// A packet of `bytes` bytes was sent at `now`.
    pub fn on_sent(&mut self, now: Instant, bytes: usize, rate: f64) {
        self.refill(now, rate);
        self.tokens -= bytes as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDS: usize = 1200;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn the_initial_window_is_ten_packets_up_to_14720_bytes() {
        assert_eq!(initial_window(1200), 12000);
        assert_eq!(initial_window(1500), 14720);
        assert_eq!(initial_window(9000), 18000);
        assert_eq!(minimum_window(1200), 2400);
    }

    #[test]
    fn slow_start_grows_the_window_by_what_is_acknowledged() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(MDS);
        for _ in 0..10 {
            cc.on_sent(MDS);
        }
        assert_eq!((cc.window(), cc.bytes_in_flight(), cc.available(), cc.blocked()), (12000, 12000, 0, true));
        cc.on_acked(MDS, t0, 12000);
        assert_eq!((cc.window(), cc.bytes_in_flight()), (13200, 10800));
        assert!(cc.in_slow_start());
    }

    #[test]
    fn the_window_does_not_grow_if_it_is_not_in_use() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(MDS);
        cc.on_sent(MDS); // a tenth of the window
        cc.on_acked(MDS, t0, MDS);
        assert_eq!(cc.window(), 12000);
        // more than half of it, in slow start: in use
        for _ in 0..7 {
            cc.on_sent(MDS);
        }
        cc.on_acked(MDS, t0, 7 * MDS);
        assert_eq!(cc.window(), 13200);
        // in congestion avoidance only a window that is nearly full is
        cc.on_lost(MDS);
        cc.on_congestion_event(t0 + ms(1), t0);
        let w = cc.window();
        assert_eq!(w, 6600);
        let mut cc2 = cc.clone();
        cc2.on_acked(MDS, t0 + ms(2), w / 4);
        assert_eq!(cc2.acked_in_avoidance, 0, "a quarter full is not in use");
        cc2.on_acked(MDS, t0 + ms(2), w - 2 * MDS);
        assert_eq!(cc2.acked_in_avoidance, MDS, "room for two packets more is");
    }

    #[test]
    fn a_loss_halves_the_window_once_per_round_trip() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(MDS);
        for _ in 0..10 {
            cc.on_sent(MDS);
        }
        cc.on_lost(MDS);
        assert!(cc.on_congestion_event(t0 + ms(100), t0));
        assert_eq!((cc.window(), cc.ssthresh(), cc.in_slow_start()), (6000, 6000, false));
        // another packet sent before the recovery began is lost: the same event
        cc.on_lost(MDS);
        assert!(!cc.on_congestion_event(t0 + ms(110), t0 + ms(50)));
        assert_eq!(cc.window(), 6000);
        // a packet sent after it begins and lost is a new one
        cc.on_lost(MDS);
        assert!(cc.on_congestion_event(t0 + ms(300), t0 + ms(150)));
        assert_eq!(cc.window(), 3000);
        // never below two packets
        assert!(cc.on_congestion_event(t0 + ms(600), t0 + ms(400)));
        assert_eq!(cc.window(), 2400);
        assert!(cc.on_congestion_event(t0 + ms(900), t0 + ms(700)));
        assert_eq!(cc.window(), 2400);
    }

    #[test]
    fn what_was_sent_before_the_recovery_does_not_grow_the_window() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(MDS);
        for _ in 0..10 {
            cc.on_sent(MDS);
        }
        cc.on_lost(MDS);
        cc.on_congestion_event(t0 + ms(100), t0 + ms(50));
        let w = cc.window();
        cc.on_acked(MDS, t0 + ms(60), 12000); // sent before the recovery began
        assert_eq!(cc.window(), w);
    }

    #[test]
    fn congestion_avoidance_adds_a_packet_per_window_acknowledged() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(MDS);
        for _ in 0..10 {
            cc.on_sent(MDS);
        }
        cc.on_lost(MDS);
        cc.on_congestion_event(t0, t0 - ms(1));
        assert_eq!(cc.window(), 6000);
        // five packets fill the window; their acknowledgments add up to one packet of growth
        let mut cc2 = cc.clone();
        for _ in 0..5 {
            cc2.on_sent(MDS);
        }
        // (the in-flight bytes are nine packets from before, and five more: far past the window)
        for _ in 0..5 {
            cc2.on_acked(MDS, t0 + ms(10), 14400);
        }
        assert_eq!(cc2.window(), 6000 + MDS);
        // and not quicker than that
        for _ in 0..4 {
            cc2.on_sent(MDS);
            cc2.on_acked(MDS, t0 + ms(10), 14400);
        }
        assert_eq!(cc2.window(), 6000 + MDS, "four packets of 1200 are not a window of 7200");
    }

    #[test]
    fn persistent_congestion_goes_to_the_minimum_and_ends_recovery() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(MDS);
        cc.on_congestion_event(t0, t0 - ms(1));
        cc.on_persistent_congestion();
        assert_eq!(cc.window(), 2400);
        // slow start again? (ssthresh is what the congestion event set: 6000, so yes, until the window gets there)
        assert!(cc.in_slow_start());
        assert!(cc.on_congestion_event(t0 + ms(5), t0 + ms(1)), "recovery was ended");
    }

    #[test]
    fn discarded_packets_leave_the_bytes_in_flight() {
        let mut cc = NewReno::new(MDS);
        cc.on_sent(1200);
        cc.on_sent(800);
        cc.on_discarded(2000);
        assert_eq!(cc.bytes_in_flight(), 0);
        cc.on_discarded(5); // (never below zero)
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn the_pacer_lets_a_burst_go_and_then_spaces_the_packets() {
        let t0 = Instant::now();
        let mut p = Pacer::new(MDS);
        let rate = Pacer::rate(12000, ms(100), true); // 240000 bytes/s: a packet every 5 ms
        assert!((rate - 240_000.0).abs() < 1.0);
        // the bucket holds ten packets, and one more goes because it is less than a millisecond in debt when it is sent
        let mut burst = 0;
        while p.next_send_time(t0, rate).is_none() {
            p.on_sent(t0, MDS, rate);
            burst += 1;
            assert!(burst <= 12);
        }
        assert_eq!(burst, 11);
        let wait = p.next_send_time(t0, rate).expect("the bucket is empty");
        // 1200 bytes in debt, less a millisecond (240 bytes) of leeway, at 240 bytes a millisecond: 4 ms
        assert!((wait - t0).as_secs_f64() > 0.0039 && (wait - t0).as_secs_f64() < 0.0041, "{:?}", wait - t0);
        assert!(p.next_send_time(t0 + ms(3), rate).is_some());
        assert_eq!(p.next_send_time(t0 + ms(4), rate), None);
        p.on_sent(t0 + ms(4), MDS, rate);
        // the long-run rate is the rate: packets go every 5 ms
        let mut sent = 0;
        let mut now = t0 + ms(4);
        while now < t0 + ms(1004) {
            match p.next_send_time(now, rate) {
                None => {
                    p.on_sent(now, MDS, rate);
                    sent += 1;
                }
                Some(t) => now = t,
            }
        }
        // about 200 packets in a second (1000 / 5), give or take the burst of debt
        assert!((195..=205).contains(&sent), "sent {sent}");
        // idle for long: no more than the burst
        let mut n = 0;
        let later = now + ms(10_000);
        while p.next_send_time(later, rate).is_none() {
            p.on_sent(later, MDS, rate);
            n += 1;
            assert!(n <= 12);
        }
        assert_eq!(n, 11);
    }

    #[test]
    fn the_rate_is_faster_in_slow_start() {
        let a = Pacer::rate(12000, ms(100), true);
        let b = Pacer::rate(12000, ms(100), false);
        assert!(a > b && (b - 150_000.0).abs() < 1.0);
    }
}
