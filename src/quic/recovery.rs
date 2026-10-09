//! Loss detection (RFC 9002 sections 5 and 6): the round-trip time estimate, which sent packets are acknowledged and which are
//! lost, and the timer that sends probes when nothing is heard.
//!
//! [`Recovery`] keeps what was sent in each packet number space until an acknowledgment or a loss settles it, and hands back the
//! packets that were acknowledged and those that were lost, with what the connection stored with each of them (`T`: the frames, say,
//! to be sent again), so it knows nothing of frames. It owns the congestion controller and the pacer, which it tells what happens.
//! It reads no clock: every call is given the time. The one timer ([`Recovery::timer`]) is set again at each event that needs it
//! and [`Recovery::on_timeout`] is called when it expires.

use super::congestion::{NewReno, Pacer};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

/// How many packets later than a packet may be acknowledged before it is lost (RFC 9002 section 6.1.1).
pub const PACKET_THRESHOLD: u64 = 3;
/// The timer granularity: no delay is shorter (RFC 9002 section 6.1.2).
pub const GRANULARITY: Duration = Duration::from_millis(1);
/// The round-trip time before there is a sample (RFC 9002 section 6.2.2).
pub const INITIAL_RTT: Duration = Duration::from_millis(333);
/// How many PTO periods of loss make persistent congestion (RFC 9002 section 7.6).
pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;
/// The longest round trip a sample counts for: a longer one is taken as this. A peer that takes longer to acknowledge is as good
/// as gone (idle timeouts are shorter), and the bound keeps what is made of the estimate (the probe timeout, times a backoff of
/// up to 2^20) finite. (A sample of a thousand years made the multiplication overflow; found by the field run's fuzzing.)
pub const MAX_RTT: Duration = Duration::from_secs(60);

/// `t + d`, or the furthest `t` can go if that is past what an `Instant` holds (a timer that far away never fires).
fn later(t: Instant, d: Duration) -> Instant {
    t.checked_add(d).or_else(|| t.checked_add(Duration::from_secs(1 << 32))).unwrap_or(t)
}

/// The three packet number spaces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    Initial,
    Handshake,
    Application,
}

impl Space {
    pub const ALL: [Space; 3] = [Space::Initial, Space::Handshake, Space::Application];

    pub fn index(self) -> usize {
        self as usize
    }
}

/// A packet that was sent and is not yet acknowledged or lost.
#[derive(Clone, Debug)]
pub struct Sent<T> {
    pub pn: u64,
    pub time: Instant,
    /// Bytes in the packet, from its first byte to its tag (no UDP or IP header).
    pub size: usize,
    /// It has a frame that the peer has to acknowledge.
    pub ack_eliciting: bool,
    /// It counts toward the bytes in flight (ack-eliciting, or with PADDING).
    pub in_flight: bool,
    pub payload: T,
}

/// What an acknowledgment settled.
#[derive(Debug)]
pub struct AckOutcome<T> {
    /// Packets that the acknowledgment newly acknowledged, from the lowest packet number up.
    pub acked: Vec<Sent<T>>,
    /// Packets that were declared lost because of it (or, for the other kind of loss, see [`Timeout`]).
    pub lost: Vec<Sent<T>>,
}

/// What a timer that expired asks for.
#[derive(Debug)]
pub struct Timeout<T> {
    /// The space that `lost` are from.
    pub lost_space: Space,
    /// Packets that the time threshold declared lost (the timer was set for them).
    pub lost: Vec<Sent<T>>,
    /// A probe timeout: send one or two ack-eliciting packets, whatever the congestion window says.
    pub probe: Option<Probe>,
}

/// What a probe timeout asks to be sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Probe {
    /// The packet number space whose packets timed out, which the probe is in.
    pub space: Space,
    /// Nothing was in flight: the client sends so as to unblock a server that may be held back by its amplification limit (a
    /// padded Initial packet if there are no Handshake keys, a Handshake packet if there are), and one packet is enough.
    pub anti_deadlock: bool,
}

struct SpaceState<T> {
    sent: BTreeMap<u64, Sent<T>>,
    largest_acked: Option<u64>,
    loss_time: Option<Instant>,
    last_ack_eliciting: Option<Instant>,
    ack_eliciting_in_flight: usize,
}

impl<T> SpaceState<T> {
    fn new() -> SpaceState<T> {
        SpaceState { sent: BTreeMap::new(), largest_acked: None, loss_time: None, last_ack_eliciting: None, ack_eliciting_in_flight: 0 }
    }
}

pub struct Recovery<T> {
    latest_rtt: Duration,
    smoothed_rtt: Duration,
    rttvar: Duration,
    min_rtt: Duration,
    /// When the first RTT sample was taken.
    first_rtt_sample: Option<Instant>,
    /// The peer's max_ack_delay (its transport parameter; 25 ms by default).
    max_ack_delay: Duration,
    handshake_confirmed: bool,
    /// An acknowledgment of a Handshake packet came: the server has validated our address.
    handshake_acked: bool,
    handshake_keys: bool,
    pto_count: u32,
    timer: Option<Instant>,
    spaces: [SpaceState<T>; 3],
    cc: NewReno,
    pacer: Pacer,
}

impl<T> Recovery<T> {
    pub fn new(max_datagram_size: usize) -> Recovery<T> {
        Recovery {
            latest_rtt: Duration::ZERO,
            smoothed_rtt: INITIAL_RTT,
            rttvar: INITIAL_RTT / 2,
            min_rtt: Duration::ZERO,
            first_rtt_sample: None,
            max_ack_delay: Duration::from_millis(25),
            handshake_confirmed: false,
            handshake_acked: false,
            handshake_keys: false,
            pto_count: 0,
            timer: None,
            spaces: [SpaceState::new(), SpaceState::new(), SpaceState::new()],
            cc: NewReno::new(max_datagram_size),
            pacer: Pacer::new(max_datagram_size),
        }
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // what is known

    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    pub fn has_rtt_sample(&self) -> bool {
        self.first_rtt_sample.is_some()
    }

    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    pub fn congestion(&self) -> &NewReno {
        &self.cc
    }

    pub fn bytes_in_flight(&self) -> usize {
        self.cc.bytes_in_flight()
    }

    /// How many ack-eliciting packets are in flight in `space`.
    pub fn ack_eliciting_in_flight(&self, space: Space) -> usize {
        self.spaces[space.index()].ack_eliciting_in_flight
    }

    pub fn largest_acked(&self, space: Space) -> Option<u64> {
        self.spaces[space.index()].largest_acked
    }

    /// The packets still waiting to be acknowledged in `space`, by packet number.
    pub fn outstanding(&self, space: Space) -> impl Iterator<Item = &Sent<T>> {
        self.spaces[space.index()].sent.values()
    }

    /// The probe timeout period for packets in the Application Data space, or in the other two (without the peer's max_ack_delay),
    /// not counting the backoff.
    pub fn pto_period(&self, space: Space) -> Duration {
        let base = self.smoothed_rtt + (4 * self.rttvar).max(GRANULARITY);
        if space == Space::Application {
            base + self.max_ack_delay
        } else {
            base
        }
    }

    pub fn timer(&self) -> Option<Instant> {
        self.timer
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // what the connection tells

    /// The peer's max_ack_delay, from its transport parameters.
    pub fn set_max_ack_delay(&mut self, delay: Duration) {
        self.max_ack_delay = delay;
    }

    /// Handshake keys are installed: a probe with nothing in flight goes in a Handshake packet.
    pub fn set_handshake_keys(&mut self, have: bool) {
        self.handshake_keys = have;
    }

    /// The handshake is confirmed (the server said so with HANDSHAKE_DONE): the peer's max_ack_delay applies, the Application
    /// Data space has a probe timeout, and nothing more is held back for the server's address validation.
    pub fn on_handshake_confirmed(&mut self, now: Instant) {
        self.handshake_confirmed = true;
        self.set_timer(now);
    }

    pub fn set_max_datagram_size(&mut self, size: usize) {
        self.cc.set_max_datagram_size(size);
        self.pacer.set_max_datagram_size(size);
    }

    /// A packet was sent. A packet that has no ack-eliciting frame and no PADDING is kept too (for what an acknowledgment of it
    /// says about what has been acknowledged), but it is not in flight and does not start a timer.
    pub fn on_packet_sent(&mut self, now: Instant, space: Space, sent: Sent<T>) {
        let (in_flight, ack_eliciting, size) = (sent.in_flight, sent.ack_eliciting, sent.size);
        let sp = &mut self.spaces[space.index()];
        if in_flight {
            if ack_eliciting {
                sp.last_ack_eliciting = Some(now);
                sp.ack_eliciting_in_flight += 1;
            }
            sp.sent.insert(sent.pn, sent);
            self.cc.on_sent(size);
            let rate = self.pacing_rate();
            self.pacer.on_sent(now, size, rate);
            self.set_timer(now);
        } else {
            sp.sent.insert(sent.pn, sent);
        }
    }

    fn pacing_rate(&self) -> f64 {
        Pacer::rate(self.cc.window(), self.smoothed_rtt, self.cc.in_slow_start())
    }

    /// When the pacer lets the next packet go (None: now). Packets that have only an ACK frame are not paced: the caller does not ask.
    pub fn next_send_time(&mut self, now: Instant) -> Option<Instant> {
        let rate = self.pacing_rate();
        self.pacer.next_send_time(now, rate)
    }

    /// An ACK frame arrived in `space`: `largest` is the largest packet number it acknowledges, `ack_delay` the delay that it
    /// reports (decoded), `ranges` the packet numbers acknowledged, from the highest range down.
    pub fn on_ack_received(
        &mut self,
        now: Instant,
        space: Space,
        largest: u64,
        ack_delay: Duration,
        ranges: impl Iterator<Item = RangeInclusive<u64>>,
    ) -> AckOutcome<T> {
        let si = space.index();
        let prior = self.spaces[si].largest_acked;
        self.spaces[si].largest_acked = Some(prior.map_or(largest, |p| p.max(largest)));

        let mut acked = Vec::new();
        for r in ranges {
            let keys: Vec<u64> = self.spaces[si].sent.range(r).map(|(&k, _)| k).collect();
            for k in keys {
                acked.push(self.spaces[si].sent.remove(&k).expect("a key that was just listed"));
            }
        }
        if acked.is_empty() {
            return AckOutcome { acked, lost: Vec::new() };
        }
        acked.sort_by_key(|p| p.pn);

        // a sample from the largest packet if this acknowledgment is the first to tell of it, and if something it acknowledges needed
        // an acknowledgment
        let newest = acked.last().expect("some acknowledged");
        if newest.pn == largest && acked.iter().any(|p| p.ack_eliciting) {
            self.latest_rtt = now.saturating_duration_since(newest.time).min(MAX_RTT);
            let delay = if space == Space::Initial { Duration::ZERO } else { ack_delay };
            self.update_rtt(now, delay);
        }

        if space == Space::Handshake {
            self.handshake_acked = true;
        }
        let in_flight_before = self.cc.bytes_in_flight();
        let lost = self.detect_lost(now, space);
        self.on_packets_lost(now, &lost);
        for p in &acked {
            if p.in_flight {
                self.cc.on_acked(p.size, p.time, in_flight_before);
                if p.ack_eliciting {
                    self.spaces[si].ack_eliciting_in_flight -= 1;
                }
            }
        }
        // A client that does not know that the server has validated its address does not take an acknowledgment as a sign that it
        // can back off less (RFC 9002 section 6.2.1).
        if self.peer_completed_address_validation() {
            self.pto_count = 0;
        }
        self.set_timer(now);
        AckOutcome { acked, lost }
    }

    fn peer_completed_address_validation(&self) -> bool {
        self.handshake_confirmed || self.handshake_acked
    }

    fn update_rtt(&mut self, now: Instant, ack_delay: Duration) {
        if self.first_rtt_sample.is_none() {
            self.min_rtt = self.latest_rtt;
            self.smoothed_rtt = self.latest_rtt;
            self.rttvar = self.latest_rtt / 2;
            self.first_rtt_sample = Some(now);
            return;
        }
        self.min_rtt = self.min_rtt.min(self.latest_rtt);
        let ack_delay = if self.handshake_confirmed { ack_delay.min(self.max_ack_delay) } else { ack_delay };
        // the delay is taken off the sample if that leaves no less than the smallest round trip seen
        let adjusted = if self.latest_rtt >= self.min_rtt + ack_delay { self.latest_rtt - ack_delay } else { self.latest_rtt };
        // (the variation is taken against the estimate before this sample, as in RFC 6298 and the appendix of RFC 9002)
        let deviation = if self.smoothed_rtt > adjusted { self.smoothed_rtt - adjusted } else { adjusted - self.smoothed_rtt };
        self.rttvar = self.rttvar * 3 / 4 + deviation / 4;
        self.smoothed_rtt = self.smoothed_rtt * 7 / 8 + adjusted / 8;
    }

    /// Takes the packets of `space` that are lost out of the sent packets: those that a packet at least `PACKET_THRESHOLD` after
    /// was acknowledged, and those sent long enough ago that the time threshold says; sets the time for those that are close.
    fn detect_lost(&mut self, now: Instant, space: Space) -> Vec<Sent<T>> {
        let si = space.index();
        self.spaces[si].loss_time = None;
        let Some(largest) = self.spaces[si].largest_acked else { return Vec::new() };
        let loss_delay = (self.latest_rtt.max(self.smoothed_rtt) * 9 / 8).max(GRANULARITY);
        let mut lost_pns = Vec::new();
        let mut loss_time: Option<Instant> = None;
        for (&pn, p) in self.spaces[si].sent.range(..=largest) {
            if now.saturating_duration_since(p.time) >= loss_delay || largest >= pn + PACKET_THRESHOLD {
                lost_pns.push(pn);
            } else {
                let t = later(p.time, loss_delay);
                loss_time = Some(loss_time.map_or(t, |l| l.min(t)));
            }
        }
        self.spaces[si].loss_time = loss_time;
        let lost: Vec<Sent<T>> = lost_pns.into_iter().map(|pn| self.spaces[si].sent.remove(&pn).expect("listed")).collect();
        self.spaces[si].ack_eliciting_in_flight -= lost.iter().filter(|p| p.in_flight && p.ack_eliciting).count();
        lost
    }

    /// What loss does to the bytes in flight and the congestion window.
    fn on_packets_lost(&mut self, now: Instant, lost: &[Sent<T>]) {
        let mut last_sent: Option<Instant> = None;
        for p in lost {
            if p.in_flight {
                self.cc.on_lost(p.size);
                last_sent = Some(last_sent.map_or(p.time, |l| l.max(p.time)));
            }
        }
        if let Some(sent) = last_sent {
            self.cc.on_congestion_event(now, sent);
        }
        if self.in_persistent_congestion(lost) {
            self.cc.on_persistent_congestion();
        }
    }

    /// Whether `lost` (packets of one space, by packet number) include two ack-eliciting packets, both sent after the first RTT sample,
    /// with no packet between them that was not lost, and further apart than the persistent congestion duration (RFC 9002 section
    /// 7.6; only the space of the acknowledgment is looked at, which the RFC allows).
    fn in_persistent_congestion(&self, lost: &[Sent<T>]) -> bool {
        let Some(first_sample) = self.first_rtt_sample else { return false };
        let duration = (self.smoothed_rtt + (4 * self.rttvar).max(GRANULARITY) + self.max_ack_delay) * PERSISTENT_CONGESTION_THRESHOLD;
        // runs of consecutive packet numbers (a packet between that is not in the list was acknowledged or is still out): from the
        // first ack-eliciting packet of a run to each later one
        let mut run_start: Option<Instant> = None;
        let mut last_pn: Option<u64> = None;
        for p in lost {
            if last_pn.is_some_and(|l| p.pn != l + 1) {
                run_start = None;
            }
            last_pn = Some(p.pn);
            if p.ack_eliciting && p.time > first_sample {
                match run_start {
                    None => run_start = Some(p.time),
                    Some(start) if p.time.saturating_duration_since(start) > duration => return true,
                    Some(_) => {}
                }
            }
        }
        false
    }

    // -----------------------------------------------------------------------------------------------------------------------
    // the timer

    fn loss_time_and_space(&self) -> Option<(Instant, Space)> {
        let mut best: Option<(Instant, Space)> = None;
        for space in Space::ALL {
            if let Some(t) = self.spaces[space.index()].loss_time {
                if best.map_or(true, |(b, _)| t < b) {
                    best = Some((t, space));
                }
            }
        }
        best
    }

    fn any_ack_eliciting_in_flight(&self) -> bool {
        self.spaces.iter().any(|s| s.ack_eliciting_in_flight > 0)
    }

    /// When the probe timeout is, and for which space (RFC 9002 section 6.2.1, with `now` where the algorithm says "now").
    fn pto_time_and_space(&self, now: Instant) -> Option<(Instant, Space)> {
        let backoff = 1u32 << self.pto_count.min(20);
        let base = self.smoothed_rtt.saturating_add(self.rttvar.saturating_mul(4).max(GRANULARITY));
        if !self.any_ack_eliciting_in_flight() {
            // the anti-deadlock probe: from now
            let space = if self.handshake_keys { Space::Handshake } else { Space::Initial };
            return Some((later(now, base.saturating_mul(backoff)), space));
        }
        let mut best: Option<(Instant, Space)> = None;
        for space in Space::ALL {
            let s = &self.spaces[space.index()];
            if s.ack_eliciting_in_flight == 0 {
                continue;
            }
            let mut duration = base.saturating_mul(backoff);
            if space == Space::Application {
                // not until the handshake is confirmed
                if !self.handshake_confirmed {
                    return best;
                }
                duration = duration.saturating_add(self.max_ack_delay.saturating_mul(backoff));
            }
            let Some(last) = s.last_ack_eliciting else { continue };
            let t = later(last, duration);
            if best.map_or(true, |(b, _)| t < b) {
                best = Some((t, space));
            }
        }
        best
    }

    /// Sets the one timer again (RFC 9002 `SetLossDetectionTimer`): for the earliest time threshold if there is one, else for the
    /// probe timeout, else off.
    fn set_timer(&mut self, now: Instant) {
        if let Some((t, _)) = self.loss_time_and_space() {
            self.timer = Some(t);
            return;
        }
        if !self.any_ack_eliciting_in_flight() && self.peer_completed_address_validation() {
            self.timer = None;
            return;
        }
        self.timer = self.pto_time_and_space(now).map(|(t, _)| t);
    }

    /// The timer expired at `now`.
    pub fn on_timeout(&mut self, now: Instant) -> Timeout<T> {
        if let Some((_, space)) = self.loss_time_and_space() {
            let lost = self.detect_lost(now, space);
            self.on_packets_lost(now, &lost);
            self.set_timer(now);
            return Timeout { lost_space: space, lost, probe: None };
        }
        let anti_deadlock = !self.any_ack_eliciting_in_flight();
        let probe = if anti_deadlock {
            debug_assert!(!self.peer_completed_address_validation());
            let space = if self.handshake_keys { Space::Handshake } else { Space::Initial };
            Probe { space, anti_deadlock: true }
        } else {
            let space = self.pto_time_and_space(now).map(|(_, s)| s).unwrap_or(Space::Application);
            Probe { space, anti_deadlock: false }
        };
        self.pto_count += 1;
        self.set_timer(now);
        Timeout { lost_space: probe.space, lost: Vec::new(), probe: Some(probe) }
    }

    /// The keys of `space` are discarded (Initial: when the client sends its first Handshake packet; Handshake: when the handshake is
    /// confirmed): its packets are given up, and the timers start over. Returns what was outstanding.
    pub fn discard_space(&mut self, now: Instant, space: Space) -> Vec<Sent<T>> {
        let s = std::mem::replace(&mut self.spaces[space.index()], SpaceState::new());
        let bytes: usize = s.sent.values().filter(|p| p.in_flight).map(|p| p.size).sum();
        self.cc.on_discarded(bytes);
        if space == Space::Handshake {
            self.handshake_keys = false;
        }
        self.pto_count = 0;
        self.set_timer(now);
        s.sent.into_values().collect()
    }

    /// The server sent a Retry: start over (RFC 9002 section 6.3.1). `rtt` is the time from the first Initial packet to the Retry,
    /// which can stand in for the first estimate. Returns the packets that were outstanding.
    pub fn reset(&mut self, rtt: Option<Duration>) -> Vec<Sent<T>> {
        let mds = self.cc.max_datagram_size();
        let mut gone = Vec::new();
        for s in &mut self.spaces {
            let old = std::mem::replace(s, SpaceState::new());
            gone.extend(old.sent.into_values());
        }
        self.cc = NewReno::new(mds);
        self.pacer = Pacer::new(mds);
        self.pto_count = 0;
        self.timer = None;
        if let Some(rtt) = rtt {
            let rtt = rtt.min(MAX_RTT);
            self.smoothed_rtt = rtt;
            self.rttvar = rtt / 2;
        }
        gone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDS: usize = 1200;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn sent(pn: u64, time: Instant, ack_eliciting: bool) -> Sent<u64> {
        Sent { pn, time, size: 1200, ack_eliciting, in_flight: ack_eliciting, payload: pn * 100 }
    }

    /// A connection after the handshake with an RTT of 100 ms and nothing to wait for.
    fn established(t0: Instant) -> Recovery<u64> {
        let mut r = Recovery::new(MDS);
        r.on_packet_sent(t0, Space::Application, sent(0, t0, true));
        r.on_handshake_confirmed(t0);
        let out = r.on_ack_received(t0 + ms(100), Space::Application, 0, ms(0), std::iter::once(0..=0));
        assert_eq!(out.acked.len(), 1);
        assert_eq!(r.smoothed_rtt(), ms(100));
        r
    }

    fn pns(v: &[Sent<u64>]) -> Vec<u64> {
        v.iter().map(|p| p.pn).collect()
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // the estimate

    #[test]
    fn a_sample_of_ages_counts_as_a_minute_and_the_backed_off_timer_stays_finite() {
        // (the field run's fuzzer found a sample long enough to overflow the probe timeout times its backoff)
        let t0 = Instant::now();
        let mut r = Recovery::new(MDS);
        r.on_packet_sent(t0, Space::Initial, sent(0, t0, true));
        let far = t0 + Duration::from_secs(1 << 40);
        r.on_ack_received(far, Space::Initial, 0, ms(0), std::iter::once(0..=0));
        assert_eq!((r.latest_rtt(), r.smoothed_rtt()), (MAX_RTT, MAX_RTT));
        // probe after probe, up to the most backoff there is: the timer is always somewhere
        r.on_packet_sent(far, Space::Initial, sent(1, far, true));
        let mut now = far;
        for _ in 0..30 {
            let Some(t) = r.timer() else { panic!("no timer with a packet out") };
            assert!(t > now);
            now = t;
            r.on_timeout(now);
            r.on_packet_sent(now, Space::Initial, sent(100 + r.pto_count() as u64, now, true));
        }
        assert_eq!(r.reset(Some(Duration::MAX)).len() > 0, true);
        assert_eq!(r.smoothed_rtt(), MAX_RTT);
    }

    #[test]
    fn the_first_sample_is_the_estimate() {
        let t0 = Instant::now();
        let mut r = Recovery::new(MDS);
        assert_eq!((r.smoothed_rtt(), r.rttvar(), r.has_rtt_sample()), (ms(333), ms(333) / 2, false));
        r.on_packet_sent(t0, Space::Initial, sent(0, t0, true));
        r.on_ack_received(t0 + ms(80), Space::Initial, 0, ms(0), std::iter::once(0..=0));
        assert_eq!((r.latest_rtt(), r.smoothed_rtt(), r.rttvar(), r.min_rtt()), (ms(80), ms(80), ms(40), ms(80)));
        assert!(r.has_rtt_sample());
    }

    #[test]
    fn later_samples_are_smoothed_and_the_peers_delay_is_taken_off() {
        let t0 = Instant::now();
        let mut r = established(t0);
        // 100 ms smoothed, 50 ms variation. A sample of 180 ms with a delay of 20 ms (the handshake is confirmed: at most max_ack_delay,
        // 25 ms): adjusted 160.
        r.on_packet_sent(t0 + ms(200), Space::Application, sent(1, t0 + ms(200), true));
        r.on_ack_received(t0 + ms(380), Space::Application, 1, ms(20), std::iter::once(1..=1));
        assert_eq!(r.latest_rtt(), ms(180));
        // variation: 3/4 * 50 + 1/4 * |100 - 160| = 37.5 + 15 = 52.5; smoothed: 7/8 * 100 + 1/8 * 160 = 107.5
        assert_eq!(r.rttvar(), Duration::from_micros(52_500));
        assert_eq!(r.smoothed_rtt(), Duration::from_micros(107_500));
        assert_eq!(r.min_rtt(), ms(100));
    }

    #[test]
    fn a_delay_larger_than_max_ack_delay_is_cut_once_the_handshake_is_confirmed() {
        let t0 = Instant::now();
        let mut r = established(t0);
        r.on_packet_sent(t0 + ms(200), Space::Application, sent(1, t0 + ms(200), true));
        // reports 90 ms of delay: only 25 ms counts, so adjusted = 200 - 25
        r.on_ack_received(t0 + ms(400), Space::Application, 1, ms(90), std::iter::once(1..=1));
        // 7/8 * 100 + 1/8 * 175 = 109.375
        assert_eq!(r.smoothed_rtt(), Duration::from_micros(109_375));
    }

    #[test]
    fn the_delay_is_not_taken_off_below_the_smallest_round_trip() {
        let t0 = Instant::now();
        let mut r = established(t0);
        r.on_packet_sent(t0 + ms(200), Space::Application, sent(1, t0 + ms(200), true));
        // a sample of 110 ms with a reported delay of 20: 110 < 100 + 20, so the delay is not taken off
        r.on_ack_received(t0 + ms(310), Space::Application, 1, ms(20), std::iter::once(1..=1));
        assert_eq!(r.smoothed_rtt(), Duration::from_micros(101_250));
    }

    #[test]
    fn some_acknowledgments_give_no_sample() {
        let t0 = Instant::now();
        let mut r = established(t0);
        r.on_packet_sent(t0 + ms(200), Space::Application, sent(1, t0 + ms(200), false));
        // the largest acknowledged is not ack-eliciting and nothing else is acknowledged
        r.on_ack_received(t0 + ms(400), Space::Application, 1, ms(0), std::iter::once(1..=1));
        assert_eq!(r.latest_rtt(), ms(100));
        // the largest acknowledged was acknowledged before: 5 first (a sample), then 4 and 5 (4 is new, but it is not the largest)
        r.on_packet_sent(t0 + ms(500), Space::Application, sent(4, t0 + ms(500), true));
        r.on_packet_sent(t0 + ms(510), Space::Application, sent(5, t0 + ms(510), true));
        r.on_ack_received(t0 + ms(630), Space::Application, 5, ms(0), std::iter::once(5..=5));
        assert_eq!(r.latest_rtt(), ms(120));
        r.on_ack_received(t0 + ms(700), Space::Application, 5, ms(0), std::iter::once(4..=5));
        assert_eq!(r.latest_rtt(), ms(120));
        // an acknowledgment that tells nothing new
        let out = r.on_ack_received(t0 + ms(800), Space::Application, 5, ms(0), std::iter::once(4..=5));
        assert!(out.acked.is_empty() && out.lost.is_empty());
    }

    #[test]
    fn a_sample_is_taken_when_the_largest_is_newly_acknowledged_with_something_that_needs_an_acknowledgment() {
        let t0 = Instant::now();
        let mut r = established(t0);
        r.on_packet_sent(t0 + ms(200), Space::Application, sent(1, t0 + ms(200), false));
        r.on_packet_sent(t0 + ms(210), Space::Application, sent(2, t0 + ms(210), true));
        r.on_packet_sent(t0 + ms(220), Space::Application, sent(3, t0 + ms(220), false));
        // (RFC 9002 appendix: the largest newly acknowledged is the largest of the frame, and some one acknowledged is ack-eliciting)
        r.on_ack_received(t0 + ms(400), Space::Application, 3, ms(0), std::iter::once(1..=3));
        assert_eq!(r.latest_rtt(), ms(180));
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // loss

    #[test]
    fn a_packet_three_behind_the_largest_acknowledged_is_lost() {
        let t0 = Instant::now();
        let mut r = established(t0);
        let t = t0 + ms(200);
        for pn in 1..=6 {
            r.on_packet_sent(t, Space::Application, sent(pn, t, true));
        }
        // 5 is acknowledged: 1 and 2 are three or more behind (5 >= 1 + 3, 5 >= 2 + 3); 3 and 4 are not
        let out = r.on_ack_received(t + ms(100), Space::Application, 5, ms(0), std::iter::once(5..=5));
        assert_eq!(pns(&out.acked), vec![5]);
        assert_eq!(pns(&out.lost), vec![1, 2]);
        assert_eq!(r.ack_eliciting_in_flight(Space::Application), 3);
        // 3 and 4 are lost by time: 9/8 of the round trip (the larger of the latest, 100 ms, and the smoothed, 100 ms) after sending
        let timer = r.timer().expect("a timer for the time threshold");
        assert_eq!(timer, t + ms(100) * 9 / 8);
        let out = r.on_timeout(timer);
        assert_eq!(pns(&out.lost), vec![3, 4]);
        assert!(out.probe.is_none());
        // 6 is still out: a probe timer
        assert_eq!(r.ack_eliciting_in_flight(Space::Application), 1);
        assert!(r.timer().unwrap() > timer);
    }

    #[test]
    fn a_packet_that_has_waited_longer_than_the_time_threshold_is_lost_at_the_next_acknowledgment() {
        let t0 = Instant::now();
        let mut r = established(t0);
        r.on_packet_sent(t0 + ms(200), Space::Application, sent(1, t0 + ms(200), true));
        r.on_packet_sent(t0 + ms(290), Space::Application, sent(2, t0 + ms(290), true));
        // 2 is acknowledged 100 ms after 1 is sent... 1 was sent 190 ms before 2 was acknowledged: more than 112.5 ms
        let out = r.on_ack_received(t0 + ms(390), Space::Application, 2, ms(0), std::iter::once(2..=2));
        assert_eq!(pns(&out.lost), vec![1]);
    }

    #[test]
    fn a_loss_cuts_the_window_once() {
        let t0 = Instant::now();
        let mut r = established(t0);
        let w = r.congestion().window();
        let t = t0 + ms(200);
        for pn in 1..=8 {
            r.on_packet_sent(t, Space::Application, sent(pn, t, true));
        }
        let out = r.on_ack_received(t + ms(100), Space::Application, 8, ms(0), std::iter::once(8..=8));
        assert_eq!(pns(&out.lost), vec![1, 2, 3, 4, 5]);
        assert!(r.congestion().window() < w, "{} < {}", r.congestion().window(), w);
        assert_eq!(r.congestion().window(), w / 2);
        // 6 and 7 go by the time threshold and are part of the same event
        let timer = r.timer().unwrap();
        r.on_timeout(timer);
        assert_eq!(r.congestion().window(), w / 2);
    }

    #[test]
    fn packets_that_are_not_in_flight_are_not_counted_but_are_lost_and_acknowledged_like_the_rest() {
        let t0 = Instant::now();
        let mut r = established(t0);
        let t = t0 + ms(200);
        r.on_packet_sent(t, Space::Application, sent(1, t, false));
        assert_eq!((r.bytes_in_flight(), r.ack_eliciting_in_flight(Space::Application)), (0, 0));
        assert_eq!(r.outstanding(Space::Application).count(), 1);
        let out = r.on_ack_received(t + ms(50), Space::Application, 1, ms(0), std::iter::once(1..=1));
        assert_eq!(pns(&out.acked), vec![1]);
        assert_eq!(r.outstanding(Space::Application).count(), 0);
    }

    #[test]
    fn persistent_congestion_needs_a_long_span_of_lost_packets() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.set_max_ack_delay(Duration::ZERO);
        r.on_handshake_confirmed(t0);
        // an RTT sample first, so that persistent congestion can be established: a round trip of 200 ms and a variation of 100 ms,
        // so the period is 200 + 4 * 100 = 600 ms and the duration three of them
        r.on_packet_sent(t0, Space::Application, sent(0, t0, true));
        r.on_ack_received(t0 + ms(200), Space::Application, 0, ms(0), std::iter::once(0..=0));
        assert_eq!((r.smoothed_rtt(), r.rttvar()), (ms(200), ms(100)));
        let base = t0 + ms(1000);
        for i in 0..7u64 {
            let t = base + ms(500 * i);
            r.on_packet_sent(t, Space::Application, sent(1 + i, t, true));
        }
        let t = base + ms(3100);
        r.on_packet_sent(t, Space::Application, sent(8, t, true));
        assert!(r.congestion().window() > 2 * MDS);
        // 8 is acknowledged late: 1 to 7 are lost, 3000 ms from the first to the last, more than 1800 (or what the estimate has become)
        let out = r.on_ack_received(base + ms(3300), Space::Application, 8, ms(0), std::iter::once(8..=8));
        assert_eq!(pns(&out.lost), vec![1, 2, 3, 4, 5, 6, 7]);
        // (the packet that was acknowledged then grows the window of two packets by its size, in slow start)
        assert_eq!(r.congestion().window(), 3 * MDS, "persistent congestion");
    }

    #[test]
    fn no_persistent_congestion_if_a_packet_between_was_acknowledged_or_the_span_is_short() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.set_max_ack_delay(Duration::ZERO);
        r.on_handshake_confirmed(t0);
        r.on_packet_sent(t0, Space::Application, sent(0, t0, true));
        r.on_ack_received(t0 + ms(200), Space::Application, 0, ms(0), std::iter::once(0..=0));
        let base = t0 + ms(1000);
        for i in 0..7u64 {
            let t = base + ms(500 * i);
            r.on_packet_sent(t, Space::Application, sent(1 + i, t, true));
        }
        // 4 (sent at 1500 after base) is acknowledged along with 8: the lost ones are in two runs, 1..=3 (1000 ms) and 5..=7
        let t = base + ms(3100);
        r.on_packet_sent(t, Space::Application, sent(8, t, true));
        let out = r.on_ack_received(base + ms(3300), Space::Application, 8, ms(0), [8..=8, 4..=4].into_iter());
        assert_eq!(pns(&out.lost), vec![1, 2, 3, 5, 6, 7]);
        assert!(r.congestion().window() > 2 * MDS, "a window of {}", r.congestion().window());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // the timer

    #[test]
    fn a_probe_timeout_is_the_estimate_plus_four_variations_plus_max_ack_delay_and_doubles() {
        let t0 = Instant::now();
        let mut r = established(t0);
        // smoothed 100, variation 50: 100 + 200 + 25
        assert_eq!(r.pto_period(Space::Application), ms(325));
        assert_eq!(r.pto_period(Space::Handshake), ms(300));
        let t = t0 + ms(200);
        r.on_packet_sent(t, Space::Application, sent(1, t, true));
        assert_eq!(r.timer(), Some(t + ms(325)));
        let out = r.on_timeout(t + ms(325));
        assert_eq!(out.probe, Some(Probe { space: Space::Application, anti_deadlock: false }));
        assert!(out.lost.is_empty(), "a probe timeout does not declare anything lost");
        assert_eq!(r.pto_count(), 1);
        assert_eq!(r.timer(), Some(t + ms(650)));
        r.on_timeout(t + ms(650));
        assert_eq!(r.timer(), Some(t + ms(1300)));
        // an acknowledgment (once the server's address is known to be validated) takes the backoff off
        r.on_ack_received(t + ms(1400), Space::Application, 1, ms(0), std::iter::once(1..=1));
        assert_eq!(r.pto_count(), 0);
        assert_eq!(r.timer(), None, "nothing in flight");
    }

    #[test]
    fn the_application_space_has_no_timer_until_the_handshake_is_confirmed() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.set_handshake_keys(true);
        r.on_packet_sent(t0, Space::Application, sent(0, t0, true));
        assert_eq!(r.timer(), None, "only Application Data packets are in flight, and the handshake is not confirmed");
        r.on_packet_sent(t0, Space::Handshake, sent(0, t0, true));
        assert_eq!(r.pto_time_and_space(t0).map(|(_, s)| s), Some(Space::Handshake));
        r.on_handshake_confirmed(t0);
        // now both: the Handshake one is earlier (no max_ack_delay), and without it the Application one has a timer
        assert_eq!(r.pto_time_and_space(t0).map(|(_, s)| s), Some(Space::Handshake));
        r.discard_space(t0, Space::Handshake);
        assert_eq!(r.pto_time_and_space(t0).map(|(_, s)| s), Some(Space::Application));
        assert_eq!(r.timer(), Some(t0 + ms(999) + ms(25)));
    }

    #[test]
    fn a_timer_for_the_earlier_of_initial_and_handshake() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.on_packet_sent(t0, Space::Initial, sent(0, t0, true));
        // (333 + 4 * 166.5) * 1 = 999 ms
        assert_eq!(r.timer(), Some(t0 + ms(999)));
        r.set_handshake_keys(true);
        r.on_packet_sent(t0 + ms(10), Space::Handshake, sent(0, t0 + ms(10), true));
        assert_eq!(r.timer(), Some(t0 + ms(999)), "the Initial packet is older");
        let out = r.on_timeout(t0 + ms(999));
        assert_eq!(out.probe, Some(Probe { space: Space::Initial, anti_deadlock: false }));
        // the backoff counts for both spaces: the Initial packet is next at 2 * 999, and the Handshake one at 10 + 2 * 999
        assert_eq!(r.timer(), Some(t0 + ms(1998)));
    }

    #[test]
    fn a_client_with_nothing_in_flight_still_has_a_timer_until_the_server_has_validated_it() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.on_packet_sent(t0, Space::Initial, sent(0, t0, true));
        r.on_ack_received(t0 + ms(50), Space::Initial, 0, ms(0), std::iter::once(0..=0));
        assert_eq!(r.ack_eliciting_in_flight(Space::Initial), 0);
        // (smoothed 50, variation 25: 150 ms from the acknowledgment)
        assert_eq!(r.timer(), Some(t0 + ms(50) + ms(150)));
        assert_eq!(r.pto_count(), 0);
        let out = r.on_timeout(t0 + ms(200));
        assert_eq!(out.probe, Some(Probe { space: Space::Initial, anti_deadlock: true }));
        assert_eq!(r.pto_count(), 1);
        // and an acknowledgment of an Initial packet does not take the backoff off
        r.on_packet_sent(t0 + ms(200), Space::Initial, sent(1, t0 + ms(200), true));
        r.on_ack_received(t0 + ms(250), Space::Initial, 1, ms(0), std::iter::once(1..=1));
        assert_eq!(r.pto_count(), 1);
        // once there are Handshake keys the probe is a Handshake packet
        r.set_handshake_keys(true);
        let out = r.on_timeout(r.timer().unwrap());
        assert_eq!(out.probe, Some(Probe { space: Space::Handshake, anti_deadlock: true }));
        // and an acknowledgment of a Handshake packet is the proof, and resets it
        r.on_packet_sent(t0 + ms(300), Space::Handshake, sent(0, t0 + ms(300), true));
        r.on_ack_received(t0 + ms(350), Space::Handshake, 0, ms(0), std::iter::once(0..=0));
        assert_eq!(r.pto_count(), 0);
        assert_eq!(r.timer(), None);
    }

    #[test]
    fn discarding_a_space_gives_up_its_packets_and_starts_the_timers_over() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.on_packet_sent(t0, Space::Initial, sent(0, t0, true));
        r.on_packet_sent(t0, Space::Initial, sent(1, t0, true));
        r.set_handshake_keys(true);
        r.on_packet_sent(t0 + ms(5), Space::Handshake, sent(0, t0 + ms(5), true));
        r.on_timeout(t0 + ms(999));
        assert_eq!(r.pto_count(), 1);
        assert_eq!(r.bytes_in_flight(), 3600);
        let gone = r.discard_space(t0 + ms(1000), Space::Initial);
        assert_eq!(pns(&gone), vec![0, 1]);
        assert_eq!((r.bytes_in_flight(), r.pto_count(), r.ack_eliciting_in_flight(Space::Initial)), (1200, 0, 0));
        assert_eq!(r.timer(), Some(t0 + ms(5) + ms(999)));
    }

    #[test]
    fn a_retry_starts_everything_over() {
        let t0 = Instant::now();
        let mut r: Recovery<u64> = Recovery::new(MDS);
        r.on_packet_sent(t0, Space::Initial, sent(0, t0, true));
        r.on_timeout(t0 + ms(999));
        let gone = r.reset(Some(ms(40)));
        assert_eq!(pns(&gone), vec![0]);
        assert_eq!((r.bytes_in_flight(), r.pto_count(), r.timer()), (0, 0, None));
        assert_eq!((r.smoothed_rtt(), r.rttvar()), (ms(40), ms(20)));
        assert!(!r.has_rtt_sample());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // a model

    /// Packets sent, acknowledged in random orders and ranges, lost: whatever is acknowledged or lost, it is accounted exactly once,
    /// the bytes in flight match what is outstanding, and the counts of ack-eliciting packets match.
    #[test]
    fn the_accounting_adds_up_under_random_acknowledgments() {
        let mut seed = 0x1234abcd5678ef01u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..200 {
            let t0 = Instant::now();
            let mut r: Recovery<u64> = Recovery::new(MDS);
            r.on_handshake_confirmed(t0);
            let mut now = t0;
            let mut next_pn = 0u64;
            let mut settled: std::collections::BTreeSet<u64> = Default::default();
            for _ in 0..60 {
                now += ms(1 + next(30));
                match next(3) {
                    0 | 1 => {
                        let ae = next(4) != 0;
                        let size = 100 + next(1100) as usize;
                        let p = Sent { pn: next_pn, time: now, size, ack_eliciting: ae, in_flight: ae || next(5) == 0, payload: next_pn };
                        next_pn += 1;
                        r.on_packet_sent(now, Space::Application, p);
                    }
                    _ => {
                        if next_pn == 0 {
                            continue;
                        }
                        let a = next(next_pn);
                        let b = (a + next(6)).min(next_pn - 1);
                        let largest = b;
                        let out = r.on_ack_received(now, Space::Application, largest, ms(next(5)), std::iter::once(a..=b));
                        for p in out.acked.iter().chain(out.lost.iter()) {
                            assert!(settled.insert(p.pn), "round {round}: packet {} settled twice", p.pn);
                        }
                    }
                }
                if next(7) == 0 {
                    if let Some(t) = r.timer() {
                        now = now.max(t);
                        let out = r.on_timeout(now);
                        for p in &out.lost {
                            assert!(settled.insert(p.pn), "round {round}: packet {} settled twice", p.pn);
                        }
                    }
                }
                let out: Vec<_> = r.outstanding(Space::Application).collect();
                let bytes: usize = out.iter().filter(|p| p.in_flight).map(|p| p.size).sum();
                assert_eq!(r.bytes_in_flight(), bytes, "round {round}");
                let ae = out.iter().filter(|p| p.in_flight && p.ack_eliciting).count();
                assert_eq!(r.ack_eliciting_in_flight(Space::Application), ae, "round {round}");
                for p in &out {
                    assert!(!settled.contains(&p.pn));
                }
            }
        }
    }
}
