//! Statistical timing-leak detection in the style of dudect ("Dude, is my code constant time?",
//! Reparaz, Balasch and Verbauwhede, 2016), with no dependencies.
//!
//! Method: for a function `op(input)`, build two classes of inputs (typically "fixed" and
//! "random", or two structurally different fixed inputs). Time many calls, with the class of each
//! call chosen at random inside small balanced blocks, so that drift in the machine's state hits
//! both classes alike. Then run a paired t-test over the blocks, both on all samples and after
//! discarding the slowest samples at several percentiles (which are dominated by interrupts and
//! scheduling noise). A large |t| means the running time depends on the secret-controlled
//! difference between the classes. dudect's rule of thumb: |t| > 4.5 is suspicious and
//! |t| > 10 is a leak; a run below those numbers is evidence of absence, not proof of it.
//!
//! Which results fail a test: a comparison whose strongest |t| is above 4.5 is measured again with
//! fresh inputs, and it fails if the repeat is above 10 as well, or if the statistic that was strongest
//! on the first run (the uncropped one or one crop level) is above 4.5 again *with the same sign*, that is
//! with the same class slower again. Noise has no direction, so on top of having to reach 4.5 a second time
//! at one statistic fixed in advance it has to land on the same side, which is a coin toss; a difference
//! that depends on the input keeps its direction. The first run and the repeat are both printed.
//! `harness_does_not_fail_comparisons_of_identical_classes` measures the false-alarm rate against the
//! harness itself, the negative control that goes with the positive ones.
//!
//! The harness is validated by *positive controls*: functions that are known to leak (an
//! early-exit comparison, a ladder that does extra work for set scalar bits) must be flagged, so
//! that a clean result for the real code means the harness could have seen a leak.
//!
//! These tests are `#[ignore]`d because timing results depend on the machine and are too noisy for
//! an unattended build. Run them one at a time, in release mode, on a quiet machine:
//! `cargo test --release --lib crypto::timing::x25519 -- --ignored --nocapture` (and `ecdh`, `ghash`,
//! `poly1305`, `aead_and_mac`, `aes`, `harness`). Each takes 10 to 25 seconds;
//! `PRATIQUE_TIMING_SECS` (default 3) sets the time spent per comparison.
//! Coarse clocks: Apple Silicon's clock ticks every 41.67 ns (a 24 MHz counter, which is all that `Instant` can read there), so
//! an operation of 40 to 300 ns reads as one to seven ticks, and a difference of a percent is far below the tick. The first
//! run on an Apple M5 Max showed what that does: a control with a known 1.3% leak was not flagged, and two cheap operations
//! (a 42 ns GHASH, a 2.3 us SHA-256) were flagged at |t| of 12 to 35 on cropped views only, where the few distinct values
//! left make the variance collapse. The harness now detects a coarse clock (a good part of back-to-back readings equal) and
//! times a *batch* of calls of one class per sample, enough for the sample to span about twenty ticks; the report says how
//! many (`x3`), and its medians are per call (`PRATIQUE_TIMING_TICKS` sets the ticks per sample for a run). A fine clock (Linux, x86-64 and aarch64 alike) is not affected: one call per
//! sample, as before. `PRATIQUE_TIMING_TICK_NS=42` makes any machine read its clock as coarsely as that, which is how the
//! batching is tested here without an Apple machine, and `PRATIQUE_TIMING_REPS=1` forces one call per sample (to see
//! what the old harness would have said).
//!
//! Data-independent timing (BACKLOG B-99): on an Apple M5 the CPU itself made ECDH, SHA-256, AES key setup and GCM sealing
//! faster on zero-heavy inputs unless ARM's `DIT` bit was set, and the library now sets it around its secret work
//! (`crypto::dit`). The rows that call a public entry point (ECDH, X25519, the AEADs, HMAC) measure it as it is, with the
//! library's own guard; the rows that call a building block directly (GHASH, the Poly1305 backends) run it inside a guard
//! as the library does, since it only ever reaches them through those entry points. Plain SHA-256 is measured inside HMAC,
//! the only way the library hashes a secret; `dit_on_and_off` measures it bare, and everything with the library's guard
//! held off and on, which is the comparison to read on a CPU that has the mode.
//!
//! What this cannot see: cache-timing differences too small to move the clock on a quiet machine,
//! differences that only exist on other CPUs, and leaks smaller than the noise floor of the machine
//! it runs on. (The table-based AES this library used to have, backlog B-20, was such a case on
//! some machines and flagged reproducibly on others; its replacement has no tables at all.)

use super::chacha20poly1305::ChaCha20Poly1305;
use super::dit::{held_off, Dit};
use super::ecdh;
use super::ecdsa::Curve;
use super::aes::Backend;
use super::gcm::AesGcm;
use super::ghash::GhashKey;
use super::hmac::Hmac;
use super::poly1305::{limbs32, radix64};
use super::sha2::{Hash, Sha256};
use super::x25519;
use crate::fuzz::Rng;
use crate::util::ct_eq;
use std::hint::black_box;
use std::time::{Duration, Instant};

/// |t| above this is reported as a leak, and fails the test if the repeat is above it too.
const LEAK_T: f64 = 10.0;
/// |t| above this is reported as suspicious, is measured again, and fails the test if the same statistic is
/// above it again on the repeat with the same sign (see [`judge`]).
const SUSPICIOUS_T: f64 = 4.5;

pub(crate) struct Report {
    pub name: String,
    pub samples: usize,
    /// Calls timed together in each sample (1 on a fine clock; see the module documentation).
    pub reps: usize,
    pub uncropped_t: f64,
    pub max_t: f64,
    pub median_ns: u32,
    /// (percentile kept, t) for each crop level.
    pub crops: Vec<(f64, f64)>,
    /// (percentile kept, 1.0 for none; mean of class 1 minus class 0 per call in ns; its standard error), uncropped and at
    /// each crop level: the size of a difference, which t does not give (t also grows with the number of samples and
    /// shrinks with the noise of a slower operation).
    pub per_call: Vec<(f64, f64, f64)>,
}

/// The fraction of the samples (the fastest) that each cropped view keeps; the slow tail is interrupts and scheduling.
const CROP_LEVELS: [f64; 6] = [0.999, 0.99, 0.95, 0.9, 0.75, 0.5];

impl Report {
    /// Every t value of the run with its sign: the uncropped one, then one per crop level of `crops`. The sign
    /// says which class was slower (positive: class 1), and is the same for a real difference run after run.
    fn statistics(&self) -> impl Iterator<Item = f64> + '_ {
        std::iter::once(self.uncropped_t).chain(self.crops.iter().map(|c| c.1))
    }

    /// The statistic with the largest |t|: its place in [`Report::statistics`] and its signed value.
    fn peak(&self) -> (usize, f64) {
        let mut best = (0, self.uncropped_t);
        for (i, t) in self.statistics().enumerate() {
            if t.abs() > best.1.abs() {
                best = (i, t);
            }
        }
        best
    }

    /// "uncropped", or "p99.9" and so on, for the statistic at `index`.
    fn label(&self, index: usize) -> String {
        match index {
            0 => "uncropped".to_string(),
            i => self.crops.get(i - 1).map_or("?".to_string(), |(p, _)| format!("p{:.1}", p * 100.0)),
        }
    }

    /// The difference per call and its standard error at the crop level that keeps `p` of the samples (1.0: uncropped).
    fn per_call_at(&self, p: f64) -> (f64, f64) {
        self.per_call.iter().find(|c| (c.0 - p).abs() < 1e-9).map_or((f64::NAN, f64::NAN), |c| (c.1, c.2))
    }

    fn verdict(&self) -> &'static str {
        if self.max_t > LEAK_T {
            "LEAK"
        } else if self.max_t > SUSPICIOUS_T {
            "suspicious"
        } else {
            "no leak detected"
        }
    }
    fn print(&self) {
        let batch = if self.reps > 1 { format!(" x{}", self.reps) } else { String::new() };
        println!(
            "{:<58} n={:>7}{:<5} median {:>7} ns  |t| uncropped {:>6.1}  max {:>6.1}  {}",
            self.name,
            self.samples,
            batch,
            self.median_ns,
            self.uncropped_t.abs(),
            self.max_t,
            self.verdict()
        );
        if self.max_t > SUSPICIOUS_T {
            let crops: Vec<String> = self.crops.iter().map(|(p, t)| format!("p{:.1}:{:.1}", p * 100.0, t)).collect();
            println!("    t by crop level: {}", crops.join("  "));
        }
    }
}

/// Samples per block: eight of each class, in random order.
const BLOCK: usize = 16;

/// The mean of the per-block differences (class 1 minus class 0, in ns per sample) and its standard error, over the
/// same blocks as [`paired_t`], with samples slower than `cutoff` ignored.
fn paired_mean_se(samples: &[(u32, bool)], cutoff: u32) -> (f64, f64) {
    let mut diffs: Vec<f64> = Vec::with_capacity(samples.len() / BLOCK);
    for block in samples.chunks(BLOCK) {
        let (mut sum, mut n) = ([0f64; 2], [0f64; 2]);
        for &(d, class) in block {
            if d <= cutoff {
                sum[class as usize] += d as f64;
                n[class as usize] += 1.0;
            }
        }
        if n[0] > 0.0 && n[1] > 0.0 {
            diffs.push(sum[1] / n[1] - sum[0] / n[0]);
        }
    }
    let n = diffs.len() as f64;
    if n < 2.0 {
        return (f64::NAN, f64::NAN);
    }
    let mean = diffs.iter().sum::<f64>() / n;
    let var = diffs.iter().map(|d| (d - mean) * (d - mean)).sum::<f64>() / (n - 1.0);
    (mean, (var / n).sqrt())
}

/// Paired t statistic over blocks. Each block holds the same number of samples of both classes, so
/// slow drift in the machine's speed (frequency changes, a noisy neighbour) hits both classes
/// alike and cancels in the per-block difference of means. A plain two-sample test over all
/// samples would treat correlated noise as independent and report leaks that are not there.
/// Samples slower than `cutoff` nanoseconds are ignored.
fn paired_t(samples: &[(u32, bool)], cutoff: u32) -> f64 {
    let mut diffs: Vec<f64> = Vec::with_capacity(samples.len() / BLOCK);
    for block in samples.chunks(BLOCK) {
        let (mut sum, mut n) = ([0f64; 2], [0f64; 2]);
        for &(d, class) in block {
            if d <= cutoff {
                sum[class as usize] += d as f64;
                n[class as usize] += 1.0;
            }
        }
        if n[0] > 0.0 && n[1] > 0.0 {
            diffs.push(sum[1] / n[1] - sum[0] / n[0]);
        }
    }
    let n = diffs.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let mean = diffs.iter().sum::<f64>() / n;
    let var = diffs.iter().map(|d| (d - mean) * (d - mean)).sum::<f64>() / (n - 1.0);
    if var == 0.0 {
        // No spread at all. With a mean of zero that is no evidence of a difference; with any other mean it is
        // the strongest evidence there can be (every block shows the same offset, which a coarse clock makes
        // the normal case for a cheap operation), and must not be reported as "no leak".
        if mean == 0.0 {
            0.0
        } else {
            f64::INFINITY.copysign(mean)
        }
    } else {
        mean / (var / n).sqrt()
    }
}

const DEFAULT_SECS: f64 = 3.0;

// ------------------------------------------------------------------------------------------------ the clock

thread_local! {
    /// A tick to pretend the clock has, for the tests of the batching (see [`with_tick`]); the environment variable
    /// `PRATIQUE_TIMING_TICK_NS` does the same for a whole run.
    static TICK_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The clock the harness reads: nanoseconds since its creation, rounded down to a multiple of `tick` if that is more than one
/// (which is how a counter that ticks every `tick` ns reads, whatever the true time).
struct Clock {
    epoch: Instant,
    tick: u64,
}

impl Clock {
    fn new() -> Clock {
        let tick = TICK_OVERRIDE
            .with(|t| t.get())
            .or_else(|| std::env::var("PRATIQUE_TIMING_TICK_NS").ok().and_then(|v| v.trim().parse::<u64>().ok()))
            .unwrap_or(0);
        Clock { epoch: Instant::now(), tick }
    }

    #[inline]
    fn now(&self) -> u64 {
        let ns = self.epoch.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        if self.tick > 1 {
            ns / self.tick * self.tick
        } else {
            ns
        }
    }

    /// The tick of the clock if it is coarse: readings taken back to back are equal for a good part of the pairs (a fine
    /// clock hardly ever repeats, because the call to read it takes longer than its resolution), and the smallest step seen
    /// between two different readings is the tick. `None` for a fine clock.
    fn coarse_tick(&self) -> Option<u64> {
        let (mut equal, mut smallest) = (0u32, u64::MAX);
        const PAIRS: u32 = 20_000;
        for _ in 0..PAIRS {
            let a = self.now();
            let b = self.now();
            if a == b {
                equal += 1;
            } else {
                smallest = smallest.min(b - a);
            }
        }
        (equal > PAIRS / 10 && smallest != u64::MAX).then_some(smallest)
    }
}

/// Runs `f` with the harness reading its clock as if it ticked every `tick_ns`.
#[cfg(test)]
fn with_tick<T>(tick_ns: u64, f: impl FnOnce() -> T) -> T {
    let before = TICK_OVERRIDE.with(|t| t.replace(Some(tick_ns)));
    let r = f();
    TICK_OVERRIDE.with(|t| t.set(before));
    r
}

/// How many ticks of a coarse clock a sample spans (see [`reps_for`]); `PRATIQUE_TIMING_TICKS` sets another number for a run.
///
/// Twenty: enough for a sample's time to take many values (one call of one to seven ticks takes so few that the cropped views
/// collapse), and short enough that a sample seldom has an interrupt in it. On a virtual machine with a pretended tick, a hundred
/// ticks lost the 1.3% control (|t| 3.5) where twenty found it (|t| 27), and neither raised a false alarm on identical classes.
const TICKS_PER_SAMPLE: f64 = 20.0;

/// How many calls to time together so that a sample spans about [`TICKS_PER_SAMPLE`] ticks of a clock that ticks every `tick_ns`, for a
/// call that takes `cost_ns`. One call for a fine clock (`tick_ns` of 0), and never more than 4096.
fn reps_for(cost_ns: f64, tick_ns: u64) -> usize {
    if tick_ns <= 1 {
        return 1;
    }
    let ticks: f64 = std::env::var("PRATIQUE_TIMING_TICKS").ok().and_then(|v| v.trim().parse().ok()).filter(|&t: &f64| t >= 1.0).unwrap_or(TICKS_PER_SAMPLE);
    let want = ticks * tick_ns as f64 / cost_ns.max(1.0);
    (want.ceil() as usize).clamp(1, 4096)
}

/// The time budget from the text of `PRATIQUE_TIMING_SECS` (`None` if it is not set): seconds, 0 or more
/// (0 is the shortest run, one measured batch). Anything else is an `Err` saying so.
fn parse_budget(value: Option<&str>) -> Result<Duration, String> {
    let Some(text) = value else { return Ok(Duration::from_secs_f64(DEFAULT_SECS)) };
    text.trim()
        .parse::<f64>()
        .ok()
        .filter(|secs| secs.is_finite() && *secs >= 0.0)
        .and_then(|secs| Duration::try_from_secs_f64(secs).ok())
        .ok_or_else(|| format!("PRATIQUE_TIMING_SECS={text:?} is not a number of seconds (0 or more); using {DEFAULT_SECS}"))
}

fn budget() -> Duration {
    match parse_budget(std::env::var("PRATIQUE_TIMING_SECS").ok().as_deref()) {
        Ok(d) => d,
        Err(why) => {
            eprintln!("{why}");
            Duration::from_secs_f64(DEFAULT_SECS)
        }
    }
}

/// Times `op` on inputs from `gen(rng, class)` for `budget` and returns the statistics.
/// `gen` runs outside the timed region; `op`'s result is passed through `black_box`.
pub(crate) fn measure<I, R>(name: &str, budget: Duration, gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) -> Report {
    measure_seeded(name, budget, 0, gen, op)
}

/// [`measure`] with a chosen seed for the input generator, so that a repeat run sees fresh data.
fn measure_seeded<I, R>(
    name: &str,
    budget: Duration,
    seed: u64,
    mut gen: impl FnMut(&mut Rng, bool) -> I,
    op: impl Fn(&I) -> R,
) -> Report {
    const BATCH_BLOCKS: usize = 64;
    let mut rng = Rng::new(0xd0de_c7 ^ name.len() as u64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let clock = Clock::new();
    let forced: Option<usize> = std::env::var("PRATIQUE_TIMING_REPS").ok().and_then(|v| v.trim().parse().ok()).filter(|&n| n >= 1);
    // on a coarse clock, several calls of one class make a sample; how many is found by timing a few calls together
    let reps = match if forced.is_some() { None } else { clock.coarse_tick() } {
        None => forced.unwrap_or(1),
        Some(tick) => {
            let probe: Vec<I> = (0..64).map(|i| gen(&mut rng, i % 2 == 0)).collect();
            // the cost of a call: the median of nine rounds of at least twenty ticks each, so that an interrupt in one round (or
            // a cold start in the first) does not make the calls look dearer than they are
            let mut costs: Vec<f64> = (0..9)
                .map(|_| {
                    let mut calls = 0usize;
                    let t0 = clock.now();
                    while clock.now() - t0 < 20 * tick && calls < 1 << 22 {
                        for input in &probe {
                            black_box(op(black_box(input)));
                        }
                        calls += probe.len();
                    }
                    (clock.now() - t0) as f64 / calls as f64
                })
                .collect();
            costs.sort_by(|a, b| a.total_cmp(b));
            reps_for(costs[4], tick)
        }
    };
    let mut samples: Vec<(u32, bool)> = Vec::new();
    let start = Instant::now();
    let mut first = true;
    // the first batch only warms up, so a run is never over before one more has been measured
    while first || samples.is_empty() || start.elapsed() < budget {
        // balanced blocks: eight of each class per block, shuffled
        let mut classes: Vec<bool> = Vec::with_capacity(BATCH_BLOCKS * BLOCK);
        for _ in 0..BATCH_BLOCKS {
            let mut block: Vec<bool> = (0..BLOCK).map(|i| i < BLOCK / 2).collect();
            for i in (1..BLOCK).rev() {
                block.swap(i, rng.below(i + 1));
            }
            classes.extend(block);
        }
        // `reps` inputs of the class of each sample
        let inputs: Vec<Vec<I>> = classes.iter().map(|&c| (0..reps).map(|_| gen(&mut rng, c)).collect()).collect();
        for (&class, group) in classes.iter().zip(&inputs) {
            let t0 = clock.now();
            for input in group {
                black_box(op(black_box(input)));
            }
            let dt = (clock.now() - t0).min(u32::MAX as u64) as u32;
            // the first batch only warms caches, branch predictors and clocks up
            if !first {
                samples.push((dt, class));
            }
        }
        first = false;
    }
    let mut sorted: Vec<u32> = samples.iter().map(|s| s.0).collect();
    sorted.sort_unstable();
    let pct = |p: f64| if sorted.is_empty() { 0 } else { sorted[(((sorted.len() - 1) as f64) * p) as usize] };
    let uncropped_t = paired_t(&samples, u32::MAX);
    // dudect also crops the slow tail: interrupts and preemption add large, class-independent noise
    let mut max_t = uncropped_t.abs();
    let mut crops = Vec::new();
    for p in CROP_LEVELS {
        let t = paired_t(&samples, pct(p));
        crops.push((p, t));
        max_t = max_t.max(t.abs());
    }
    let per_call = std::iter::once((1.0, u32::MAX))
        .chain(CROP_LEVELS.iter().map(|&p| (p, pct(p))))
        .map(|(p, cutoff)| {
            let (m, se) = paired_mean_se(&samples, cutoff);
            (p, m / reps as f64, se / reps as f64)
        })
        .collect();
    Report { name: name.to_string(), samples: samples.len(), reps, uncropped_t, max_t, median_ns: pct(0.5) / reps as u32, crops, per_call }
}

thread_local! {
    /// Rows that stayed flagged on the repeat run; reported together by [`finish`].
    static FAILED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Whether a row that was flagged on its first run stays flagged on the repeat with fresh inputs, and
/// if so, why (the text that [`finish`] reports). There are two ways to stay flagged, and the second
/// only adds to the first:
///
/// * the strongest |t| of both runs is above [`LEAK_T`], whichever statistic and whichever sign;
/// * the first run's strongest statistic is above [`SUSPICIOUS_T`] and *that same statistic* is above
///   [`SUSPICIOUS_T`] again on the repeat, with the same sign (the same class slower again).
///
/// The second is a replication, not a second look at the maximum. The first run chose the statistic
/// out of seven, so a t value of 5 there is not much; the repeat then asks one question fixed in
/// advance (is it there again, in the same direction?), which noise answers yes to only rarely, because
/// its sign is a coin toss. A real difference in running time keeps its direction and its size.
fn judge(first: &Report, again: &Report) -> Option<String> {
    if first.max_t > LEAK_T && again.max_t > LEAK_T {
        return Some(format!("{}: |t| = {:.1} and {:.1} on two runs", first.name, first.max_t, again.max_t));
    }
    let (at, t) = first.peak();
    if t.abs() <= SUSPICIOUS_T {
        return None;
    }
    let repeat = again.statistics().nth(at)?;
    (repeat.abs() > SUSPICIOUS_T && repeat.signum() == t.signum()).then(|| {
        format!("{}: t = {:+.1} at {} and {:+.1} at the same statistic on a repeat with fresh inputs", first.name, t, first.label(at), repeat)
    })
}

/// Reports a comparison and records a failure if it is flagged twice in a row (see [`judge`]).
///
/// A real leak depends on the input, so it shows up again on a repeat with fresh data; a burst of
/// noise (another core waking up, a clock change) almost never does, and when a stretch of noise
/// does reach a t value above [`SUSPICIOUS_T`] its sign is as likely to be one as the other. The first
/// flagged run is printed too, so nothing is hidden. A failure does not stop the remaining rows from
/// running; call [`finish`] at the end of the test to fail it.
fn expect_constant_time<I, R>(name: &str, mut gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) {
    let r = measure(name, budget(), &mut gen, &op);
    r.print();
    if r.max_t <= SUSPICIOUS_T {
        return;
    }
    println!("    above {SUSPICIOUS_T}; measuring {:?} again with fresh inputs", name);
    let again = measure_seeded(name, budget(), 1, &mut gen, &op);
    again.print();
    match judge(&r, &again) {
        Some(why) => {
            println!("    came back: recorded as a failure");
            FAILED.with(|f| f.borrow_mut().push(why));
        }
        None => println!("    did not come back at the same statistic with the same sign: noise, not recorded"),
    }
}

/// Fails the test if any comparison since the last call stayed flagged on its repeat run.
fn finish() {
    let failed = FAILED.with(|f| std::mem::take(&mut *f.borrow_mut()));
    assert!(failed.is_empty(), "timing depends on the input:\n  {}", failed.join("\n  "));
}

/// Reports and requires that the leak WAS found (a positive control for the harness itself).
fn expect_leak<I, R>(name: &str, budget: Duration, gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) {
    let r = measure(name, budget, gen, op);
    r.print();
    assert!(
        r.max_t > LEAK_T,
        "{}: the harness did not notice a known leak (|t| = {:.1}); its results cannot be trusted on this machine",
        name,
        r.max_t
    );
}

fn rand32(rng: &mut Rng) -> [u8; 32] {
    rng.bytes(32).try_into().unwrap()
}

/// `n` random bytes for class 1, `n` bytes of `fill` for class 0, both made the same way (random bytes, then overwritten for
/// class 0). A class made with `vec![0; n]` is a calloc, which an allocator can hand over without writing it, while the other
/// was just written: the two then differ in where they are and in what the caches hold, and on an Apple M5 that alone was
/// flagged (SHA-256, GHASH and Poly1305 on zeros, the rows built that way, while the rows built like this were clean).
fn fixed_or_random(rng: &mut Rng, random: bool, n: usize, fill: u8) -> Vec<u8> {
    let mut v = rng.bytes(n);
    if !random {
        v.fill(fill);
    }
    v
}

// ------------------------------------------------------------------------ positive controls

/// The textbook mistake: stop at the first difference.
fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Two 4 KiB strings that differ at the first byte (class 0) or only at the last byte (class 1).
fn eq_pair(rng: &mut Rng, class: bool) -> (Vec<u8>, Vec<u8>) {
    let a = rng.bytes(4096);
    let mut b = a.clone();
    let at = if class { 4095 } else { 0 };
    b[at] ^= 0x80;
    (a, b)
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_flags_an_early_exit_comparison_and_passes_ct_eq() {
    expect_leak("control: early-exit comparison (must be flagged)", Duration::from_secs(2), eq_pair, |(a, b)| {
        leaky_eq(black_box(a), black_box(b))
    });
    expect_constant_time("util::ct_eq, mismatch at first vs last byte", eq_pair, |(a, b)| ct_eq(a, b));
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_flags_a_ladder_that_works_harder_for_set_scalar_bits() {
    // zero scalar (after clamping, almost no set bits) against random scalars
    let gen = |rng: &mut Rng, class: bool| -> ([u8; 32], [u8; 32]) {
        (if class { rand32(rng) } else { [0u8; 32] }, x25519::BASE_POINT)
    };
    expect_leak("control: x25519 with extra work per set bit (must be flagged)", Duration::from_secs(4), gen, |(k, u)| {
        x25519::x25519_leaky_control(k, u)
    });
}

// ----------------------------------------------------------------------------- the real code

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn x25519_is_constant_time() {
    let op = |(k, u): &([u8; 32], [u8; 32])| x25519::x25519(k, u);
    // few set bits against random scalars
    expect_constant_time(
        "x25519 scalar: all zero vs random",
        |rng, c| (if c { rand32(rng) } else { [0u8; 32] }, x25519::BASE_POINT),
        op,
    );
    // many set bits against few
    expect_constant_time(
        "x25519 scalar: all ones vs all zeros",
        |_, c| (if c { [0xffu8; 32] } else { [0u8; 32] }, x25519::BASE_POINT),
        op,
    );
    // fixed scalar, special points against random points
    let fixed_scalar = [0x5au8; 32];
    expect_constant_time(
        "x25519 point: u = 0, 1 or p-1 vs random (fixed scalar)",
        move |rng, c| {
            let u = if c {
                rand32(rng)
            } else {
                let mut u = [0u8; 32];
                match rng.below(3) {
                    0 => {}
                    1 => u[0] = 1,
                    _ => {
                        u = [0xff; 32];
                        u[0] = 0xec;
                        u[31] = 0x7f;
                    }
                }
                u
            };
            (fixed_scalar, u)
        },
        op,
    );
    finish();
}

/// Key generation goes through a table of multiples of the base point (`x25519_base`, B-103) rather than the ladder: the
/// scalar's digits pick the entries, so the classes are scalars whose digits are small and positive (the first entry of
/// each row), large and negative (the last entries, negated), zero, and random.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn x25519_key_generation_is_constant_time() {
    let op = |k: &[u8; 32]| x25519::public_key(k);
    expect_constant_time("x25519 key generation: scalar all zero vs random", |rng, c| if c { rand32(rng) } else { [0u8; 32] }, op);
    expect_constant_time("x25519 key generation: scalar all ones vs all zeros", |_, c| if c { [0xffu8; 32] } else { [0u8; 32] }, op);
    expect_constant_time(
        "x25519 key generation: digits +1 vs about -7 (first entries vs last, negated)",
        |_, c| if c { [0x88u8; 32] } else { [0x11u8; 32] },
        op,
    );
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn ecdh_on_p256_and_p384_is_constant_time() {
    for (curve, size) in [(Curve::P256, 32usize), (Curve::P384, 48)] {
        let label = if size == 32 { "p256" } else { "p384" };
        // 32 valid peer points, made outside the timed region
        let pool: Vec<Vec<u8>> = (0..32).map(|_| ecdh::generate(curve).unwrap().1).collect();
        let mut one = vec![0u8; size];
        one[size - 1] = 1;
        let generator = ecdh::public_key(curve, &one).unwrap();
        let random_scalar = move |rng: &mut Rng| -> Vec<u8> {
            loop {
                let k = rng.bytes(size);
                if ecdh::public_key(curve, &k).is_some() {
                    return k;
                }
            }
        };
        let op = move |(k, p): &(Vec<u8>, Vec<u8>)| ecdh::shared_secret(curve, k, p);
        let small = {
            let mut k = vec![0u8; size];
            k[size - 1] = 3;
            k
        };
        // few set bits and many leading zero bits against random scalars
        let (pool_a, small_a, rs) = (pool.clone(), small.clone(), random_scalar.clone());
        expect_constant_time(
            &format!("ecdh {label} scalar: 3 vs random"),
            move |rng, c| (if c { rs(rng) } else { small_a.clone() }, pool_a[rng.below(32)].clone()),
            op,
        );
        // a run of set bits against a run of zero bits (both in range)
        let pool_b = pool.clone();
        expect_constant_time(
            &format!("ecdh {label} scalar: 0x00ff..ff vs 0x7f00..00"),
            move |rng, c| {
                let mut k = vec![if c { 0x00 } else { 0x7f }; size];
                if c {
                    k[1..].fill(0xff);
                } else {
                    k[1..].fill(0);
                }
                (k, pool_b[rng.below(32)].clone())
            },
            op,
        );
        // fixed scalar: the generator against random points
        let fixed = random_scalar(&mut Rng::new(7));
        let pool_c = pool.clone();
        let generator_c = generator.clone();
        expect_constant_time(
            &format!("ecdh {label} peer: generator vs random point"),
            move |rng, c| (fixed.clone(), if c { pool_c[rng.below(32)].clone() } else { generator_c.clone() }),
            op,
        );
        // the public key of a secret scalar is also computed from it
        let (rs, small_b) = (random_scalar.clone(), small.clone());
        expect_constant_time(
            &format!("ecdh {label} public key: scalar 3 vs random"),
            move |rng, c| if c { rs(rng) } else { small_b.clone() },
            move |k: &Vec<u8>| ecdh::public_key(curve, k),
        );
    }
    finish();
}

/// The backends this machine can run: portable always, hardware where the CPU has it.
fn backends() -> Vec<Backend> {
    let mut v = vec![Backend::Portable];
    if super::aes_hw::available() {
        v.push(Backend::Hardware);
    }
    v
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn ghash_multiplication_is_constant_time() {
    // as the library runs it: only inside AES-GCM's entry points, which set data-independent timing
    let _dit = Dit::on();
    // eight blocks per call, so one call is well above the timer's resolution
    let rand128 = |rng: &mut Rng| rng.bytes(16);
    for backend in backends() {
        let fixed_h = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128.to_be_bytes();
        let blocks = |rng: &mut Rng, c: bool, fill: u8| -> Vec<u8> { fixed_or_random(rng, c, 128, fill) };
        let by_data = |(h, data): &([u8; 16], Vec<u8>)| GhashKey::new(h, backend).hash(b"aad", data);
        expect_constant_time(&format!("ghash [{backend:?}] data blocks: 0 vs random (fixed H)"), |rng, c| (fixed_h, blocks(rng, c, 0)), by_data);
        expect_constant_time(&format!("ghash [{backend:?}] data blocks: all ones vs random (fixed H)"), |rng, c| (fixed_h, blocks(rng, c, 0xff)), by_data);
        let data = vec![0x5au8; 128];
        let key = |rng: &mut Rng, c: bool, fill: u8| -> [u8; 16] { if c { rand128(rng).try_into().unwrap() } else { [fill; 16] } };
        expect_constant_time(&format!("ghash [{backend:?}] hash key H: 0 vs random"), |rng, c| (key(rng, c, 0), data.clone()), by_data);
        expect_constant_time(&format!("ghash [{backend:?}] hash key H: all ones vs random"), |rng, c| (key(rng, c, 0xff), data.clone()), by_data);
    }
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn poly1305_is_constant_time() {
    // 1 KiB messages (4 KiB for `blocks`); the key is the secret in the AEAD, the message is public but should not matter
    fn run64(k: &[u8; 32], m: &[u8]) -> [u8; 16] {
        let mut p = radix64::Poly1305::new(k);
        for c in m.chunks_exact(16) {
            p.block(c.try_into().unwrap(), true);
        }
        p.finish()
    }
    // the whole message at once: four blocks at a time with AVX2 on an x86-64 that has it (B-104), as the AEAD runs it
    fn run64_blocks(k: &[u8; 32], m: &[u8]) -> [u8; 16] {
        let mut p = radix64::Poly1305::new(k);
        p.blocks(m);
        p.finish()
    }
    fn run32(k: &[u8; 32], m: &[u8]) -> [u8; 16] {
        let mut p = limbs32::Poly1305::new(k);
        for c in m.chunks_exact(16) {
            p.block(c.try_into().unwrap(), true);
        }
        p.finish()
    }
    let fixed_key = [0x33u8; 32];
    // as the library runs it: only inside ChaCha20-Poly1305's entry points, which set data-independent timing
    let _dit = Dit::on();
    // (4 KiB for `blocks`, which takes the AVX2 path only from 2 KiB)
    let backends = [
        ("radix64 (2 x 64-bit)", run64 as fn(&[u8; 32], &[u8]) -> [u8; 16], 1024),
        ("radix64 blocks, 4 KiB (AVX2 where there is)", run64_blocks, 4096),
        ("limbs32 (5 x 26-bit)", run32, 1024),
    ];
    for (label, run, len) in backends {
        let fixed_msg = vec![0xa7u8; len];
        expect_constant_time(
            &format!("poly1305 {} key: zero vs random", label),
            |rng, c| (if c { rand32(rng) } else { [0u8; 32] }, fixed_msg.clone()),
            |(k, m)| run(k, m),
        );
        expect_constant_time(
            &format!("poly1305 {} key: all ones vs random", label),
            |rng, c| (if c { rand32(rng) } else { [0xffu8; 32] }, fixed_msg.clone()),
            |(k, m)| run(k, m),
        );
        expect_constant_time(
            &format!("poly1305 {} message: zeros vs random", label),
            |rng, c| (fixed_key, fixed_or_random(rng, c, len, 0)),
            |(k, m)| run(k, m),
        );
        expect_constant_time(
            &format!("poly1305 {} message: all ones vs random", label),
            |rng, c| (fixed_key, fixed_or_random(rng, c, len, 0xff)),
            |(k, m)| run(k, m),
        );
    }
    finish();
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn aead_and_mac_primitives_are_constant_time_in_their_data() {
    // end to end ChaCha20-Poly1305 and AES-GCM over 1 KiB: plaintext zeros / ones vs random
    let nonce = [9u8; 12];
    let cc = ChaCha20Poly1305::new(&[0x42u8; 32]);
    // Both classes are built the same way, and the zero class is overwritten afterwards. Building it with
    // `vec![0; 1024]` (a zeroed allocation) and the other with `rng.bytes` puts the buffers in different
    // places, and on an operation of 550 ns the harness sees that: |t| 5 to 11 on every run, same sign, on
    // the AES-GCM row below. The same lesson is in `aes_is_constant_time`, where it was learned first.
    // Each input is sealed in the buffer it was made in, before the clock started, and nothing else is timed. These rows
    // used to time a copy of the input as well: under macOS on an Apple M5 copying 1 KiB of random bytes is slower than
    // copying 1 KiB of zeros (|t| 15 to 35), which flagged the AES-GCM row there (`aes_gcm_seal_parts`, B-24).
    // Under macOS on the M5 the AES-GCM row may still be flagged: the one-pass seal itself takes about 0.1 ns longer per KiB
    // for random plaintext there (`aes_gcm_one_pass_against_two_passes`), a known residual (B-24).
    let sealed_n = |n: usize, c: bool, rng: &mut Rng| {
        let mut buf = rng.bytes(n);
        if !c {
            buf.fill(0);
        }
        buf.extend_from_slice(&[0u8; 16]);
        std::cell::RefCell::new(buf)
    };
    let sealed = |c: bool, rng: &mut Rng| sealed_n(1024, c, rng);
    expect_constant_time("chacha20-poly1305 seal 1 KiB: zeros vs random", |rng, c| sealed(c, rng), |cell| {
        let mut b = cell.borrow_mut();
        cc.seal_in_place(&nonce, b"aad", &mut b);
        b[b.len() - 1]
    });
    expect_constant_time("chacha20-poly1305 key setup + seal 64 B: zero key vs random", |rng, c| fixed_or_random(rng, c, 32, 0), |key| {
        let c = ChaCha20Poly1305::new(key);
        let mut b = vec![0u8; 64 + 16];
        c.seal_in_place(&nonce, b"", &mut b);
        b
    });
    let gcm = AesGcm::new(&[0x42u8; 16]);
    expect_constant_time("aes-128-gcm seal 1 KiB: zeros vs random", |rng, c| sealed(c, rng), |cell| {
        let mut b = cell.borrow_mut();
        gcm.seal_in_place(&nonce, b"aad", &mut b);
        b[b.len() - 1]
    });
    // 100 bytes: six whole blocks and a partial one, the path of a message's last 127 bytes or fewer (B-103)
    expect_constant_time("aes-128-gcm seal 100 B: zeros vs random", |rng, c| sealed_n(100, c, rng), |cell| {
        let mut b = cell.borrow_mut();
        gcm.seal_in_place(&nonce, b"aad", &mut b);
        b[b.len() - 1]
    });
    // HMAC-SHA-256 and SHA-256: key / message bytes
    expect_constant_time("hmac-sha256 key: zero vs random (1 KiB message)", |rng, c| fixed_or_random(rng, c, 32, 0), |key| {
        let mut h = Hmac::<Sha256>::new(key);
        h.update(&[0x5au8; 1024]);
        h.finalize()
    });
    // SHA-256 over secret bytes, as the library does it: as HMAC's message (HKDF-Extract's input keying material is one).
    // Bare SHA-256, which the library uses on public data only, is in `dit_on_and_off`.
    expect_constant_time("hmac-sha256 message: zeros vs random (1 KiB)", |rng, c| fixed_or_random(rng, c, 1024, 0), |m| Hmac::<Sha256>::mac(&[0x5au8; 32], m));
    finish();
}

/// Where the time of `aead_and_mac`'s AES-GCM row goes (report only). That row used to time a new buffer, the copy of the input
/// into it, the seal and the buffer's release together; on an Apple M5 Max under macOS it read random plaintext as slower than
/// zeros in most runs (|t| 5 to 11), and not once in five runs in a Linux VM on the same CPU. The first run of this test there
/// put it in the copy: copying 1 KiB of random bytes was slower than copying 1 KiB of zeros (|t| 20 to 33 at every crop level,
/// with or without a new buffer), and the seal rows showed it only as far as they contained the copy. Each piece is timed here
/// on its own, twice with fresh inputs; "seal only" seals each input in the buffer it was made in, so nothing but the seal is
/// timed. The second run there: the 1 KiB seal alone reads random as slower too, if much less than the copy (|t| 5.6 and 9.2,
/// at every crop level), while reading 1 KiB is clean, copying a fixed pattern is as fast as copying zeros, and the copy and
/// the seal of 16 KiB are clean. The last rows ask whether that is the cipher or the writes it makes over its input: the
/// same writes with no cipher (fixed bytes written over the input, and an XOR in place with a fixed key stream), and the
/// opposite direction (opening in place, which writes zeros or random bytes over random ones). The third run: those are all
/// clean, and the 1 KiB seal alone flags again (5.7 and 7.0). Plaintext only goes through loads, an XOR and stores in the
/// one-pass kernel, so the rows after it ask whether this is B-85's code at all: the same seal by the two steps that came
/// before it, and ChaCha20-Poly1305's.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn aes_gcm_seal_parts() {
    use std::cell::RefCell;
    let nonce = [9u8; 12];
    let gcm = AesGcm::new(&[0x42u8; 16]);
    println!("\nAES-GCM backend: {:?}; each row twice, t > 0 means the random class is slower (report only)", gcm.backend());
    // n bytes of `fill` (or random ones), and 16 bytes of room for the tag
    let made = |n: usize, fill: u8| move |rng: &mut Rng, c: bool| -> Vec<u8> {
        let mut buf = rng.bytes(n);
        if !c {
            buf.fill(fill);
        }
        buf.extend_from_slice(&[0u8; 16]);
        buf
    };
    let in_cell = |n: usize| move |rng: &mut Rng, c: bool| RefCell::new(made(n, 0)(rng, c));
    let reused = RefCell::new(vec![0u8; 16 * 1024 + 16]);
    let copy_into_reused = |buf: &Vec<u8>| {
        let mut r = reused.borrow_mut();
        let b = &mut r[..buf.len()];
        b.copy_from_slice(buf);
        b[b.len() - 1]
    };
    let mut table: Vec<(&str, Vec<Report>)> = Vec::new();
    let mut row = |name: &'static str, run: &mut dyn FnMut(&str, u64) -> Report| {
        let runs: Vec<Report> = (0..2u64)
            .map(|seed| {
                let r = run(name, seed);
                r.print();
                r
            })
            .collect();
        table.push((name, runs));
    };
    row("1 KiB: new buffer, copy, seal, free (the old aead row)", &mut |name, seed| {
        measure_seeded(name, budget(), seed, made(1024, 0), |buf: &Vec<u8>| {
            let mut b = buf.clone();
            gcm.seal_in_place(&nonce, b"aad", &mut b);
            b
        })
    });
    row("1 KiB: new buffer, copy, free (no seal)", &mut |name, seed| measure_seeded(name, budget(), seed, made(1024, 0), |buf: &Vec<u8>| buf.clone()));
    row("1 KiB: copy into a reused buffer (no seal)", &mut |name, seed| measure_seeded(name, budget(), seed, made(1024, 0), copy_into_reused));
    // the seal and nothing else: each input is sealed where it was made, once (the inputs are made before the clock starts)
    row("1 KiB: seal only", &mut |name, seed| {
        measure_seeded(name, budget(), seed, in_cell(1024), |cell: &RefCell<Vec<u8>>| {
            let mut b = cell.borrow_mut();
            gcm.seal_in_place(&nonce, b"aad", &mut b);
            b[b.len() - 1]
        })
    });
    // the same seal by other code: the two steps the hardware path took before B-85 (CTR, then GHASH), and another AEAD
    row("1 KiB: seal only, two passes (the code before B-85)", &mut |name, seed| {
        measure_seeded(name, budget(), seed, in_cell(1024), |cell: &RefCell<Vec<u8>>| {
            let mut b = cell.borrow_mut();
            gcm.seal_in_place_two_passes(&nonce, b"aad", &mut b);
            b[b.len() - 1]
        })
    });
    let chacha = ChaCha20Poly1305::new(&[0x42u8; 32]);
    row("1 KiB: ChaCha20-Poly1305 seal only", &mut |name, seed| {
        measure_seeded(name, budget(), seed, in_cell(1024), |cell: &RefCell<Vec<u8>>| {
            let mut b = cell.borrow_mut();
            chacha.seal_in_place(&nonce, b"aad", &mut b);
            b[b.len() - 1]
        })
    });
    row("16 KiB: seal only", &mut |name, seed| {
        measure_seeded(name, budget(), seed, in_cell(16 * 1024), |cell: &RefCell<Vec<u8>>| {
            let mut b = cell.borrow_mut();
            gcm.seal_in_place(&nonce, b"aad", &mut b);
            b[b.len() - 1]
        })
    });
    // what kind of effect the copy's is
    row("16 KiB: copy into a reused buffer (no seal)", &mut |name, seed| measure_seeded(name, budget(), seed, made(16 * 1024, 0), copy_into_reused));
    row("1 KiB: read only (XOR of its words)", &mut |name, seed| {
        measure_seeded(name, budget(), seed, made(1024, 0), |buf: &Vec<u8>| {
            buf.chunks_exact(8).fold(0u64, |a, w| a ^ u64::from_le_bytes(w.try_into().unwrap()))
        })
    });
    row("1 KiB: copy, a fixed pattern (0x5a) vs random", &mut |name, seed| measure_seeded(name, budget(), seed, made(1024, 0x5a), copy_into_reused));
    // the writes the seal makes over its input, with no cipher: fixed bytes written over it, and an XOR in place with a fixed
    // key stream (read it, change it, write it back, as CTR does)
    let stream: Vec<u8> = Rng::new(0x5eed).bytes(1024);
    row("1 KiB: fixed bytes written over it (no cipher)", &mut |name, seed| {
        measure_seeded(name, budget(), seed, in_cell(1024), |cell: &RefCell<Vec<u8>>| {
            let mut b = cell.borrow_mut();
            b[..1024].copy_from_slice(&stream);
            b[0]
        })
    });
    row("1 KiB: XOR in place with a fixed stream (no cipher)", &mut |name, seed| {
        measure_seeded(name, budget(), seed, in_cell(1024), |cell: &RefCell<Vec<u8>>| {
            let mut b = cell.borrow_mut();
            for (d, k) in b[..1024].iter_mut().zip(&stream) {
                *d ^= k;
            }
            b[0]
        })
    });
    // the other direction: each input is sealed before the clock starts and opened in place, which writes zeros or random
    // plaintext over random ciphertext
    row("1 KiB: open only (zeros or random come out)", &mut |name, seed| {
        measure_seeded(
            name,
            budget(),
            seed,
            |rng: &mut Rng, c: bool| {
                let mut b = made(1024, 0)(rng, c);
                gcm.seal_in_place(&nonce, b"aad", &mut b);
                RefCell::new(b)
            },
            |cell: &RefCell<Vec<u8>>| {
                let mut b = cell.borrow_mut();
                gcm.open_in_place(&nonce, b"aad", &mut b)
            },
        )
    });
    println!("\nt at p50 / p90 / p99 and the largest |t|, two runs each (|t| above {SUSPICIOUS_T} is suspicious, above {LEAK_T} reads as a leak):");
    for (name, runs) in &table {
        let cells: Vec<String> = runs
            .iter()
            .map(|r| {
                let at = |p: f64| r.crops.iter().find(|(q, _)| (q - p).abs() < 1e-9).map_or(f64::NAN, |c| c.1);
                format!("{:+5.1} {:+5.1} {:+5.1} |{:4.1}|", at(0.5), at(0.9), at(0.99), r.max_t)
            })
            .collect();
        println!("  {name:<54} {}", cells.join("   "));
    }
}

/// The 1 KiB seal by the one-pass kernel as it is now (hashing each group's ciphertext from registers), by the one-pass
/// kernel as it was from B-85 until this test (reading each group back from memory to hash it), and by the two steps that
/// came before B-85 (CTR, then GHASH), alternated over several rounds, as a difference per call in nanoseconds (random
/// minus zeros) with two standard errors, pooled over the rounds (report only). A t value alone cannot compare them: the
/// two-pass seal takes about 3.5 times as long, so the same difference gives it a smaller t. Under macOS on an Apple M5 the
/// read-back kernel measured +0.077 ns +/- 0.010 at p99 (six rounds, all positive) and the two-pass code +0.015 +/- 0.012.
/// The next run, with the kernel that hashes from registers: +0.113 +/- 0.011, against +0.206 +/- 0.012 for the read-back
/// kernel and -0.001 +/- 0.014 for the two-pass code. Half, not none: the rest is kept as a known macOS residual (B-24).
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn aes_gcm_one_pass_against_two_passes() {
    use std::cell::RefCell;
    const ROUNDS: u64 = 6;
    let nonce = [9u8; 12];
    let gcm = AesGcm::new(&[0x42u8; 16]);
    let long = budget() * 3;
    println!(
        "\nAES-GCM backend: {:?}; {ROUNDS} rounds of {:.0} s for each; per call, random minus zeros (report only)",
        gcm.backend(),
        long.as_secs_f64()
    );
    let made = |rng: &mut Rng, c: bool| {
        let mut buf = rng.bytes(1024);
        if !c {
            buf.fill(0);
        }
        buf.extend_from_slice(&[0u8; 16]);
        RefCell::new(buf)
    };
    const NAMES: [&str; 3] = ["1 KiB seal, one pass, registers (now)", "1 KiB seal, one pass, read back (B-85)", "1 KiB seal, two passes (before B-85)"];
    let mut runs: [Vec<Report>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for round in 0..ROUNDS {
        for (i, name) in NAMES.iter().enumerate() {
            let r = match i {
                0 => measure_seeded(name, long, round, made, |cell: &RefCell<Vec<u8>>| {
                    let mut b = cell.borrow_mut();
                    gcm.seal_in_place(&nonce, b"aad", &mut b);
                    b[b.len() - 1]
                }),
                1 => measure_seeded(name, long, round, made, |cell: &RefCell<Vec<u8>>| {
                    let mut b = cell.borrow_mut();
                    gcm.seal_in_place_by_reload(&nonce, b"aad", &mut b);
                    b[b.len() - 1]
                }),
                _ => measure_seeded(name, long, round, made, |cell: &RefCell<Vec<u8>>| {
                    let mut b = cell.borrow_mut();
                    gcm.seal_in_place_two_passes(&nonce, b"aad", &mut b);
                    b[b.len() - 1]
                }),
            };
            r.print();
            let (m, se) = r.per_call_at(0.99);
            println!("    per call at p99: {m:+.3} ns +/- {:.3} (two standard errors)", 2.0 * se);
            runs[i].push(r);
        }
    }
    // each round weighted by its precision (1 / se^2)
    let pooled = |rs: &[Report], p: f64| -> (f64, f64) {
        let (mut w, mut wm) = (0.0, 0.0);
        for r in rs {
            let (m, se) = r.per_call_at(p);
            if m.is_finite() && se.is_finite() && se > 0.0 {
                w += 1.0 / (se * se);
                wm += m / (se * se);
            }
        }
        if w == 0.0 {
            (f64::NAN, f64::NAN)
        } else {
            (wm / w, (1.0 / w).sqrt())
        }
    };
    println!("\npooled over {ROUNDS} rounds, per call in ns, random minus zeros, +/- two standard errors (and the median time of a call):");
    println!("  {:<40} {:>27} {:>27} {:>27} {:>8}", "", "uncropped", "p99", "p90", "median");
    for (i, name) in NAMES.iter().enumerate() {
        let cell = |p: f64| {
            let (m, se) = pooled(&runs[i], p);
            format!("{m:+8.3} +/- {:.3} ({:+5.1}se)", 2.0 * se, m / se)
        };
        let mut medians: Vec<u32> = runs[i].iter().map(|r| r.median_ns).collect();
        medians.sort_unstable();
        println!("  {name:<40} {:>27} {:>27} {:>27} {:>5} ns", cell(1.0), cell(0.99), cell(0.9), medians[medians.len() / 2]);
    }
}

#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_detects_a_difference_of_about_one_percent() {
    one_percent_control();
}

/// The same control with a clock that ticks every 41.67 ns, as Apple Silicon's does: without batching the calls it was not
/// flagged on an Apple M5 Max (|t| 8.1 at best), because a tick is more than ten times the difference.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_detects_a_difference_of_about_one_percent_on_a_coarse_clock() {
    with_tick(test_tick(), one_percent_control);
}

fn one_percent_control() {
    // sensitivity: class 1 does ten extra dependent multiplications (about 9 ns) on an operation
    // that takes about 680 ns. A harness that cannot see that would give clean results for
    // leaks of that size too.
    fn delay(n: u32) -> u64 {
        let mut x = 0x9e37_79b9u64;
        for _ in 0..n {
            x = black_box(x.wrapping_mul(0x2545_f491_4f6c_dd1d).wrapping_add(1));
        }
        x
    }
    let key = [0x33u8; 32];
    expect_leak("control: poly1305 1 KiB, one class ~1.3% slower", Duration::from_secs(3), |rng, c| (c, rng.bytes(1024)), |(c, m)| {
        let mut p = radix64::Poly1305::new(&key);
        for ch in m.chunks_exact(16) {
            p.block(ch.try_into().unwrap(), true);
        }
        let tag = p.finish();
        if *c {
            black_box(delay(10));
        }
        tag
    });
}

#[test]
#[should_panic(expected = "timing depends on the input")]
fn finish_fails_when_a_row_stayed_flagged() {
    FAILED.with(|f| f.borrow_mut().push("example row".to_string()));
    finish();
}

/// AES with a secret key and secret data, on every backend this machine has. The cipher used to
/// index an S-box table with key-dependent bytes (backlog B-20), which one x86-64 host flagged
/// reproducibly (|t| 17 to 69) and the Apple M5 Max did not; the bitsliced and hardware
/// implementations have no such lookups, so unlike before, this is expected to stay clean.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn aes_is_constant_time() {
    let nonce = [9u8; 12];
    for backend in backends() {
        for key_len in [16usize, 32] {
            for (what, fill) in [("zero", 0u8), ("all-ones", 0xff)] {
                expect_constant_time(
                    &format!("aes-{}-gcm [{backend:?}] key setup + seal 64 B: {what} key vs random", key_len * 8),
                    |rng, c| fixed_or_random(rng, c, key_len, fill),
                    |key| {
                        let g = AesGcm::with_backend(key, backend);
                        let mut b = vec![0u8; 64 + 16];
                        g.seal_in_place(&nonce, b"", &mut b);
                        b
                    },
                );
            }
        }
        // a message of at most 48 bytes, which the portable cipher encrypts with J0 in one pass: the key, and the plaintext
        let short_key = AesGcm::with_backend(&[0x6bu8; 16], backend);
        expect_constant_time(&format!("aes-128-gcm [{backend:?}] key setup + seal 32 B: zero key vs random"), |rng, c| fixed_or_random(rng, c, 16, 0), |key| {
            let g = AesGcm::with_backend(key, backend);
            let mut b = vec![0u8; 32 + 16];
            g.seal_in_place(&nonce, b"", &mut b);
            b
        });
        expect_constant_time(&format!("aes-128-gcm [{backend:?}] seal 32 B: zeros vs random"), |rng, c| fixed_or_random(rng, c, 48, 0), |buf| {
            let mut b = buf.clone();
            short_key.seal_in_place(&nonce, b"", &mut b);
            b
        });
        // a fixed key, secret plaintext of 1 KiB (CTR keystream and GHASH over the ciphertext).
        // Both classes are built the same way and only then overwritten: filling one class with
        // `vec![0; n]` (a calloc) and the other by pushing bytes puts the buffers at different
        // addresses, and at under a microsecond per call the harness sees that (|t| 5 to 7) even
        // though no byte of the data is ever branched on.
        let g = AesGcm::with_backend(&[0x6bu8; 16], backend);
        for (what, fill) in [("zeros", 0u8), ("all-ones", 0xff)] {
            expect_constant_time(
                &format!("aes-128-gcm [{backend:?}] seal 1 KiB: {what} vs random"),
                |rng, c| {
                    let mut v = rng.bytes(1024);
                    if !c {
                        v.fill(fill);
                    }
                    v
                },
                |pt| g.seal(&nonce, b"aad", pt),
            );
        }
    }
    finish();
}

// ------------------------------------------------------------------------ the harness's own arithmetic

/// `blocks` blocks of eight samples of each class, class 0 taking `a` ns and class 1 taking `b(block)` ns.
fn blocks_of(blocks: usize, a: u32, b: impl Fn(usize) -> u32) -> Vec<(u32, bool)> {
    let mut v = Vec::new();
    for k in 0..blocks {
        for i in 0..BLOCK {
            let class = i % 2 == 1;
            v.push((if class { b(k) } else { a }, class));
        }
    }
    v
}

#[test]
fn a_difference_with_no_spread_is_the_strongest_evidence_not_none() {
    // class 1 is exactly 1 ns slower in every block: the old code answered 0 ("no leak detected")
    let t = paired_t(&blocks_of(200, 100, |_| 101), u32::MAX);
    assert_eq!(t, f64::INFINITY);
    assert_eq!(paired_t(&blocks_of(200, 101, |_| 100), u32::MAX), f64::NEG_INFINITY);
    // no difference and no spread is no evidence
    assert_eq!(paired_t(&blocks_of(200, 100, |_| 100), u32::MAX), 0.0);
    // the same offset with some spread was always found
    let t = paired_t(&blocks_of(200, 100, |k| 101 + (k % 3) as u32), u32::MAX);
    assert!(t.is_finite() && t > 10.0, "{t}");
    // and a report built on an infinite t says LEAK, in both signs
    let r = Report { name: "x".into(), samples: 0, reps: 1, uncropped_t: f64::INFINITY, max_t: f64::INFINITY, median_ns: 0, crops: vec![], per_call: vec![] };
    assert_eq!(r.verdict(), "LEAK");
    r.print();
}

#[test]
fn the_time_budget_is_read_with_care() {
    assert_eq!(parse_budget(None), Ok(Duration::from_secs(3)));
    assert_eq!(parse_budget(Some("0.5")), Ok(Duration::from_millis(500)));
    assert_eq!(parse_budget(Some(" 12 ")), Ok(Duration::from_secs(12)));
    assert_eq!(parse_budget(Some("0")), Ok(Duration::ZERO));
    // these panicked (a negative or enormous number in `Duration::from_secs_f64`) or were silently the default
    for bad in ["-1", "-0.001", "abc", "", "NaN", "inf", "1e300"] {
        let why = parse_budget(Some(bad)).unwrap_err();
        assert!(why.contains("PRATIQUE_TIMING_SECS"), "{bad}: {why}");
    }
}

#[test]
fn a_budget_of_zero_still_measures_something() {
    // it used to be one batch, the warm-up one, which is thrown away, and then an empty sample set to index into
    let r = measure("zero budget", Duration::ZERO, |rng, _| rng.next_u64(), |x| x.wrapping_mul(3));
    assert!(r.samples >= BLOCK, "{}", r.samples);
    assert!(r.max_t.is_finite() || r.max_t.is_infinite());
}

/// A report holding the given signed t values (the uncropped one, then one per crop level), as `measure_seeded` builds it.
fn report(ts: [f64; 7]) -> Report {
    let crops: Vec<(f64, f64)> = CROP_LEVELS.iter().copied().zip(ts[1..].iter().copied()).collect();
    let max_t = ts.iter().fold(0f64, |m, t| m.max(t.abs()));
    Report { name: "row".into(), samples: 1000, reps: 1, uncropped_t: ts[0], max_t, median_ns: 100, crops, per_call: vec![] }
}

const QUIET: [f64; 7] = [0.5, -1.0, 0.3, 0.8, -0.2, 1.1, 0.4];

/// `QUIET` with `t` at statistic `at` (0 is the uncropped one).
fn with(at: usize, t: f64) -> [f64; 7] {
    let mut ts = QUIET;
    ts[at] = t;
    ts
}

#[test]
fn a_flagged_row_fails_when_its_statistic_comes_back_with_the_same_sign() {
    // the first run peaks at p95 (index 3) with +6: suspicious, not a leak
    let first = report(with(3, 6.0));
    assert_eq!(first.peak(), (3, 6.0));
    assert_eq!(first.label(3), "p95.0");
    assert_eq!(first.label(0), "uncropped");
    assert_eq!(first.label(6), "p50.0");
    assert_eq!(first.verdict(), "suspicious");

    // the same statistic, the same direction, above 4.5 again: a real difference
    let why = judge(&first, &report(with(3, 5.0))).expect("a difference that came back");
    assert!(why.contains("p95.0") && why.contains("+6.0") && why.contains("+5.0"), "{why}");
    // the other direction (class 1 faster this time) is what noise does half of the time
    assert_eq!(judge(&first, &report(with(3, -5.5))), None);
    assert_eq!(judge(&first, &report(with(3, -50.0))), None);
    // below 4.5 at that statistic, however loud another statistic is
    assert_eq!(judge(&first, &report(with(3, 4.4))), None);
    assert_eq!(judge(&first, &report(with(6, 7.0))), None);
    assert_eq!(judge(&first, &report(QUIET)), None);
    // a negative first run is judged the same way round
    let slower_first = report(with(2, -6.0));
    assert!(judge(&slower_first, &report(with(2, -4.6))).is_some());
    assert_eq!(judge(&slower_first, &report(with(2, 4.6))), None);
}

#[test]
fn the_old_rule_still_holds_and_the_new_one_only_adds_to_it() {
    // above 10 on both runs fails whichever statistic or sign it is: nothing that failed before passes now
    let first = report(with(2, 12.0));
    let why = judge(&first, &report(with(5, -11.0))).expect("two runs above 10");
    assert!(why.contains("on two runs"), "{why}");
    assert!(judge(&first, &report(with(2, 11.0))).is_some());
    // above 10 once and between 4.5 and 10 at the same statistic the second time: this is new, and fails
    let why = judge(&first, &report(with(2, 7.0))).expect("a replicated leak");
    assert!(why.contains("p99.0"), "{why}");
    // above 10 once and quiet the second time is a burst of noise, as before
    assert_eq!(judge(&first, &report(QUIET)), None);
    assert_eq!(judge(&first, &report(with(2, 4.0))), None);
    // a quiet first run is never held against the row
    assert_eq!(judge(&report(with(4, 4.0)), &report(with(4, 40.0))), None);
    // the coarse clock: every block offset by the same amount is an infinite t, in either direction
    let inf = report(with(0, f64::INFINITY));
    assert!(judge(&inf, &report(with(0, f64::INFINITY))).is_some());
    assert!(judge(&inf, &report(with(0, f64::NEG_INFINITY))).is_some());
    assert_eq!(judge(&inf, &report(QUIET)), None);
}

#[test]
fn a_report_with_fewer_statistics_than_expected_is_judged_not_crashed_on() {
    let bare = |t: f64| Report { name: "bare".into(), samples: 0, reps: 1, uncropped_t: t, max_t: t.abs(), median_ns: 0, crops: vec![], per_call: vec![] };
    assert_eq!(bare(6.0).peak(), (0, 6.0));
    assert_eq!(bare(6.0).label(0), "uncropped");
    assert_eq!(bare(6.0).label(3), "?");
    assert!(judge(&bare(6.0), &bare(5.0)).is_some());
    assert_eq!(judge(&bare(6.0), &bare(-5.0)), None);
    // the first run peaked at a crop level the repeat does not have
    assert_eq!(judge(&report(with(3, 6.0)), &bare(9.0)), None);
}

// ------------------------------------------------------------------------ the false-alarm rate

/// The time for each run of the negative control: `PRATIQUE_TIMING_SECS` if it is set, else half a second, so
/// that the default run (ten pairs of three operations) takes about half a minute and not a quarter of an hour.
fn null_budget() -> Duration {
    if std::env::var_os("PRATIQUE_TIMING_SECS").is_some() {
        budget()
    } else {
        Duration::from_millis(500)
    }
}

/// What [`false_alarms`] counted.
#[derive(Default)]
struct Tally {
    /// first runs whose strongest |t| was above [`SUSPICIOUS_T`], and above [`LEAK_T`]
    above_suspicious: usize,
    above_leak: usize,
    /// pairs that the old rule (above [`LEAK_T`] twice) and the new one ([`judge`]) would have failed
    old_rule: usize,
    new_rule: usize,
    /// the strongest |t| of any run
    largest_t: f64,
}

/// Measures `pairs` first runs and repeats of a comparison whose two classes are the same kind of input,
/// so that every difference the harness finds is noise, and counts what each rule would have done.
fn false_alarms<I, R>(name: &str, pairs: usize, mut gen: impl FnMut(&mut Rng, bool) -> I, op: impl Fn(&I) -> R) -> Tally {
    let mut tally = Tally::default();
    for k in 0..pairs {
        let first = measure_seeded(name, null_budget(), 2 * k as u64, &mut gen, &op);
        let again = measure_seeded(name, null_budget(), 2 * k as u64 + 1, &mut gen, &op);
        tally.above_suspicious += (first.max_t > SUSPICIOUS_T) as usize;
        tally.above_leak += (first.max_t > LEAK_T) as usize;
        tally.old_rule += (first.max_t > LEAK_T && again.max_t > LEAK_T) as usize;
        tally.largest_t = tally.largest_t.max(first.max_t).max(again.max_t);
        if let Some(why) = judge(&first, &again) {
            tally.new_rule += 1;
            println!("    new rule failed a pair of identical classes: {why}");
        }
    }
    tally
}

/// The negative control: the repeat rule must not fail comparisons that have nothing to find. Three operations
/// of very different length (the short one runs close to the clock's resolution, where noise is worst), each
/// compared with itself. `PRATIQUE_NULL_PAIRS` (default 10) sets the number of first-run and repeat pairs per
/// operation, `PRATIQUE_TIMING_SECS` the time of each run (default here 0.5).
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_does_not_fail_comparisons_of_identical_classes() {
    let pairs: usize = std::env::var("PRATIQUE_NULL_PAIRS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(10);
    let mut new_rule_failures = 0;
    let mut report_row = |what: &str, c: Tally| {
        println!(
            "{what:<46} {pairs} pairs: first run above {SUSPICIOUS_T}: {:>2}, above {LEAK_T}: {:>2}; failed by the old rule: {:>2}, by the new rule: {:>2}; largest |t| of any run {:.1}",
            c.above_suspicious, c.above_leak, c.old_rule, c.new_rule, c.largest_t
        );
        new_rule_failures += c.new_rule;
    };
    report_row("x25519, random scalar (about 100 us)", false_alarms("null x25519", pairs, |rng, _| (rand32(rng), x25519::BASE_POINT), |(k, u)| x25519::x25519(k, u)));
    report_row("sha256, 1 KiB of random bytes (a few us)", false_alarms("null sha256", pairs, |rng, _| rng.bytes(1024), |m| Sha256::digest(m)));
    report_row("ct_eq, 32 equal random bytes (tens of ns)", false_alarms("null ct_eq", pairs, |rng, _| { let a = rng.bytes(32); (a.clone(), a) }, |(a, b)| ct_eq(a, b)));
    assert_eq!(new_rule_failures, 0, "the repeat rule failed comparisons of identical classes");
}

// ---------------------------------------------------------------------------------------------- coarse clocks

#[test]
fn the_number_of_calls_per_sample_follows_the_cost_and_the_tick() {
    // a fine clock (or none): one call
    assert_eq!(reps_for(500.0, 0), 1);
    assert_eq!(reps_for(500.0, 1), 1);
    // twenty ticks of 41 ns are 820 ns
    assert_eq!(reps_for(42.0, 41), 20);
    assert_eq!(reps_for(292.0, 41), 3);
    assert_eq!(reps_for(819.0, 41), 2);
    assert_eq!(reps_for(820.0, 41), 1);
    assert_eq!(reps_for(150_000.0, 41), 1);
    // never zero, never more than 4096, whatever the cost
    assert_eq!(reps_for(0.0, 41), 820);
    assert_eq!(reps_for(0.0, 1000), 4096);
    assert_eq!(reps_for(f64::NAN, 41), 820);
    assert_eq!(reps_for(f64::INFINITY, 41), 1);
}

/// A tick for the tests of the batching that is coarse next to the cost of reading the clock: Apple Silicon's is 41.67 ns and a
/// reading takes it 10 to 20 ns, so back-to-back readings repeat; on a machine where reading the clock takes longer than a tick (a
/// virtual machine's can take a few hundred ns) a pretended tick of 42 ns would not repeat anything and nothing would look coarse.
#[cfg(test)]
fn test_tick() -> u64 {
    let c = Clock::new();
    let t0 = Instant::now();
    for _ in 0..20_000 {
        black_box(c.now());
    }
    (t0.elapsed().as_nanos() as u64 / 20_000 * 4).max(42)
}

/// An operation of `n` dependent multiplications: a cost that is set by choosing `n`.
#[cfg(test)]
fn chain(n: u32) -> impl Fn(&u64) -> u64 {
    move |x: &u64| {
        let mut a = *x;
        for _ in 0..n {
            a = black_box(a.wrapping_mul(3).wrapping_add(1));
        }
        a
    }
}

/// What one step of [`chain`] costs here, in ns.
#[cfg(test)]
fn ns_per_step() -> f64 {
    let (op, x) = (chain(200_000), 7u64);
    let t0 = Instant::now();
    for _ in 0..5 {
        black_box(op(black_box(&x)));
    }
    t0.elapsed().as_nanos() as f64 / (5.0 * 200_000.0)
}

#[test]
fn a_clock_that_ticks_coarsely_is_recognised_and_its_tick_measured() {
    let t = test_tick();
    // (not much coarser than 64 t: the smallest step is only seen when a pair of readings straddles a tick, which happens
    // to about one pair in 4n for a tick of n t, t being four readings' time; at 1000 t that was some 5 pairs of the
    // 20,000, and none at all in about one run in a hundred, more on a busy machine)
    for tick in [t, 4 * t, 64 * t] {
        let found = with_tick(tick, || Clock::new().coarse_tick());
        assert_eq!(found, Some(tick), "a clock of {tick} ns");
    }
    // readings of the pretended clock are multiples of its tick
    with_tick(t, || {
        let c = Clock::new();
        for _ in 0..1000 {
            assert_eq!(c.now() % t, 0);
        }
    });
}

#[test]
fn a_coarse_clock_makes_the_harness_time_several_calls_together() {
    let tick = test_tick();
    let r = with_tick(tick, || measure("batching", Duration::from_millis(100), |rng, _| rng.next_u64(), |x| x.wrapping_mul(0x9e37_79b9)));
    // a multiplication is far below the tick: many calls to a sample, and a median per call that is far below it too
    assert!(r.reps > 100, "calls per sample: {} (tick {tick} ns)", r.reps);
    assert!((r.median_ns as u64) < tick, "median per call: {} ns (tick {tick} ns)", r.median_ns);
    // a call that takes about a tick gets just enough company to make a sample span about twenty ticks (not one call per sample,
    // which a sample of a tick would be, nor thousands)
    let per_step = ns_per_step();
    let few = (tick as f64 / per_step) as u32;
    let r = with_tick(tick, || measure("a tick", Duration::from_millis(100), |rng, _| rng.next_u64(), chain(few)));
    let span = r.reps as u64 * r.median_ns as u64;
    assert!((5..=80).contains(&r.reps), "reps {} median {} ns (tick {tick} ns, {per_step:.2} ns a step)", r.reps, r.median_ns);
    assert!((10 * tick..=45 * tick).contains(&span), "a sample spans {span} ns ({} calls of {} ns; tick {tick} ns)", r.reps, r.median_ns);
    // a call that takes many more than twenty ticks is timed on its own
    let long = (300.0 * tick as f64 / per_step).min(5_000_000.0) as u32;
    let r = with_tick(tick, || measure("long", Duration::from_millis(100), |rng, _| rng.next_u64(), chain(long)));
    assert_eq!(r.reps, 1, "median {} ns (tick {tick} ns, {per_step:.2} ns a step, {long} steps)", r.median_ns);
}

/// The negative control on a coarse clock, where the cheap operations are most exposed: the repeat rule must not fail
/// comparisons of a thing with itself (nor, as it did on the M5, call a 42 ns operation a leak).
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn harness_does_not_fail_identical_classes_on_a_coarse_clock() {
    let pairs: usize = std::env::var("PRATIQUE_NULL_PAIRS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(10);
    let mut failures = 0;
    with_tick(test_tick(), || {
        for (what, tally) in [
            ("ct_eq, 32 equal random bytes", false_alarms("null ct_eq", pairs, |rng, _| { let a = rng.bytes(32); (a.clone(), a) }, |(a, b)| ct_eq(a, b))),
            ("sha256, 1 KiB of random bytes", false_alarms("null sha256", pairs, |rng, _| rng.bytes(1024), |m| Sha256::digest(m))),
            ("a 64-bit multiply", false_alarms("null mul", pairs, |rng, _| rng.next_u64(), |x| x.wrapping_mul(0x9e37_79b9_7f4a_7c15))),
        ] {
            println!(
                "{what:<34} {pairs} pairs: first run above {SUSPICIOUS_T}: {:>2}, above {LEAK_T}: {:>2}; failed by the new rule: {:>2}; largest |t| {:.1}",
                tally.above_suspicious, tally.above_leak, tally.new_rule, tally.largest_t
            );
            failures += tally.new_rule;
        }
    });
    assert_eq!(failures, 0, "the repeat rule failed comparisons of identical classes on a coarse clock");
}

// -------------------------------------------------------------------------------------------------- operand probe

/// Not a pass or fail test: whether this CPU itself takes longer for some operand values than for others, which no source code
/// can fix and which would explain a timing difference in code with no branch or table index on a secret. (The first run on an
/// Apple M5 Max flagged the ECDH scalar multiplication for a scalar of 3 against random scalars, |t| 40 to 110 on both curves and
/// every run, with the fixed-window, masked-select, complete-formula code that is constant time as written.) Each row is a
/// simple loop over 2048 words, run on words of one kind and on random words; a row far from "no leak detected" says the hardware
/// (a multiplier that is faster for zeros, a prefetcher that follows values that look like addresses, a clock that follows the
/// power the data draws) is the cause and not the library. Run it with
/// `cargo test --release --lib crypto::timing::operand_probe -- --ignored --nocapture`.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn operand_probe() {
    const N: usize = 2048;
    type Kind = (&'static str, fn(&mut Rng, usize, *const u64) -> u64);
    let kinds: [Kind; 5] = [
        ("zeros", |_, _, _| 0),
        ("small (below 2^16)", |r, _, _| r.next_u64() & 0xffff),
        ("all ones", |_, _, _| u64::MAX),
        ("below 2^47 (could be addresses)", |r, _, _| (r.next_u64() & ((1 << 47) - 1)) | (1 << 32)),
        ("addresses of its own words", |r, _, base| base as u64 + 8 * (r.below(N) as u64)),
    ];
    type Op = (&'static str, fn(&[u64]) -> u64);
    let ops: [Op; 4] = [
        ("64-bit multiply, summed", |d| d.chunks_exact(2).fold(0u64, |a, c| a.wrapping_add(c[0].wrapping_mul(c[1])))),
        ("128-bit multiply (high half), summed", |d| d.chunks_exact(2).fold(0u64, |a, c| a.wrapping_add(((c[0] as u128 * c[1] as u128) >> 64) as u64))),
        ("add, rotate, xor (no multiply)", |d| d.iter().fold(0u64, |a, &x| (a.rotate_left(5) ^ x).wrapping_add(0x9e37_79b9_7f4a_7c15))),
        ("loads, the index taken from the data", |d| (0..d.len()).fold(0u64, |a, i| a.wrapping_add(d[((a as usize) ^ i) & (d.len() - 1)]))),
    ];
    let all_rows = |suffix: &str| {
        for (op_name, op) in ops {
            for (kind_name, kind) in kinds {
                let name = format!("{op_name} on {kind_name}{suffix}");
                let r = measure(
                    &name,
                    Duration::from_millis(1500),
                    move |rng, random| {
                        let mut v = vec![0u64; N];
                        let base = v.as_ptr();
                        for w in v.iter_mut() {
                            *w = if random { rng.next_u64() } else { kind(rng, N, base) };
                        }
                        v
                    },
                    |v: &Vec<u64>| op(v),
                );
                r.print();
            }
        }
    };
    println!("\noperand probe: each row compares words of one kind with random words (class 1 is random)");
    all_rows("");
    // the same with ARM's data-independent timing mode set on this thread, where the CPU has it (BACKLOG B-99)
    if super::dit::Dit::available() {
        println!("\nand again with DIT set:");
        let _dit = super::dit::Dit::on();
        all_rows(" [DIT]");
    } else {
        println!("\n(this CPU has no data-independent timing mode, FEAT_DIT: no rows with it)");
    }
}

// ---------------------------------------------------------------------------------------- DIT on and off

/// Not a pass or fail test (BACKLOG B-99): the comparisons that an Apple M5 Max flagged, each measured with ARM's
/// data-independent timing mode (`crypto::dit`) off (the library's own guards held off) and then on, back to back on this
/// thread, and a table of the two. The M5's second run (2026-10-08) answered the question it was written for: every row
/// flagged with the mode off was clean with it on, and so the library sets it now. It stays as the check that the mode still
/// does that on the next CPU. On a CPU without the mode it says so and stops. Run it with
/// `cargo test --release --lib crypto::timing::dit -- --ignored --nocapture`.
#[test]
#[ignore = "statistical timing run; see the module documentation"]
fn dit_on_and_off() {
    use super::dit::Dit;
    if !Dit::available() {
        println!("\nthis CPU has no data-independent timing mode (FEAT_DIT): nothing to compare");
        return;
    }
    println!("\nthe same comparisons with DIT off and then on (report only; |t| above {LEAK_T} reads as a leak)");
    let mut table: Vec<(String, f64, f64)> = Vec::new();
    let mut both = |name: String, run: &mut dyn FnMut(&str) -> Report| {
        assert!(!Dit::is_set());
        let off = held_off(|| run(&name));
        off.print();
        let on = {
            let _dit = Dit::on();
            assert!(Dit::is_set());
            run(&format!("{name} [DIT]"))
        };
        on.print();
        table.push((name, off.max_t, on.max_t));
    };
    for (curve, size, label) in [(Curve::P256, 32usize, "p256"), (Curve::P384, 48, "p384")] {
        let pool: Vec<Vec<u8>> = (0..32).map(|_| ecdh::generate(curve).unwrap().1).collect();
        let random_scalar = move |rng: &mut Rng| -> Vec<u8> {
            loop {
                let k = rng.bytes(size);
                if ecdh::public_key(curve, &k).is_some() {
                    return k;
                }
            }
        };
        let mut small = vec![0u8; size];
        small[size - 1] = 3;
        let (p, k3) = (pool.clone(), small.clone());
        both(format!("ecdh {label} scalar: 3 vs random"), &mut |name| {
            measure(name, budget(), |rng, c| (if c { random_scalar(rng) } else { k3.clone() }, p[rng.below(32)].clone()), |(k, pt): &(Vec<u8>, Vec<u8>)| {
                ecdh::shared_secret(curve, k, pt)
            })
        });
        let k3 = small.clone();
        both(format!("ecdh {label} public key: scalar 3 vs random"), &mut |name| {
            measure(name, budget(), |rng, c| if c { random_scalar(rng) } else { k3.clone() }, |k: &Vec<u8>| ecdh::public_key(curve, k))
        });
    }
    both("sha256 message: zeros vs random (1 KiB)".into(), &mut |name| measure(name, budget(), |rng, c| fixed_or_random(rng, c, 1024, 0), |m| Sha256::digest(m)));
    both("poly1305 limbs32 (5 x 26-bit) message: zeros vs random".into(), &mut |name| {
        measure(name, budget(), |rng, c| fixed_or_random(rng, c, 1024, 0), |m: &Vec<u8>| {
            let mut p = limbs32::Poly1305::new(&[0x33u8; 32]);
            for c in m.chunks_exact(16) {
                p.block(c.try_into().unwrap(), true);
            }
            p.finish()
        })
    });
    let h = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128.to_be_bytes();
    both("ghash [Portable] data blocks: 0 vs random (fixed H)".into(), &mut |name| {
        measure(name, budget(), |rng, c| fixed_or_random(rng, c, 128, 0), |d: &Vec<u8>| GhashKey::new(&h, Backend::Portable).hash(b"aad", d))
    });
    // the AES rows the M5's second run flagged: key setup with a zero key, and the hardware path sealing 32 zero bytes
    let nonce = [9u8; 12];
    for backend in backends() {
        for key_len in [16usize, 32] {
            both(format!("aes-{}-gcm [{backend:?}] key setup + seal 64 B: zero key vs random", key_len * 8), &mut |name| {
                measure(name, budget(), |rng, c| fixed_or_random(rng, c, key_len, 0), |key: &Vec<u8>| {
                    let g = AesGcm::with_backend(key, backend);
                    let mut b = vec![0u8; 64 + 16];
                    g.seal_in_place(&nonce, b"", &mut b);
                    b
                })
            });
        }
        let short_key = AesGcm::with_backend(&[0x6bu8; 16], backend);
        both(format!("aes-128-gcm [{backend:?}] seal 32 B: zeros vs random"), &mut |name| {
            measure(name, budget(), |rng, c| fixed_or_random(rng, c, 48, 0), |buf: &Vec<u8>| {
                let mut b = buf.clone();
                short_key.seal_in_place(&nonce, b"", &mut b);
                b
            })
        });
    }
    println!("\nlargest |t| of each comparison, DIT off and on:");
    for (name, off, on) in &table {
        let mark = |t: f64| if t > LEAK_T { "LEAK" } else if t > SUSPICIOUS_T { "suspicious" } else { "ok" };
        println!("  {name:<56} DIT off {off:>6.1} {:<10}  DIT on {on:>6.1} {}", mark(*off), mark(*on));
    }
}
