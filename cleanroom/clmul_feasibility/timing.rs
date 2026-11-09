//! Independent, noisy timing screen; not the production GHASH timing suite.
use clmul_feasibility::{PreparedPolynomial128x64, clmul128_batch_xor_prepared};
use std::hint::black_box;
use std::time::Instant;

#[derive(Default)]
struct Moments {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn add(&mut self, value: f64) {
        self.n += 1.0;
        let delta = value - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (value - self.mean);
    }

    fn variance(&self) -> f64 {
        self.m2 / (self.n - 1.0)
    }
}

fn next(state: &mut u64) -> u128 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    let low = *state;
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    u128::from(low) ^ (u128::from(*state) << 64)
}

fn screen(label: &str, vary_b: bool, rounds: usize, repetitions: usize, seed: u64) {
    let mut state = seed;
    let mut fixed = [0; 64];
    for value in &mut fixed {
        *value = next(&mut state);
    }
    let fixed = black_box(fixed);
    let mut stats = [Moments::default(), Moments::default()];
    for _ in 0..rounds {
        let first = (next(&mut state) & 1) as usize;
        for turn in 0..2 {
            let class = first ^ turn;
            let mask = 0u128.wrapping_sub(class as u128);
            let mut varying = [0; 64];
            for value in &mut varying {
                *value = next(&mut state) & mask;
            }
            // Build both classes in the same local storage, outside the timer.
            let (a, b) = if vary_b {
                (fixed, varying)
            } else {
                (varying, fixed)
            };
            let a = black_box(a);
            let mut prepared = PreparedPolynomial128x64::empty();
            prepared.prepare(black_box(&b));
            let start = Instant::now();
            for _ in 0..repetitions {
                black_box(clmul128_batch_xor_prepared(
                    black_box(a),
                    black_box(&prepared),
                ));
            }
            stats[class].add(start.elapsed().as_secs_f64() * 1e9 / repetitions as f64);
        }
    }
    let t = (stats[0].mean - stats[1].mean)
        / (stats[0].variance() / stats[0].n + stats[1].variance() / stats[1].n).sqrt();
    println!(
        "{label}: n/class={rounds}, calls/sample={repetitions}, zero={:.3} ns, random={:.3} ns, Welch t={t:.3}",
        stats[0].mean, stats[1].mean
    );
}

fn main() {
    let rounds = std::env::args()
        .nth(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(20_000);
    screen(
        "varied message operand",
        false,
        rounds,
        8,
        0x6a09_e667_f3bc_c909,
    );
    screen(
        "varied prepared operand",
        true,
        rounds,
        8,
        0xbb67_ae85_84ca_a73b,
    );
}
