//! Standalone throughput probe; no production GHASH source is loaded.
use clmul_feasibility as primitive;

use std::hint::black_box;
use std::time::Instant;

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn measure(label: &str, products: usize, iterations: usize, mut run: impl FnMut()) {
    let mut samples = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        for _ in 0..iterations {
            run();
        }
        samples.push(start.elapsed().as_secs_f64() * 1e9 / iterations as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "{label}: median {:.3} ns/call; {:.3} ns/three products; min {:.3}",
        samples[4],
        samples[4] * 3.0 / products as f64,
        samples[0] * 3.0 / products as f64
    );
}

fn main() {
    let mut state = 0xbb67_ae85_84ca_a73b;
    let mut a = [0; 64];
    let mut b = [0; 64];
    for lane in 0..64 {
        a[lane] = next(&mut state);
        b[lane] = next(&mut state);
    }
    let iterations = std::env::args()
        .nth(1)
        .map(|x| x.parse().unwrap())
        .unwrap_or(100_000);
    let a = black_box(a);
    let b = black_box(b);
    let mut prepared = primitive::Prepared64::empty();
    prepared.prepare(black_box(&b));
    measure("accepted scalar x3", 3, iterations, || {
        black_box([
            primitive::clmul64_portable(black_box(a[0]), black_box(b[0])),
            primitive::clmul64_portable(black_box(a[1]), black_box(b[1])),
            primitive::clmul64_portable(black_box(a[2]), black_box(b[2])),
        ]);
    });
    measure("transpose only", 64, iterations, || {
        black_box(primitive::transpose(black_box(a)));
    });
    measure("Boolean Karatsuba x64", 64, iterations, || {
        black_box(primitive::clmul64x64_portable(black_box(a), black_box(b)));
    });
    let mut coefficients = [0; 64];
    let mut product_planes = [0; 128];
    let mut product = 0;
    measure("prepared x64 xor", 64, iterations, || {
        coefficients.copy_from_slice(black_box(&a));
        primitive::clmul64_batch_xor_prepared(
            black_box(&mut coefficients),
            black_box(&prepared),
            black_box(&mut product_planes),
            black_box(&mut product),
        );
        black_box(&product);
    });
    let mut a128 = [0; 64];
    let mut b128 = [0; 64];
    for lane in 0..64 {
        a128[lane] = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
        b128[lane] = u128::from(next(&mut state)) ^ (u128::from(next(&mut state)) << 64);
    }
    let mut prepared128 = primitive::PreparedPolynomial128x64::empty();
    prepared128.prepare(black_box(&b128));
    let mut working = primitive::BatchWorking128x64::empty();
    measure("128-bit polynomial batch x64 xor", 192, iterations, || {
        primitive::clmul128_batch_xor_prepared(
            black_box(&a128),
            black_box(&prepared128),
            black_box(&mut working),
        );
        black_box(working.output());
    });
    let mut destination = primitive::Prepared64::empty();
    measure("prepare x64 operand in place", 64, iterations, || {
        destination.prepare(black_box(&b));
        black_box(&destination);
    });
    let mut destination128 = primitive::PreparedPolynomial128x64::empty();
    measure(
        "prepare 128-bit operand set in place",
        192,
        iterations,
        || {
            destination128.prepare(black_box(&b128));
            black_box(&destination128);
        },
    );
}
