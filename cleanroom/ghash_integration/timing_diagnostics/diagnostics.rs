// Diagnostic-only test module, included inside crypto::timing by the runner.
// It neither changes the production operation nor the existing timing judge.

fn diagnostic_measure<const PRE: bool, R>(
    name: &str,
    seed: u64,
    mut gen: impl FnMut(&mut Rng, bool) -> Vec<u8>,
    pre: impl Fn(&Vec<u8>),
    op: impl Fn(&Vec<u8>) -> R,
    timed_address: impl Fn(&Vec<u8>) -> usize,
) -> Report {
    use std::io::Write;
    let seed = seed ^ std::env::var("PRATIQUE_DIAGNOSTIC_SEED").unwrap_or_else(|_| "0".into()).parse::<u64>().unwrap();
    let mut rng = Rng::new(0xd0de_c7 ^ "ghash [Portable] batch 1024 data: 0 vs random".len() as u64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let clock = Clock::new();
    let coarse = clock.coarse_tick();
    println!("DIAGNOSTIC clock coarse_tick={coarse:?} forced_reps={:?}", std::env::var("PRATIQUE_TIMING_REPS").ok());
    assert!(coarse.is_none(), "native fine-clock diagnostic required");
    assert!(std::env::var("PRATIQUE_TIMING_REPS").map_or(true, |v| v == "1"));
    let seconds: f64 = std::env::var("PRATIQUE_DIAGNOSTIC_SECS").unwrap_or_else(|_| "3".into()).parse().unwrap();
    let start = Instant::now();
    let mut first = true;
    let mut samples = Vec::new();
    let mut raw = Vec::new();
    let mut batch = 0usize;
    while first || samples.is_empty() || start.elapsed() < Duration::from_secs_f64(seconds) {
        let mut classes = Vec::with_capacity(64 * BLOCK);
        for _ in 0..64 {
            let mut block: Vec<bool> = (0..BLOCK).map(|i| i < BLOCK / 2).collect();
            for i in (1..BLOCK).rev() {
                block.swap(i, rng.below(i + 1));
            }
            classes.extend(block);
        }
        // Preserve the original generator's nested allocation/storage structure.
        let inputs: Vec<Vec<Vec<u8>>> = classes.iter().map(|&c| vec![gen(&mut rng, c)]).collect();
        for (index, (&class, group)) in classes.iter().zip(&inputs).enumerate() {
            if PRE { pre(black_box(&group[0])); }
            let t0 = clock.now();
            for input in group {
                black_box(op(black_box(input)));
            }
            let dt = (clock.now() - t0).min(u32::MAX as u64) as u32;
            // Address observation follows the timer; it does not pre-touch metadata.
            let input = &group[0];
            let address = input.as_ptr() as usize;
            let actual_address = timed_address(input);
            if !first {
                samples.push((dt, class));
                raw.push((dt, class, address, actual_address, batch, index));
            }
        }
        first = false;
        batch += 1;
    }
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let filename: String = name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let mut file = std::io::BufWriter::new(std::fs::File::create(root.join(format!("{filename}.csv"))).unwrap());
    writeln!(file, "duration_ns,class,input_address,timed_address,batch,sample").unwrap();
    for (dt, class, address, timed, batch, index) in raw {
        writeln!(file, "{dt},{},{address},{timed},{batch},{index}", class as u8).unwrap();
    }
    let mut sorted: Vec<u32> = samples.iter().map(|s| s.0).collect();
    sorted.sort_unstable();
    let pct = |p: f64| sorted[(((sorted.len() - 1) as f64) * p) as usize];
    let uncropped_t = paired_t(&samples, u32::MAX);
    let crops: Vec<_> = CROP_LEVELS.iter().map(|&p| (p, paired_t(&samples, pct(p)))).collect();
    let max_t = crops.iter().fold(uncropped_t.abs(), |m, c| m.max(c.1.abs()));
    let per_call: Vec<_> = std::iter::once((1.0, u32::MAX))
        .chain(CROP_LEVELS.iter().map(|&p| (p, pct(p))))
        .map(|(p, cutoff)| {
            let (mean, se) = paired_mean_se(&samples, cutoff);
            println!("DIAGNOSTIC {name} crop={p} cutoff={cutoff} delta_ns={mean:.9} se_ns={se:.9}");
            (p, mean, se)
        })
        .collect();
    let report = Report { name: name.into(), samples: samples.len(), reps: 1, uncropped_t,
        max_t, median_ns: pct(0.5), crops, per_call };
    report.print();
    report
}

fn diagnostic_equal_preparation(rng: &mut Rng, class: bool) -> Vec<u8> {
    let mut data = rng.bytes(1024);
    let mask = black_box(0u8.wrapping_sub(class as u8));
    for byte in &mut data { *byte &= mask; }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    black_box(data)
}

fn diagnostic_fixed_work(iterations: usize) -> u64 {
    let mut value = black_box(0x0123_4567_89ab_cdef_u64);
    for _ in 0..iterations {
        value = black_box((value.rotate_left(13) ^ 0x9e37_79b9_7f4a_7c15).wrapping_add(0x5a5a_3c3c_a5a5_c3c3));
    }
    value
}

fn diagnostic_scan(data: &[u8], rounds: usize) -> u64 {
    let mut result = 0u64;
    for _ in 0..rounds {
        result ^= black_box(black_box(data).iter().fold(0u64, |sum, &b| sum.wrapping_add(b as u64)));
    }
    black_box(result)
}

fn diagnostic_copy(data: &[u8], rounds: usize) -> u8 {
    let mut scratch = [0u8; 1024];
    let mut result = 0u8;
    for _ in 0..rounds {
        scratch.copy_from_slice(black_box(data));
        result ^= black_box(&scratch)[0];
    }
    black_box(result)
}

fn diagnostic_cost<R>(op: impl Fn() -> R) -> f64 {
    let mut costs = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        for _ in 0..64 { black_box(op()); }
        costs.push(start.elapsed().as_nanos() as f64 / 64.0);
    }
    costs.sort_by(|a, b| a.total_cmp(b));
    costs[4].max(1.0)
}

#[test]
#[ignore = "diagnostic-only native x86 investigation; does not replace the unchanged timing gate"]
fn pr10_ghash_timing_diagnostics() {
    use std::cell::RefCell;
    use std::sync::atomic::{fence, Ordering};
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let sensitivity = std::panic::catch_unwind(harness_detects_a_difference_of_about_one_percent).is_ok();
    let early_exit = std::panic::catch_unwind(harness_flags_an_early_exit_comparison_and_passes_ct_eq).is_ok();
    println!("DIAGNOSTIC SENSITIVITY_CONTROL_PASSED={sensitivity} EARLY_EXIT_CONTROL_PASSED={early_exit}");
    std::fs::write(root.join("positive-control-results.txt"), format!("sensitivity={sensitivity}\nearly_exit={early_exit}\n")).unwrap();
    let _dit = Dit::on();
    let fixed_h = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128.to_be_bytes();
    let prepared = GhashKey::new(&fixed_h, Backend::Portable);
    let fixed_data = vec![0x5au8; 1024];
    let original = |rng: &mut Rng, c| fixed_or_random(rng, c, 1024, 0);
    let address = |data: &Vec<u8>| data.as_ptr() as usize;
    let fixed_address = |_: &Vec<u8>| fixed_data.as_ptr() as usize;
    let noop = |_: &Vec<u8>| {};
    let target_cost = diagnostic_cost(|| prepared.hash(b"aad", black_box(&fixed_data)));
    let work = ((1024.0 * target_cost / diagnostic_cost(|| diagnostic_fixed_work(1024))).round() as usize).max(1);
    let scans = (target_cost / diagnostic_cost(|| diagnostic_scan(black_box(&fixed_data), 1))).round() as usize;
    let copies = (target_cost / diagnostic_cost(|| diagnostic_copy(black_box(&fixed_data), 1))).round() as usize;
    println!("DIAGNOSTIC calibrated hash_ns={target_cost:.3} work_iterations={work} scan_rounds={scans} copy_rounds={copies}");
    println!("DIAGNOSTIC final_control_cost_ns fixed_work={:.3} scan={:.3} copy={:.3}",
        diagnostic_cost(|| diagnostic_fixed_work(work)),
        diagnostic_cost(|| diagnostic_scan(black_box(&fixed_data), scans.max(1))),
        diagnostic_cost(|| diagnostic_copy(black_box(&fixed_data), copies.max(1))));
    diagnostic_measure::<false, _>("actual_original_preparation", 0, original, noop,
        |data| prepared.hash(b"aad", data), address);
    diagnostic_measure::<false, _>("fixed_hash_original_preparation", 0, original, noop,
        |_| prepared.hash(b"aad", black_box(&fixed_data)), fixed_address);
    diagnostic_measure::<false, _>("fixed_work_original_preparation", 0, original, noop,
        |_| diagnostic_fixed_work(work), |_| 0);
    diagnostic_measure::<false, _>("scan_original_preparation", 0, original, noop,
        |data| diagnostic_scan(data, scans.max(1)), address);
    diagnostic_measure::<false, _>("copy_original_preparation", 0, original, noop,
        |data| diagnostic_copy(data, copies.max(1)), address);
    diagnostic_measure::<false, _>("actual_equal_preparation", 0, diagnostic_equal_preparation, noop,
        |data| prepared.hash(b"aad", data), address);
    diagnostic_measure::<false, _>("fixed_hash_equal_preparation", 0, diagnostic_equal_preparation, noop,
        |_| prepared.hash(b"aad", black_box(&fixed_data)), fixed_address);
    let scratch = RefCell::new([0u8; 1024]);
    let pre = |data: &Vec<u8>| {
        scratch.borrow_mut().copy_from_slice(black_box(data));
        black_box(&*scratch.borrow());
        fence(Ordering::SeqCst);
    };
    let scratch_address = |_: &Vec<u8>| scratch.borrow().as_ptr() as usize;
    diagnostic_measure::<true, _>("actual_same_address_original_preparation", 0, original, pre,
        |_| prepared.hash(b"aad", black_box(&*scratch.borrow())), scratch_address);
    diagnostic_measure::<true, _>("fixed_hash_after_same_address_preparation", 0, original, pre,
        |_| prepared.hash(b"aad", black_box(&fixed_data)), fixed_address);
    diagnostic_measure::<true, _>("actual_same_address_equal_preparation", 0, diagnostic_equal_preparation, pre,
        |_| prepared.hash(b"aad", black_box(&*scratch.borrow())), scratch_address);
}
