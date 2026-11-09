// Diagnostic-only matched 1024-byte batch controls. No production expression changes.
const BATCH_DATA_NAME: &str = "ghash [Portable] batch 1024 data: 0 vs random";
const BATCH_KEY_NAME: &str = "ghash [Portable] batch 1024 prepared H: 0 vs random";
const BATCH_BYTES: usize = 1024;

#[derive(Clone)]
struct BatchRng(u64);
impl BatchRng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchKind {
    Data,
    Key,
}
#[derive(Clone, Copy)]
enum BatchGeneration {
    Literal,
    IdenticalHistory,
    EqualVariable,
    EqualIdentical,
}
impl BatchGeneration {
    fn original_schedule(self) -> bool {
        matches!(self, Self::Literal | Self::IdenticalHistory)
    }
    fn identical(self) -> bool {
        matches!(self, Self::IdenticalHistory | Self::EqualIdentical)
    }
}

#[derive(Debug)]
struct BatchFixture {
    class: bool,
    before: u64,
    h: [u8; 16],
}

fn batch_name(kind: BatchKind) -> &'static str {
    match kind {
        BatchKind::Data => BATCH_DATA_NAME,
        BatchKind::Key => BATCH_KEY_NAME,
    }
}
fn batch_seed(kind: BatchKind, seed: u64) -> u64 {
    0xd0de_c7 ^ batch_name(kind).len() as u64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}
fn batch_classes(rng: &mut Rng) -> Vec<bool> {
    let mut classes = Vec::with_capacity(64 * BLOCK);
    for _ in 0..64 {
        let mut block: Vec<bool> = (0..BLOCK).map(|i| i < BLOCK / 2).collect();
        for i in (1..BLOCK).rev() {
            block.swap(i, rng.below(i + 1));
        }
        classes.extend(block);
    }
    classes
}
fn batch_fixtures(rng: &mut BatchRng, kind: BatchKind) -> Vec<BatchFixture> {
    let mut classes = Vec::with_capacity(64 * BLOCK);
    for _ in 0..64 {
        let mut block: Vec<bool> = (0..BLOCK).map(|i| i < BLOCK / 2).collect();
        for i in (1..BLOCK).rev() {
            block.swap(i, (rng.next() % (i + 1) as u64) as usize);
        }
        classes.extend(block);
    }
    classes
        .into_iter()
        .map(|class| {
            let before = rng.0;
            let mut h = [0u8; 16];
            match kind {
                BatchKind::Data => {
                    for _ in 0..BATCH_BYTES {
                        rng.next();
                    }
                }
                BatchKind::Key => {
                    if class {
                        for b in &mut h {
                            *b = rng.next() as u8;
                        }
                    }
                }
            }
            BatchFixture { class, before, h }
        })
        .collect()
}

// Variable public length is also exercised by the unit test. Keep the original
// scalar RNG low-byte arithmetic/store lowering, not per-byte opaque u64 work.
#[inline(never)]
fn batch_original_data(rng: &mut Rng, class: bool, len: usize) -> Vec<u8> {
    let mut v = rng.bytes(len);
    if !class {
        v.fill(0);
    }
    v
}
#[inline(never)]
fn batch_identical_data(rng: &mut Rng, class: bool, len: usize) -> Vec<u8> {
    // Preserve fixed-class random bytes followed by its original extra clear.
    // The random class stores zeros. Both classes execute the added byte AND.
    let mask = black_box((class as u8).wrapping_sub(1));
    let mut v: Vec<u8> = (0..len).map(|_| (rng.next_u64() as u8) & mask).collect();
    if !class {
        v.fill(0);
    } // Original extra clear, at the actual timed buffer.
    v
}
#[inline(never)]
fn batch_equal_data(f: &BatchFixture, identical: bool, len: usize) -> Vec<u8> {
    let mut rng = BatchRng(f.before);
    let mask = black_box(if identical {
        0
    } else {
        0u8.wrapping_sub(f.class as u8)
    });
    (0..len).map(|_| (rng.next() as u8) & mask).collect()
}
#[inline(never)]
fn batch_original_h(rng: &mut Rng, class: bool) -> [u8; 16] {
    if class {
        rng.bytes(16).try_into().unwrap()
    } else {
        [0; 16]
    }
}
#[inline(never)]
fn batch_identical_h(rng: &mut Rng, class: bool) -> [u8; 16] {
    let mut h: [u8; 16] = if class {
        let v = rng.bytes(16);
        // Retain the completed original random heap payload before converting
        // and masking the raw H. There is no post-key overwrite/repreparation.
        black_box(&v);
        v.try_into().unwrap()
    } else {
        [0; 16]
    };
    let mask = black_box((class as u8).wrapping_sub(1));
    for byte in &mut h {
        *byte &= mask;
    }
    h
}
#[inline(never)]
fn batch_equal_h(f: &BatchFixture, identical: bool) -> [u8; 16] {
    let mut rng = BatchRng(f.before);
    let mask = black_box(if identical {
        0
    } else {
        0u8.wrapping_sub(f.class as u8)
    });
    let v: Vec<u8> = (0..16).map(|_| (rng.next() as u8) & mask).collect();
    v.try_into().unwrap()
}

// Both triplets use one helper per operation. Inputs are borrowed; only the
// original Copy tag is observed before stop. No key construction/Drop/Vec free.
#[inline(never)]
fn batch_time_data(clock: &Clock, key: &GhashKey, input: &Vec<u8>) -> u32 {
    let start = clock.now();
    black_box(key.hash(b"aad", black_box(input)));
    (clock.now() - start).min(u32::MAX as u64) as u32
}
#[inline(never)]
fn batch_time_key(clock: &Clock, input: &GhashKey, data: &Vec<u8>) -> u32 {
    let start = clock.now();
    black_box(black_box(input).hash(b"aad", data));
    (clock.now() - start).min(u32::MAX as u64) as u32
}
#[inline(never)]
fn batch_delay(n: usize) -> u64 {
    let mut x = black_box(0x1234_5678_9abc_def0u64);
    for _ in 0..n {
        x = black_box(x.rotate_left(13).wrapping_add(0x5a5a_3c3c_a5a5_c3c3));
    }
    x
}
#[inline(never)]
fn batch_time_positive(
    clock: &Clock,
    key: &GhashKey,
    data: &Vec<u8>,
    class: bool,
    delay: usize,
) -> u32 {
    let start = clock.now();
    black_box(black_box(key).hash(b"aad", black_box(data)));
    if black_box(class) {
        black_box(batch_delay(delay));
    }
    (clock.now() - start).min(u32::MAX as u64) as u32
}
fn batch_cost<R>(op: impl Fn() -> R) -> f64 {
    let mut costs = Vec::new();
    for _ in 0..9 {
        let start = Instant::now();
        for _ in 0..64 {
            black_box(op());
        }
        costs.push(start.elapsed().as_nanos() as f64 / 64.0);
    }
    costs.sort_by(|a, b| a.total_cmp(b));
    costs[4].max(1.0)
}

fn batch_report(name: &str, samples: &[(u32, bool)]) -> Report {
    let mut sorted: Vec<_> = samples.iter().map(|s| s.0).collect();
    sorted.sort_unstable();
    let pct = |p: f64| sorted[(((sorted.len() - 1) as f64) * p) as usize];
    let uncropped_t = paired_t(samples, u32::MAX);
    let crops: Vec<_> = CROP_LEVELS
        .iter()
        .map(|&p| (p, paired_t(samples, pct(p))))
        .collect();
    let max_t = crops
        .iter()
        .fold(uncropped_t.abs(), |m, c| m.max(c.1.abs()));
    let per_call = std::iter::once((1.0, u32::MAX))
        .chain(CROP_LEVELS.iter().map(|&p| (p, pct(p))))
        .map(|(p, cutoff)| {
            let (m, se) = paired_mean_se(samples, cutoff);
            println!(
                "BATCH crop name={name} keep={p} cutoff={cutoff} mean_ns={m:.12} SE_ns={se:.12}"
            );
            (p, m, se)
        })
        .collect();
    let report = Report {
        name: name.into(),
        samples: samples.len(),
        reps: 1,
        uncropped_t,
        max_t,
        median_ns: pct(0.5),
        crops,
        per_call,
    };
    report.print();
    report
}

trait BatchInput {
    fn kind() -> BatchKind;
    fn make(
        rng: &mut Rng,
        class: bool,
        f: Option<&BatchFixture>,
        generation: BatchGeneration,
    ) -> Self;
    fn time(&self, clock: &Clock, key: &GhashKey, data: &Vec<u8>, class: bool, delay: usize)
        -> u32;
    fn data_address(&self, data: &Vec<u8>) -> usize;
    fn key_address(&self, key: &GhashKey) -> usize;
    fn validate(&self, f: &BatchFixture, generation: BatchGeneration);
}
impl BatchInput for Vec<u8> {
    fn kind() -> BatchKind {
        BatchKind::Data
    }
    fn make(rng: &mut Rng, class: bool, f: Option<&BatchFixture>, g: BatchGeneration) -> Self {
        match g {
            BatchGeneration::Literal => batch_original_data(rng, class, BATCH_BYTES),
            BatchGeneration::IdenticalHistory => batch_identical_data(rng, class, BATCH_BYTES),
            BatchGeneration::EqualVariable => batch_equal_data(f.unwrap(), false, BATCH_BYTES),
            BatchGeneration::EqualIdentical => batch_equal_data(f.unwrap(), true, BATCH_BYTES),
        }
    }
    fn time(&self, clock: &Clock, key: &GhashKey, _: &Vec<u8>, class: bool, delay: usize) -> u32 {
        if delay == 0 {
            batch_time_data(clock, key, self)
        } else {
            batch_time_positive(clock, key, self, class, delay)
        }
    }
    fn data_address(&self, _: &Vec<u8>) -> usize {
        self.as_ptr() as usize
    }
    fn key_address(&self, key: &GhashKey) -> usize {
        key as *const GhashKey as usize
    }
    fn validate(&self, f: &BatchFixture, g: BatchGeneration) {
        assert_eq!(self.len(), BATCH_BYTES);
        let mut rng = BatchRng(f.before);
        let mask = if g.identical() {
            0
        } else {
            0u8.wrapping_sub(f.class as u8)
        };
        for byte in self {
            assert_eq!(*byte, (rng.next() as u8) & mask);
        }
    }
}
impl BatchInput for GhashKey {
    fn kind() -> BatchKind {
        BatchKind::Key
    }
    fn make(rng: &mut Rng, class: bool, f: Option<&BatchFixture>, g: BatchGeneration) -> Self {
        let h = match g {
            BatchGeneration::Literal => batch_original_h(rng, class),
            BatchGeneration::IdenticalHistory => batch_identical_h(rng, class),
            BatchGeneration::EqualVariable => batch_equal_h(f.unwrap(), false),
            BatchGeneration::EqualIdentical => batch_equal_h(f.unwrap(), true),
        };
        GhashKey::new(&h, Backend::Portable)
    }
    fn time(&self, clock: &Clock, _: &GhashKey, data: &Vec<u8>, class: bool, delay: usize) -> u32 {
        if delay == 0 {
            batch_time_key(clock, self, data)
        } else {
            batch_time_positive(clock, self, data, class, delay)
        }
    }
    fn data_address(&self, data: &Vec<u8>) -> usize {
        data.as_ptr() as usize
    }
    fn key_address(&self, _: &GhashKey) -> usize {
        self as *const GhashKey as usize
    }
    // H is verified at the generator boundary in the unit/codegen proof. No
    // private-key inspector, extra runtime hash, adjacent metadata, or per-key
    // data clone is introduced into the literal prebuilt-key storage graph.
    fn validate(&self, _: &BatchFixture, _: BatchGeneration) {}
}

fn batch_measure<I: BatchInput>(
    name: &str,
    seed: u64,
    generation: BatchGeneration,
    fixed_key: &GhashKey,
    fixed_data: &Vec<u8>,
    delay: usize,
    seconds: f64,
) -> Report {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let clock = Clock::new();
    assert_eq!(clock.tick, 0, "no forced clock quantization");
    assert!(clock.coarse_tick().is_none(), "native fine clock required");
    assert!(std::env::var("PRATIQUE_TIMING_REPS").map_or(true, |x| x.trim() == "1"));
    let mut actual_rng = Rng::new(batch_seed(I::kind(), seed));
    let mut fixture_rng = BatchRng::new(batch_seed(I::kind(), seed));
    let mut samples = Vec::new();
    let mut raw = Vec::new();
    let mut prefixes = Vec::new();
    let start = Instant::now();
    // Preserve the original inner iterator/collect allocation graph rather
    // than vec![gen()], which can evaluate generation before reserving storage.
    let reps = black_box(1usize);
    let mut batch = 0;
    while batch == 0 || samples.is_empty() || start.elapsed() < Duration::from_secs_f64(seconds) {
        let mut fixtures = if generation.original_schedule() {
            Vec::new()
        } else {
            batch_fixtures(&mut fixture_rng, I::kind())
        };
        let classes = if generation.original_schedule() {
            batch_classes(&mut actual_rng)
        } else {
            fixtures.iter().map(|f| f.class).collect()
        };
        // Exact sample/group storage: I is Vec<u8> OR GhashKey itself. Metadata
        // is separate, never beside a key. Fixed data is shared by all keys.
        let inputs: Vec<Vec<I>> = classes
            .iter()
            .enumerate()
            .map(|(i, &class)| {
                (0..reps)
                    .map(|_| I::make(&mut actual_rng, class, fixtures.get(i), generation))
                    .collect()
            })
            .collect();
        let mut observed = Vec::with_capacity(classes.len());
        for (index, (&class, group)) in classes.iter().zip(&inputs).enumerate() {
            let input = &group[0];
            let dt = input.time(&clock, fixed_key, fixed_data, class, delay);
            observed.push((
                dt,
                class,
                input as *const I as usize,
                input.data_address(fixed_data),
                input.key_address(fixed_key),
                batch,
                index,
            ));
        }
        // Literal fixtures are replayed only AFTER the entire timed batch.
        if generation.original_schedule() {
            fixtures = batch_fixtures(&mut fixture_rng, I::kind());
        }
        for (i, (fixture, row)) in fixtures.iter().zip(observed).enumerate() {
            assert_eq!(fixture.class, classes[i]);
            inputs[i][0].validate(fixture, generation);
            prefixes.push((
                batch,
                i,
                fixture.class,
                fixture.before,
                u128::from_be_bytes(fixture.h),
            ));
            if batch != 0 {
                samples.push((row.0, row.1));
                raw.push((row, fixture.before, u128::from_be_bytes(fixture.h)));
            }
        }
        drop(inputs); // All owned key Drop/wipe and Vec deallocation are untimed.
        batch += 1;
    }
    let mut file = std::io::BufWriter::new(
        std::fs::File::create(root.join(format!("{name}-seed{seed}.csv"))).unwrap(),
    );
    writeln!(file, "duration_ns,class,input_address,timed_address,data_address,key_address,batch,sample,fixture_rng_before,fixture_h_value").unwrap();
    for ((dt, class, input, data, key, batch, sample), before, h) in raw {
        let timed = if I::kind() == BatchKind::Data {
            data
        } else {
            key
        };
        writeln!(
            file,
            "{dt},{},{input},{timed},{data},{key},{batch},{sample},{before},{h}",
            class as u8
        )
        .unwrap();
    }
    let mut prefix = std::io::BufWriter::new(
        std::fs::File::create(root.join(format!("{name}-seed{seed}.fixtures.txt"))).unwrap(),
    );
    writeln!(
        prefix,
        "reference={:?} seed={seed} reps=1 first_batch=warmup metadata=out_of_band",
        batch_name(I::kind())
    )
    .unwrap();
    for (batch, i, class, before, h) in prefixes {
        writeln!(prefix, "{batch},{i},{},{before},{h}", class as u8).unwrap();
    }
    println!("BATCH metadata name={name} seed={seed} kind={:?} I_size={} Vec_header={} fixed_data_address={} fixed_key_address={} batches={batch} native_tick={} reps=1", I::kind(), std::mem::size_of::<I>(), std::mem::size_of::<Vec<u8>>(), fixed_data.as_ptr() as usize, fixed_key as *const GhashKey as usize, clock.tick);
    batch_report(name, &samples)
}

fn batch_control_run<I: BatchInput>(label: &str) {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let sensitivity =
        std::panic::catch_unwind(harness_detects_a_difference_of_about_one_percent).is_ok();
    let early_exit =
        std::panic::catch_unwind(harness_flags_an_early_exit_comparison_and_passes_ct_eq).is_ok();
    let _dit = Dit::on();
    let h = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210u128.to_be_bytes();
    let fixed_key = GhashKey::new(&h, Backend::Portable);
    let zero_key = GhashKey::new(&[0; 16], Backend::Portable);
    let fixed_data = vec![0x5a; BATCH_BYTES];
    let zero_data = vec![0; BATCH_BYTES];
    let seconds: f64 = std::env::var("PRATIQUE_BATCH_SECS")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .unwrap();
    assert!(seconds.is_finite() && seconds >= 0.0);
    let mut status = std::io::BufWriter::new(
        std::fs::File::create(root.join("batch-control-results.txt")).unwrap(),
    );
    writeln!(
        status,
        "sensitivity={sensitivity}\nearly_exit={early_exit}\nkind={label}"
    )
    .unwrap();
    status.flush().unwrap();
    let target = match I::kind() {
        BatchKind::Data => batch_cost(|| fixed_key.hash(b"aad", black_box(&zero_data))),
        BatchKind::Key => batch_cost(|| zero_key.hash(b"aad", black_box(&fixed_data))),
    };
    let initial_cost = batch_cost(|| batch_delay(128));
    let mut delay = ((0.02 * target / initial_cost) * 128.0).round().max(1.0) as usize;
    writeln!(
        status,
        "calibration_target_ns={target}\ncalibration_initial128_ns={initial_cost}"
    )
    .unwrap();
    for round in 0..4 {
        let cost = batch_cost(|| batch_delay(delay));
        let ratio = cost / target;
        let in_range = (0.015..=0.025).contains(&ratio);
        writeln!(status, "calibration_round{round}_iterations={delay}\ncalibration_round{round}_cost_ns={cost}\ncalibration_round{round}_ratio={ratio}\ncalibration_round{round}_in_range={in_range}").unwrap();
        status.flush().unwrap();
        if in_range {
            break;
        }
        delay = ((delay as f64 * 0.02 * target / cost).round().max(1.0)) as usize;
    }
    let final_cost = batch_cost(|| batch_delay(delay));
    let ratio = final_cost / target;
    let in_range = (0.015..=0.025).contains(&ratio);
    writeln!(status, "calibration_final_iterations={delay}\ncalibration_final_cost_ns={final_cost}\ncalibration_final_ratio={ratio}\ncalibration_final_in_range={in_range}").unwrap();
    status.flush().unwrap();
    for (name, generation, added_delay) in [
        ("literal", BatchGeneration::Literal, 0),
        ("identical_history", BatchGeneration::IdenticalHistory, 0),
        ("equal_variable", BatchGeneration::EqualVariable, 0),
        (
            "negative_identical_equal",
            BatchGeneration::EqualIdentical,
            0,
        ),
        ("positive_matched", BatchGeneration::EqualIdentical, delay),
    ] {
        let first = batch_measure::<I>(
            name,
            0,
            generation,
            &fixed_key,
            &fixed_data,
            added_delay,
            seconds,
        );
        let again = batch_measure::<I>(
            name,
            1,
            generation,
            &fixed_key,
            &fixed_data,
            added_delay,
            seconds,
        );
        let failure = judge(&first, &again);
        println!("BATCH result kind={label} row={name} confirmed_failure={failure:?}");
        writeln!(status, "{name}_confirmed_failure={}", failure.is_some()).unwrap();
        if name == "positive_matched" {
            writeln!(
                status,
                "positive_matched_detected={}\npositive_matched_healthy={}",
                first.max_t > LEAK_T && again.max_t > LEAK_T,
                in_range && first.max_t > LEAK_T && again.max_t > LEAK_T
            )
            .unwrap();
        }
        status.flush().unwrap();
    }
}

#[test]
fn pr10_batch_fixture_storage_check() {
    assert_eq!(std::mem::size_of::<Vec<u8>>(), 24);
    assert_eq!(std::mem::size_of::<GhashKey>(), 1712);
    for kind in [BatchKind::Data, BatchKind::Key] {
        for seed in [0, 1] {
            let mut original = Rng::new(batch_seed(kind, seed));
            let mut scheduler = BatchRng::new(batch_seed(kind, seed));
            for _ in 0..4 {
                let classes = batch_classes(&mut original);
                let fixtures = batch_fixtures(&mut scheduler, kind);
                for (&class, f) in classes.iter().zip(&fixtures) {
                    assert_eq!(class, f.class);
                    match kind {
                        BatchKind::Data => {
                            let v = batch_original_data(&mut original, class, BATCH_BYTES);
                            v.validate(f, BatchGeneration::Literal);
                            assert_eq!(batch_equal_data(f, false, BATCH_BYTES), v);
                            assert!(batch_equal_data(f, true, BATCH_BYTES)
                                .iter()
                                .all(|&x| x == 0));
                        }
                        BatchKind::Key => {
                            let h = batch_original_h(&mut original, class);
                            assert_eq!(h, f.h);
                            assert_eq!(batch_equal_h(f, false), h);
                            assert_eq!(batch_equal_h(f, true), [0; 16]);
                        }
                    }
                }
            }
            for _ in 0..32 {
                assert_eq!(original.next_u64(), scheduler.next());
            }
            let (mut a, mut b) = (
                Rng::new(batch_seed(kind, seed)),
                Rng::new(batch_seed(kind, seed)),
            );
            for _ in 0..4 {
                let classes = batch_classes(&mut a);
                assert_eq!(classes, batch_classes(&mut b));
                for class in classes {
                    match kind {
                        BatchKind::Data => {
                            let _ = batch_original_data(&mut a, class, BATCH_BYTES);
                            assert!(batch_identical_data(&mut b, class, BATCH_BYTES)
                                .iter()
                                .all(|&x| x == 0));
                        }
                        BatchKind::Key => {
                            let _ = batch_original_h(&mut a, class);
                            assert_eq!(batch_identical_h(&mut b, class), [0; 16]);
                        }
                    }
                }
            }
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
    // Meaningful variable-length producer checks also retain a generic public
    // length rather than changing the normal RNG loop to a tiny fixed array.
    for len in [1, 15, 16, 17, 33, 1024] {
        let (mut a, mut b) = (Rng::new(71), Rng::new(71));
        let original = batch_original_data(&mut a, true, len);
        let zero = batch_identical_data(&mut b, true, len);
        assert_eq!(original.len(), len);
        assert_eq!(zero, vec![0; len]);
        assert_eq!(a.next_u64(), b.next_u64());
    }
    let data = vec![0x5a; BATCH_BYTES];
    let data_address = data.as_ptr() as usize;
    let mut rng = Rng::new(7);
    let inputs: Vec<Vec<GhashKey>> = [false, true]
        .iter()
        .map(|&c| vec![GhashKey::make(&mut rng, c, None, BatchGeneration::Literal)])
        .collect();
    for group in &inputs {
        assert_eq!(group[0].data_address(&data), data_address);
    }
    // All retained keys are fresh and their normal Drop is outside any timer.
}

#[test]
#[ignore = "diagnostic-only; requires corresponding sealed1024data failure on this live core"]
fn pr10_batch_data_controls() {
    batch_control_run::<Vec<u8>>("DATA");
}
#[test]
#[ignore = "diagnostic-only; requires corresponding sealed1024preparedH failure on this live core"]
fn pr10_batch_key_controls() {
    batch_control_run::<GhashKey>("KEY");
}
