// Diagnostic-only H-row isolation. Included in an owned-source e2dd test build.
// Production expressions, lifecycle rules and the original timing judge are unchanged.

const H_REFERENCE_NAME: &str = "ghash [Portable] hash key H: 0 vs random";
type HInput = ([u8; 16], Vec<u8>);

// A separate fixture scheduler reproduces the owned test RNG. It never receives
// control-generator work, so that work cannot change subsequent labels or H.
#[derive(Clone)]
struct HFixtureRng(u64);
impl HFixtureRng {
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct HFixture {
    class: bool,
    h: [u8; 16],
    rng_before: u64,
}

fn h_seed(seed: u64) -> u64 {
    0xd0de_c7 ^ H_REFERENCE_NAME.len() as u64 ^ seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn h_original_classes(rng: &mut Rng) -> Vec<bool> {
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

fn h_fixture_batch(rng: &mut HFixtureRng) -> Vec<HFixture> {
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
            let rng_before = rng.0;
            let mut h = [0u8; 16];
            if class {
                for byte in &mut h {
                    *byte = rng.next() as u8;
                }
            }
            HFixture {
                class,
                h,
                rng_before,
            }
        })
        .collect()
}

// Literal original H generator: class 0 does no RNG/Vec work for H; class 1
// calls the original bytes(16) then converts it to the array. data.clone()
// and the outer nested sample allocations are retained by the recorder.
#[inline(never)]
fn h_original_input(rng: &mut Rng, class: bool, data: &Vec<u8>) -> HInput {
    let h = if class {
        rng.bytes(16).try_into().unwrap()
    } else {
        [0; 16]
    };
    (h, data.clone())
}

// Identical final H, while preserving class 1's RNG/allocation/normal stores.
// The opaque mask is applied BEFORE each generated Vec store. There is no
// common final overwrite, and class 0 retains the literal fixed-array path.
#[inline(never)]
fn h_identical_original_history(rng: &mut Rng, class: bool, data: &Vec<u8>) -> HInput {
    let h = if class {
        let mask = black_box(0u8);
        let bytes: Vec<u8> = (0..16)
            .map(|_| (rng.next_u64() as u8) & black_box(mask))
            .collect();
        bytes.try_into().unwrap()
    } else {
        [0; 16]
    };
    (h, data.clone())
}

// Fixture replay has equal H RNG/allocation/store work in both classes.
// It is a counterfactual, not a claim to reproduce original allocation history.
// Masking occurs before the normal stores, with no second normalization pass.
#[inline(never)]
fn h_equal_input(fixture: &HFixture, data: &Vec<u8>, identical: bool) -> HInput {
    let mut rng = HFixtureRng(fixture.rng_before);
    let mask = black_box(if identical {
        0
    } else {
        0u8.wrapping_sub(fixture.class as u8)
    });
    let bytes: Vec<u8> = (0..16)
        .map(|_| (rng.next() as u8) & black_box(mask))
        .collect();
    (bytes.try_into().unwrap(), data.clone())
}

#[derive(Clone, Copy)]
enum HGeneration {
    LiteralOriginal,
    IdenticalOriginalHistory,
    EqualReplay,
    IdenticalEqualReplay,
}
impl HGeneration {
    fn literal(self) -> bool {
        matches!(self, Self::LiteralOriginal | Self::IdenticalOriginalHistory)
    }
    fn identical(self) -> bool {
        matches!(
            self,
            Self::IdenticalOriginalHistory | Self::IdenticalEqualReplay
        )
    }
}

#[derive(Clone, Copy)]
enum HOperation {
    Full,
    PreparedHash,
    ConstructorDrop,
    ConstructorOnly,
    WipeOnly,
    KnownLeak(usize),
}

struct HTiming {
    duration: u32,
    key_address: usize,
}
fn h_duration(start: u64, end: u64) -> u32 {
    (end - start).min(u32::MAX as u64) as u32
}

fn h_require_native_tick(tick: u64) {
    assert_eq!(tick, 0, "H diagnostics reject forced clock quantization");
}

#[inline(always)]
fn h_full_operation((h, data): &HInput) -> [u8; 16] {
    GhashKey::new(h, Backend::Portable).hash(b"aad", data)
}

#[inline(never)]
fn h_time_full(clock: &Clock, input: &HInput) -> HTiming {
    let start = clock.now();
    black_box(h_full_operation(black_box(input)));
    let end = clock.now();
    // The original temporary's actual address is unavailable without changing
    // its storage. Zero means unobserved, not a real object at address zero.
    HTiming {
        duration: h_duration(start, end),
        key_address: 0,
    }
}

#[inline(never)]
fn h_time_prepared_hash(clock: &Clock, input: &HInput) -> HTiming {
    let key = GhashKey::new(&input.0, Backend::Portable);
    black_box(&key);
    let start = clock.now();
    black_box(key.hash(b"aad", black_box(&input.1)));
    let end = clock.now();
    let key_address = &key as *const GhashKey as usize;
    drop(key);
    HTiming {
        duration: h_duration(start, end),
        key_address,
    }
}

#[inline(never)]
fn h_time_constructor_drop(clock: &Clock, input: &HInput) -> HTiming {
    let start = clock.now();
    {
        let key = GhashKey::new(&black_box(input).0, Backend::Portable);
        black_box(&key);
    } // The fresh key is destroyed in place before the stop timestamp.
    let end = clock.now();
    HTiming {
        duration: h_duration(start, end),
        key_address: 0,
    }
}

// Explicit retained local storage is essential: the existing generic measure
// drops a returned operation value BEFORE its stop timestamp. This helper
// instead reads the stop timestamp before cleanup. The constructor's existing
// return/storage moves remain measured; compiler copies remain best effort.
#[inline(always)]
fn h_retained_construction<T>(mut now: impl FnMut() -> u64, make: impl FnOnce() -> T) -> HTiming {
    let start = now();
    let retained = make();
    black_box(&retained);
    let end = now();
    let key_address = &retained as *const T as usize;
    drop(retained);
    HTiming {
        duration: h_duration(start, end),
        key_address,
    }
}

#[inline(never)]
fn h_time_constructor_only(clock: &Clock, input: &HInput) -> HTiming {
    h_retained_construction(
        || clock.now(),
        || GhashKey::new(&black_box(input).0, Backend::Portable),
    )
}

#[inline(never)]
fn h_time_wipe_only(clock: &Clock, input: &HInput) -> HTiming {
    let mut key = GhashKey::new(&input.0, Backend::Portable);
    black_box(&key);
    let start = clock.now();
    black_box(&mut key).wipe();
    let end = clock.now();
    let key_address = &key as *const GhashKey as usize;
    black_box(&key);
    drop(key); // Its normal second wipe is untimed. No key is timed twice.
    HTiming {
        duration: h_duration(start, end),
        key_address,
    }
}

#[inline(never)]
fn h_known_delay(iterations: usize) -> u64 {
    let mut x = black_box(0x1234_5678_9abc_def0u64);
    for _ in 0..iterations {
        x = black_box(x.rotate_left(13).wrapping_add(0x5a5a_3c3c_a5a5_c3c3));
    }
    x
}

#[inline(never)]
fn h_time_known_leak(clock: &Clock, input: &HInput, class: bool, iterations: usize) -> HTiming {
    let start = clock.now();
    black_box(h_full_operation(black_box(input)));
    if black_box(class) {
        black_box(h_known_delay(iterations));
    }
    let end = clock.now();
    HTiming {
        duration: h_duration(start, end),
        key_address: 0,
    }
}

fn h_cost<R>(op: impl Fn() -> R) -> f64 {
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

fn h_report(name: &str, samples: &[(u32, bool)]) -> Report {
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
        .fold(uncropped_t.abs(), |v, c| v.max(c.1.abs()));
    let per_call = std::iter::once((1.0, u32::MAX))
        .chain(CROP_LEVELS.iter().map(|&p| (p, pct(p))))
        .map(|(p, cutoff)| {
            let (mean, se) = paired_mean_se(samples, cutoff);
            println!(
                "H_DIAGNOSTIC {name} crop={p} cutoff={cutoff} delta_ns={mean:.12} se_ns={se:.12}"
            );
            (p, mean, se)
        })
        .collect();
    Report {
        name: name.into(),
        samples: samples.len(),
        reps: 1,
        uncropped_t,
        max_t,
        median_ns: pct(0.5),
        crops,
        per_call,
    }
}

fn h_measure(
    name: &str,
    seed: u64,
    generation: HGeneration,
    operation: HOperation,
    seconds: f64,
) -> Report {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let mut prefix = std::io::BufWriter::new(
        std::fs::File::create(root.join(format!("{name}-seed{seed}.fixtures.txt"))).unwrap(),
    );
    writeln!(
        prefix,
        "original_name={H_REFERENCE_NAME:?} seed={seed} reps=1 first_batch=warmup"
    )
    .unwrap();
    let clock = Clock::new();
    h_require_native_tick(clock.tick);
    let coarse = clock.coarse_tick();
    assert!(
        coarse.is_none(),
        "H diagnostics require a native fine clock, got {coarse:?}"
    );
    assert!(std::env::var("PRATIQUE_TIMING_REPS").map_or(true, |v| v.trim() == "1"));
    let mut literal_rng = Rng::new(h_seed(seed));
    let mut scheduler = HFixtureRng::new(h_seed(seed));
    let data = vec![0x5au8; 128];
    let mut samples = Vec::new();
    let mut raw = Vec::new();
    let start = Instant::now();
    let mut batch = 0;
    while batch == 0 || samples.is_empty() || start.elapsed() < Duration::from_secs_f64(seconds) {
        // Literal rows do not precompute fixtures before allocating their
        // inputs. Replay rows explicitly do, and are labeled accordingly.
        let mut fixtures = if generation.literal() {
            Vec::new()
        } else {
            h_fixture_batch(&mut scheduler)
        };
        let classes = if generation.literal() {
            h_original_classes(&mut literal_rng)
        } else {
            fixtures.iter().map(|f| f.class).collect()
        };
        let inputs: Vec<Vec<HInput>> = classes
            .iter()
            .enumerate()
            .map(|(i, &class)| {
                vec![match generation {
                    HGeneration::LiteralOriginal => {
                        h_original_input(&mut literal_rng, class, &data)
                    }
                    HGeneration::IdenticalOriginalHistory => {
                        h_identical_original_history(&mut literal_rng, class, &data)
                    }
                    HGeneration::EqualReplay => h_equal_input(&fixtures[i], &data, false),
                    HGeneration::IdenticalEqualReplay => h_equal_input(&fixtures[i], &data, true),
                }]
            })
            .collect();
        let mut batch_raw = Vec::with_capacity(classes.len());
        for (index, (&class, group)) in classes.iter().zip(&inputs).enumerate() {
            let input = &group[0];
            let timed = match operation {
                HOperation::Full => h_time_full(&clock, input),
                HOperation::PreparedHash => h_time_prepared_hash(&clock, input),
                HOperation::ConstructorDrop => h_time_constructor_drop(&clock, input),
                HOperation::ConstructorOnly => h_time_constructor_only(&clock, input),
                HOperation::WipeOnly => h_time_wipe_only(&clock, input),
                HOperation::KnownLeak(n) => h_time_known_leak(&clock, input, class, n),
            };
            // All address and byte observations follow the stop timestamp.
            let h_address = input.0.as_ptr() as usize;
            let timed_address = if timed.key_address == 0 {
                h_address
            } else {
                timed.key_address
            };
            batch_raw.push((
                timed.duration,
                class,
                input as *const HInput as usize,
                timed_address,
                input.1.as_ptr() as usize,
                timed.key_address,
                batch,
                index,
                u128::from_be_bytes(input.0),
                h_address,
            ));
        }
        if generation.literal() {
            fixtures = h_fixture_batch(&mut scheduler);
        }
        assert_eq!(fixtures.len(), inputs.len());
        for (index, (fixture, row)) in fixtures.iter().zip(batch_raw).enumerate() {
            assert_eq!(fixture.class, classes[index]);
            let expected = if generation.identical() {
                [0; 16]
            } else {
                fixture.h
            };
            assert_eq!(
                inputs[index][0].0, expected,
                "fixture mismatch at batch {batch}/{index}"
            );
            assert_eq!(inputs[index][0].1, data);
            writeln!(
                prefix,
                "{batch},{index},{},{},{},{}",
                fixture.class as u8,
                u128::from_be_bytes(fixture.h),
                fixture.rng_before,
                row.8
            )
            .unwrap();
            if batch != 0 {
                samples.push((row.0, row.1));
                raw.push((row, u128::from_be_bytes(fixture.h), fixture.rng_before));
            }
        }
        batch += 1;
    }
    let mut file = std::io::BufWriter::new(
        std::fs::File::create(root.join(format!("{name}-seed{seed}.csv"))).unwrap(),
    );
    writeln!(file, "duration_ns,class,input_address,timed_address,data_address,key_address,batch,sample,h_value,fixture_h_value,rng_before,h_address").unwrap();
    for (
        (dt, class, input, timed_address, data, key, batch, sample, h, h_address),
        fixture_h,
        rng_before,
    ) in raw
    {
        writeln!(file, "{dt},{},{input},{timed_address},{data},{key},{batch},{sample},{h},{fixture_h},{rng_before},{h_address}", class as u8).unwrap();
    }
    println!("H_DIAGNOSTIC metadata name={name} seed={seed} original_name={H_REFERENCE_NAME:?} coarse_tick={coarse:?} tick_override_ns={} reps=1 batches={batch} input_fixture_checks=passed", clock.tick);
    let report = h_report(name, &samples);
    report.print();
    report
}

#[test]
fn pr10_h_fixture_and_cleanup_check() {
    h_require_native_tick(0);
    for tick in [1, 2, 42] {
        assert!(std::panic::catch_unwind(|| h_require_native_tick(tick)).is_err());
    }
    for seed in [0, 1] {
        let mut original = Rng::new(h_seed(seed));
        let mut fixture = HFixtureRng::new(h_seed(seed));
        // Includes the complete warmup and three measured-sized batches.
        for _batch in 0..4 {
            let classes = h_original_classes(&mut original);
            let expected = h_fixture_batch(&mut fixture);
            for (&class, f) in classes.iter().zip(&expected) {
                let input = h_original_input(&mut original, class, &vec![0x5a; 128]);
                assert_eq!(class, f.class);
                assert_eq!(input.0, f.h);
                assert_eq!(h_equal_input(f, &input.1, false), input);
                assert_eq!(h_equal_input(f, &input.1, true).0, [0; 16]);
            }
        }
        for _ in 0..32 {
            assert_eq!(original.next_u64(), fixture.next());
        }
        let (mut original, mut masked) = (Rng::new(h_seed(seed)), Rng::new(h_seed(seed)));
        for _batch in 0..4 {
            let a = h_original_classes(&mut original);
            let b = h_original_classes(&mut masked);
            assert_eq!(a, b);
            for class in a {
                let data = vec![0x5a; 128];
                let _ = h_original_input(&mut original, class, &data);
                assert_eq!(
                    h_identical_original_history(&mut masked, class, &data).0,
                    [0; 16]
                );
            }
        }
        assert_eq!(original.next_u64(), masked.next_u64());
    }
    use std::cell::RefCell;
    let events = RefCell::new(Vec::new());
    struct Tracked<'a>(&'a RefCell<Vec<&'static str>>);
    impl Drop for Tracked<'_> {
        fn drop(&mut self) {
            self.0.borrow_mut().push("cleanup");
        }
    }
    let mut tick = 0;
    let result = h_retained_construction(
        || {
            tick += 1;
            events
                .borrow_mut()
                .push(if tick == 1 { "start" } else { "stop" });
            tick
        },
        || {
            events.borrow_mut().push("construct");
            Tracked(&events)
        },
    );
    assert_eq!(
        &*events.borrow(),
        &["start", "construct", "stop", "cleanup"]
    );
    assert_eq!(result.duration, 1);
    for h in [[0; 16], [0x5a; 16]] {
        let mut fresh = GhashKey::new(&h, Backend::Portable);
        fresh.wipe();
        assert!(fresh.is_wiped());
    }
}

#[test]
#[ignore = "diagnostic-only H preparation isolation; never replaces sealed production gates"]
fn pr10_h_preparation_controls() {
    use std::io::Write;
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let sensitivity =
        std::panic::catch_unwind(harness_detects_a_difference_of_about_one_percent).is_ok();
    let early_exit =
        std::panic::catch_unwind(harness_flags_an_early_exit_comparison_and_passes_ct_eq).is_ok();
    let _dit = Dit::on();
    let seconds: f64 = std::env::var("PRATIQUE_H_DIAGNOSTIC_SECS")
        .unwrap_or_else(|_| "3".into())
        .parse()
        .unwrap();
    assert!(seconds.is_finite() && seconds >= 0.0);
    let fixture = ([0u8; 16], vec![0x5a; 128]);
    let target = h_cost(|| h_full_operation(black_box(&fixture)));
    let mut delay = ((0.02 * target / h_cost(|| h_known_delay(128))) * 128.0)
        .round()
        .max(1.0) as usize;
    for _ in 0..4 {
        let cost = h_cost(|| h_known_delay(delay));
        if (0.015 * target..=0.025 * target).contains(&cost) {
            break;
        }
        delay = ((delay as f64 * 0.02 * target / cost).round().max(1.0)) as usize;
    }
    let extra = h_cost(|| h_known_delay(delay));
    let delay_ratio = extra / target;
    let calibration_in_range = (0.015..=0.025).contains(&delay_ratio);
    println!("H_DIAGNOSTIC known_leak calibration target_ns={target:.9} delay_iterations={delay} extra_ns={extra:.9} extra_ratio={delay_ratio:.9} in_range={calibration_in_range}");
    let rows = [
        (
            "h01_literal_original_full",
            HGeneration::LiteralOriginal,
            HOperation::Full,
        ),
        (
            "h02_identical_original_history",
            HGeneration::IdenticalOriginalHistory,
            HOperation::Full,
        ),
        (
            "h03_equal_work_variable_h",
            HGeneration::EqualReplay,
            HOperation::Full,
        ),
        (
            "h04_fresh_prepared_hash128_only",
            HGeneration::EqualReplay,
            HOperation::PreparedHash,
        ),
        (
            "h05_constructor_preparation_drop",
            HGeneration::EqualReplay,
            HOperation::ConstructorDrop,
        ),
        (
            "h06_constructor_preparation_only",
            HGeneration::EqualReplay,
            HOperation::ConstructorOnly,
        ),
        (
            "h07_fresh_in_place_wipe_only",
            HGeneration::EqualReplay,
            HOperation::WipeOnly,
        ),
        (
            "h_negative_identical_operation",
            HGeneration::IdenticalEqualReplay,
            HOperation::Full,
        ),
        (
            "h_positive_matched_cost_leak",
            HGeneration::IdenticalEqualReplay,
            HOperation::KnownLeak(delay),
        ),
    ];
    let mut statuses =
        std::io::BufWriter::new(std::fs::File::create(root.join("h-control-results.txt")).unwrap());
    writeln!(statuses, "sensitivity={sensitivity}\nearly_exit={early_exit}\nknown_leak_target_ns={target}\nknown_leak_extra_ns={extra}\nknown_leak_iterations={delay}\nknown_leak_extra_ratio={delay_ratio}\nknown_leak_calibration_in_range={calibration_in_range}").unwrap();
    for (name, generation, operation) in rows {
        let first = h_measure(name, 0, generation, operation, seconds);
        let again = h_measure(name, 1, generation, operation, seconds);
        let failure = judge(&first, &again);
        println!("H_DIAGNOSTIC outcome name={name} repeated_failure={failure:?}");
        writeln!(statuses, "{name}_repeated_failure={}", failure.is_some()).unwrap();
        if name == "h_positive_matched_cost_leak" {
            let detected = first.max_t > LEAK_T && again.max_t > LEAK_T;
            writeln!(statuses, "matched_cost_positive_detected={}", detected).unwrap();
            writeln!(
                statuses,
                "matched_cost_positive_healthy={}",
                detected && calibration_in_range
            )
            .unwrap();
        }
        if name == "h_negative_identical_operation" {
            writeln!(
                statuses,
                "identical_operation_negative_passed={}",
                failure.is_none()
            )
            .unwrap();
        }
        statuses.flush().unwrap();
    }
    // A collection's exit success means data was saved. Positive/negative and
    // all unchanged normal-gate outcomes must be interpreted separately.
}
