// Supplemental diagnostics only. Production expressions and timing criteria stay unchanged.
#[repr(C, align(64))]
struct HistoryBytes { bytes: [u8; 1088] }

struct HistoryBuffer {
    storage: std::cell::RefCell<HistoryBytes>,
    offset: usize,
}

impl HistoryBuffer {
    fn new(offset: usize) -> Self {
        assert!(offset <= 48 && offset % 16 == 0);
        Self { storage: std::cell::RefCell::new(HistoryBytes { bytes: [0; 1088] }), offset }
    }
    fn bytes(&self) -> std::cell::Ref<'_, [u8]> {
        std::cell::Ref::map(self.storage.borrow(), |s| &s.bytes[self.offset..self.offset + 1024])
    }
    fn observe(&self, hardware_fence: bool) {
        // The opaque observation prevents removal of prior writes before equalization.
        black_box(&*self.bytes());
        if hardware_fence {
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        } else {
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
    fn copy(&self, source: &[u8], hardware_fence: bool) {
        self.storage.borrow_mut().bytes[self.offset..self.offset + 1024].copy_from_slice(black_box(source));
        self.observe(hardware_fence);
    }
    fn fill(&self, value: u8, hardware_fence: bool) {
        self.storage.borrow_mut().bytes[self.offset..self.offset + 1024].fill(black_box(value));
        self.observe(hardware_fence);
    }
    fn address(&self) -> usize { self.bytes().as_ptr() as usize }
}

fn history_calibrate<R>(target_ns: f64, mut rounds: usize, op: impl Fn(usize) -> R) -> (usize, f64) {
    for _ in 0..5 {
        let cost = diagnostic_cost(|| op(rounds));
        if (0.9 * target_ns..=1.1 * target_ns).contains(&cost) { break; }
        rounds = ((rounds as f64 * target_ns / cost).round().clamp(1.0, 1_048_576.0)) as usize;
    }
    // Report the cost of the returned count even if the last adjustment did not converge.
    let cost = diagnostic_cost(|| op(rounds));
    (rounds, cost)
}

// Both classes store identical zero bytes through the normal PRNG/Vec loop.
// Only class 0 retains the original generator's additional literal-zero clear.
#[inline(never)]
fn history_identical_zero_original_clear(rng: &mut Rng, class: bool) -> Vec<u8> {
    let zero_mask = black_box(0u8);
    let mut bytes: Vec<u8> = (0..1024)
        .map(|_| (black_box(rng.next_u64()) as u8) & black_box(zero_mask))
        .collect();
    if !class { bytes.fill(0); }
    bytes
}

#[test]
fn pr10_history_control_storage_check() {
    let zero = [0u8; 1024];
    let random_fixture = [0xa5u8; 1024];
    let final_bytes = [0x5au8; 1024];
    for offset in [0, 16, 32, 48] {
        let buffer = HistoryBuffer::new(offset);
        let address = buffer.address();
        assert_eq!(address % 64, offset);
        for source in [&zero, &random_fixture] {
            for fenced in [false, true] {
                buffer.copy(source, fenced);
                assert_eq!(&*buffer.bytes(), source);
                buffer.fill(0x5a, fenced);
                assert_eq!(buffer.address(), address);
                assert_eq!(&*buffer.bytes(), &final_bytes);
                buffer.copy(source, fenced);
                buffer.copy(&final_bytes, fenced);
                assert_eq!(buffer.address(), address);
                assert_eq!(&*buffer.bytes(), &final_bytes);
            }
        }
    }
    for seed in [0, 1, 0x9e37_79b9_7f4a_7c15] {
        let (mut fixed_rng, mut random_rng) = (Rng::new(seed), Rng::new(seed));
        let fixed = history_identical_zero_original_clear(&mut fixed_rng, false);
        let random = history_identical_zero_original_clear(&mut random_rng, true);
        assert_eq!(fixed, zero);
        assert_eq!(random, zero);
        assert_eq!(fixed_rng.next_u64(), random_rng.next_u64());
    }
}

#[test]
#[ignore = "supplemental history/dispatch diagnostic; never replaces production gates"]
fn pr10_actual_buffer_history_controls() {
    let root = std::path::PathBuf::from(std::env::var("PRATIQUE_DIAGNOSTIC_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let sensitivity = std::panic::catch_unwind(harness_detects_a_difference_of_about_one_percent).is_ok();
    let early_exit = std::panic::catch_unwind(harness_flags_an_early_exit_comparison_and_passes_ct_eq).is_ok();
    std::fs::write(root.join("history-positive-control-results.txt"),
        format!("sensitivity={sensitivity}\nearly_exit={early_exit}\n")).unwrap();
    println!("HISTORY positive sensitivity={sensitivity} early_exit={early_exit}");
    let offset: usize = std::env::var("PRATIQUE_HISTORY_OFFSET").unwrap_or_else(|_| "00".into()).parse().unwrap();
    let buffer = HistoryBuffer::new(offset);
    assert_eq!(buffer.address() % 64, offset);
    let prior = vec![0x33u8; 1024];
    let final_bytes = vec![0x5au8; 1024];
    let key = GhashKey::new(&0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128.to_be_bytes(), Backend::Portable);
    let _dit = Dit::on();
    let address = |_: &Vec<u8>| buffer.address();
    let op = |_: &Vec<u8>| key.hash(b"aad", black_box(&*buffer.bytes()));
    println!("HISTORY timed_address={} cacheline_offset={offset} final_identical_byte=90", buffer.address());
    diagnostic_measure::<true, _>("history_variable_then_fixed_fill", 0, diagnostic_equal_preparation,
        |input| { buffer.copy(input, false); buffer.fill(0x5a, false); }, op, address);
    diagnostic_measure::<true, _>("history_identical_then_fixed_fill", 0, diagnostic_equal_preparation,
        |_| { buffer.copy(&prior, false); buffer.fill(0x5a, false); }, op, address);
    diagnostic_measure::<true, _>("history_variable_then_fixed_copy", 0, diagnostic_equal_preparation,
        |input| { buffer.copy(input, false); buffer.copy(&final_bytes, false); }, op, address);
    diagnostic_measure::<true, _>("history_identical_then_fixed_copy", 0, diagnostic_equal_preparation,
        |_| { buffer.copy(&prior, false); buffer.copy(&final_bytes, false); }, op, address);
    diagnostic_measure::<true, _>("history_variable_then_fixed_fill_fenced", 0, diagnostic_equal_preparation,
        |input| { buffer.copy(input, true); buffer.fill(0x5a, true); }, op, address);
    diagnostic_measure::<true, _>("history_actual_variable_timed_bytes", 0, diagnostic_equal_preparation,
        |input| buffer.copy(input, false), op, address);
    // Varying input addresses are deliberate here; there is NO common overwrite
    // before timing. This retains the original class-specific last-store route.
    diagnostic_measure::<false, _>("history_original_extra_clear_identical_zero_bytes", 0,
        history_identical_zero_original_clear, |_| {},
        |input| key.hash(b"aad", black_box(input)), |input| input.as_ptr() as usize);
    let target = diagnostic_cost(|| key.hash(b"aad", black_box(&final_bytes)));
    let (copies, copy_cost) = history_calibrate(target, 1, |n| diagnostic_copy(black_box(&final_bytes), n));
    let (scans, scan_cost) = history_calibrate(target, 1, |n| diagnostic_scan(black_box(&final_bytes), n));
    println!("HISTORY calibrated target_ns={target:.6} copies={copies} copy_ns={copy_cost:.6} scans={scans} scan_ns={scan_cost:.6}");
    diagnostic_measure::<false, _>("history_iterative_matched_copy", 0, diagnostic_equal_preparation,
        |_| {}, |input| diagnostic_copy(input, copies), |input| input.as_ptr() as usize);
    diagnostic_measure::<false, _>("history_iterative_matched_scan", 0, diagnostic_equal_preparation,
        |_| {}, |input| diagnostic_scan(input, scans), |input| input.as_ptr() as usize);
}
