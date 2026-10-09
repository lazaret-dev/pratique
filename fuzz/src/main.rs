//! A small coverage-guided fuzzer for `pratique`, with no dependencies.
//!
//! The library and this program are compiled with LLVM's SanitizerCoverage counters (stable
//! rustc can emit them: `-C passes=sancov-module -C llvm-args=-sanitizer-coverage-inline-8bit-counters`,
//! see `run_all.sh`). The counters register themselves through `__sanitizer_cov_8bit_counters_init`
//! below; after each input the engine looks for edges it has not seen (or seen a different number
//! of times, in AFL's buckets), keeps the inputs that find some, and mutates the kept ones.
//!
//! What it reports, per target (see `targets.rs`):
//!   * a panic (this includes arithmetic overflow, failed `debug_assert!`s and the `assert!`s that
//!     check the targets' own invariants, such as "a tampered certificate chain is never accepted");
//!   * a crash that no panic handler sees (stack overflow, abort), found by a supervisor process
//!     that keeps the current input in a file;
//!   * a hang (an input that runs longer than `--timeout`);
//!   * memory bloat: an input that makes the target allocate far more than a parser should for its
//!     size, or a single allocation or total above a hard cap (a claimed length trusted before the
//!     bytes are there).
//!
//! Commands: `list`, `check`, `seed <target> <dir>`, `run <target> [options]`, `replay <target>
//! <files>`, `merge <target> --into <dir> <dirs>`. Unix only (it writes the current input with
//! `pwrite`).

mod cms_targets;
mod h2_targets;
mod h3_targets;
mod inflate_targets;
mod key_targets;
mod log_targets;
mod quic_state_targets;
mod quic_targets;
mod seed_data;
mod sigstore_targets;
mod targets;

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------------------ coverage

static REGIONS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());

/// Adds the bytes `start..end` to `list` (address, length), merging with any range they touch.
///
/// Each instrumented module's constructor reports "its" counters, but on some platforms (macOS) it
/// reports the whole counter section every time, so the same bytes arrive once per module (26 times
/// in the first campaign there). Kept as separate regions they would be reset and scanned that many
/// times per input and every edge counted that many times, which made the cheap targets about ten
/// times slower than they should be.
fn add_region(list: &mut Vec<(usize, usize)>, start: usize, end: usize) {
    let (mut s, mut e) = (start, end);
    list.retain(|&(rs, rl)| {
        let re = rs + rl;
        if rs <= e && s <= re {
            s = s.min(rs);
            e = e.max(re);
            false
        } else {
            true
        }
    });
    list.push((s, e - s));
}

/// Called by the instrumented modules' constructors with the range of their counters.
#[no_mangle]
pub extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    if start.is_null() || stop <= start {
        return;
    }
    if let Ok(mut r) = REGIONS.lock() {
        add_region(&mut r, start as usize, stop as usize);
    }
}

#[no_mangle]
pub extern "C" fn __sanitizer_cov_pcs_init(_beg: *const usize, _end: *const usize) {}

fn regions() -> Vec<&'static mut [u8]> {
    let r = REGIONS.lock().unwrap();
    // SAFETY: each range was handed to us by the module that owns it, stays mapped for the life of
    // the process and is only touched by this thread and (as plain byte increments) the code
    // under test, which runs on this thread.
    r.iter().map(|&(p, n)| unsafe { std::slice::from_raw_parts_mut(p as *mut u8, n) }).collect()
}

fn counter_total() -> usize {
    REGIONS.lock().unwrap().iter().map(|r| r.1).sum()
}

fn reset_counters(regions: &mut [&'static mut [u8]]) {
    for r in regions.iter_mut() {
        r.fill(0);
    }
}

fn bucket(count: u8) -> u8 {
    match count {
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// Edges (and hit-count buckets) seen so far.
struct Virgin {
    seen: Vec<u8>,
    edges: usize,
}

impl Virgin {
    fn new() -> Virgin {
        Virgin { seen: vec![0; counter_total()], edges: 0 }
    }

    /// Records the counters of the run that just finished; true if any edge or bucket is new.
    fn absorb(&mut self, regions: &[&'static mut [u8]]) -> bool {
        let mut found = false;
        let mut base = 0;
        for r in regions {
            let (head, words, tail) = unsafe { r.align_to::<u64>() };
            let mut visit = |offset: usize, byte: u8| {
                let b = bucket(byte);
                let s = &mut self.seen[base + offset];
                if *s & b == 0 {
                    if *s == 0 {
                        self.edges += 1;
                    }
                    *s |= b;
                    found = true;
                }
            };
            for (i, &c) in head.iter().enumerate() {
                if c != 0 {
                    visit(i, c);
                }
            }
            for (w, &word) in words.iter().enumerate() {
                if word == 0 {
                    continue;
                }
                for (k, c) in word.to_ne_bytes().into_iter().enumerate() {
                    if c != 0 {
                        visit(head.len() + w * 8 + k, c);
                    }
                }
            }
            for (i, &c) in tail.iter().enumerate() {
                if c != 0 {
                    visit(head.len() + words.len() * 8 + i, c);
                }
            }
            base += r.len();
        }
        found
    }
}

// ------------------------------------------------------------------------------------ allocation

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static SINGLE_LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);
static LIVE_LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);
static REPORTING: AtomicBool = AtomicBool::new(false);
static REASON_FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

fn die(reason: &str) -> ! {
    if !REPORTING.swap(true, Ordering::SeqCst) {
        if let Ok(g) = REASON_FILE.try_lock() {
            if let Some(p) = g.as_ref() {
                let _ = fs::write(p, reason);
            }
        }
        eprintln!("fuzz: {reason}");
    }
    std::process::abort();
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() > SINGLE_LIMIT.load(Ordering::Relaxed) && !REPORTING.load(Ordering::Relaxed) {
            die(&format!("oom: a single allocation of {} bytes", layout.size()));
        }
        let p = System.alloc(layout);
        if !p.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
            if now > LIVE_LIMIT.load(Ordering::Relaxed) && !REPORTING.load(Ordering::Relaxed) {
                die(&format!("oom: {now} bytes live at once"));
            }
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.size() > SINGLE_LIMIT.load(Ordering::Relaxed) && !REPORTING.load(Ordering::Relaxed) {
            die(&format!("oom: a single allocation of {} bytes", layout.size()));
        }
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            let now = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
            if now > LIVE_LIMIT.load(Ordering::Relaxed) && !REPORTING.load(Ordering::Relaxed) {
                die(&format!("oom: {now} bytes live at once"));
            }
        }
        p
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size > SINGLE_LIMIT.load(Ordering::Relaxed) && !REPORTING.load(Ordering::Relaxed) {
            die(&format!("oom: a single allocation of {new_size} bytes"));
        }
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            let now = if new_size >= layout.size() {
                LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed) + (new_size - layout.size())
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed) - (layout.size() - new_size)
            };
            PEAK.fetch_max(now, Ordering::Relaxed);
            if now > LIVE_LIMIT.load(Ordering::Relaxed) && !REPORTING.load(Ordering::Relaxed) {
                die(&format!("oom: {now} bytes live at once"));
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

// ------------------------------------------------------------------------------------ rng

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

fn fnv(data: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

// ------------------------------------------------------------------------------------ mutation

const INTERESTING_8: [u8; 12] = [0, 1, 2, 0x7f, 0x80, 0xfe, 0xff, 0x10, 0x20, 0x30, 0x04, 0x03];
const INTERESTING_16: [u16; 12] = [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xfffe, 0xffff, 0x0303, 0x4000];
const INTERESTING_32: [u32; 8] = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x00ff_ffff, 0x0100_0000, 0x4000];

fn mutate(rng: &mut Rng, data: &mut Vec<u8>, other: &[u8], dict: &[&[u8]], max_len: usize) {
    let rounds = 1 + rng.below(5);
    for _ in 0..rounds {
        let n = data.len();
        match rng.below(16) {
            0 if n > 0 => {
                let i = rng.below(n);
                data[i] ^= 1 << rng.below(8);
            }
            1 if n > 0 => {
                let i = rng.below(n);
                data[i] = rng.next() as u8;
            }
            2 if n > 0 => {
                let i = rng.below(n);
                data[i] = INTERESTING_8[rng.below(INTERESTING_8.len())];
            }
            3 if n > 0 => {
                let i = rng.below(n);
                let d = 1 + rng.below(16) as u8;
                data[i] = if rng.chance(50) { data[i].wrapping_add(d) } else { data[i].wrapping_sub(d) };
            }
            4 if n >= 2 => {
                let i = rng.below(n - 1);
                data[i..i + 2].copy_from_slice(&INTERESTING_16[rng.below(INTERESTING_16.len())].to_be_bytes());
            }
            5 if n >= 4 => {
                let i = rng.below(n - 3);
                data[i..i + 4].copy_from_slice(&INTERESTING_32[rng.below(INTERESTING_32.len())].to_be_bytes());
            }
            6 if n < max_len => {
                let i = rng.below(n + 1);
                let k = 1 + rng.below(8).min(max_len - n - 1);
                let bytes: Vec<u8> = (0..k).map(|_| rng.next() as u8).collect();
                data.splice(i..i, bytes);
            }
            7 if n > 1 => {
                // delete a range
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(16));
                data.drain(i..i + k);
            }
            8 if n > 0 && n < max_len => {
                // duplicate a range
                let i = rng.below(n);
                let k = 1 + rng.below((n - i).min(32));
                let k = k.min(max_len - n);
                let chunk = data[i..i + k].to_vec();
                let at = rng.below(n + 1);
                data.splice(at..at, chunk);
            }
            9 if !other.is_empty() && n < max_len => {
                // splice a piece of another corpus entry
                let i = rng.below(other.len());
                let k = (1 + rng.below((other.len() - i).min(64))).min(max_len - n);
                let at = rng.below(n + 1);
                data.splice(at..at, other[i..i + k].iter().copied());
            }
            10 if !other.is_empty() && n > 0 => {
                // overwrite with a piece of another entry
                let i = rng.below(other.len());
                let k = (1 + rng.below((other.len() - i).min(32))).min(n);
                let at = rng.below(n - k + 1);
                data[at..at + k].copy_from_slice(&other[i..i + k]);
            }
            11 if !dict.is_empty() => {
                let tok = dict[rng.below(dict.len())];
                if rng.chance(50) && n >= tok.len() && !tok.is_empty() {
                    let at = rng.below(n - tok.len() + 1);
                    data[at..at + tok.len()].copy_from_slice(tok);
                } else if n + tok.len() <= max_len {
                    let at = rng.below(n + 1);
                    data.splice(at..at, tok.iter().copied());
                }
            }
            12 if n > 1 => {
                let (i, j) = (rng.below(n), rng.below(n));
                data.swap(i, j);
            }
            13 if n > 1 => {
                // truncate
                let k = 1 + rng.below(n - 1);
                data.truncate(k);
            }
            14 if n > 2 => {
                // bump a length-looking pair up or down by one
                let i = rng.below(n - 1);
                let v = u16::from_be_bytes([data[i], data[i + 1]]);
                let v = if rng.chance(50) { v.wrapping_add(1) } else { v.wrapping_sub(1) };
                data[i..i + 2].copy_from_slice(&v.to_be_bytes());
            }
            _ if n > 0 => {
                let i = rng.below(n);
                data[i] = data[i].wrapping_add(rng.below(256) as u8);
            }
            _ => {}
        }
    }
    data.truncate(max_len);
}

// ------------------------------------------------------------------------------------ options

struct Options {
    target: String,
    corpus: PathBuf,
    artifacts: PathBuf,
    seconds: u64,
    execs: u64,
    seed: u64,
    timeout: u64,
    max_len: Option<usize>,
    max_crashes: usize,
    extra: Vec<String>,
}

fn parse_options(args: &[String]) -> Options {
    let mut o = Options {
        target: String::new(),
        corpus: PathBuf::new(),
        artifacts: PathBuf::from("artifacts"),
        seconds: 60,
        execs: u64::MAX,
        seed: 1,
        timeout: 5,
        max_len: None,
        max_crashes: 20,
        extra: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut value = || {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| usage(&format!("{a} needs a value")))
        };
        match a {
            "--corpus" => o.corpus = PathBuf::from(value()),
            "--artifacts" => o.artifacts = PathBuf::from(value()),
            "--seconds" => o.seconds = value().parse().unwrap_or_else(|_| usage("--seconds: a number")),
            "--execs" => o.execs = value().parse().unwrap_or_else(|_| usage("--execs: a number")),
            "--seed" => o.seed = value().parse().unwrap_or_else(|_| usage("--seed: a number")),
            "--timeout" => o.timeout = value().parse().unwrap_or_else(|_| usage("--timeout: seconds")),
            "--max-len" => o.max_len = Some(value().parse().unwrap_or_else(|_| usage("--max-len: a number"))),
            "--max-crashes" => o.max_crashes = value().parse().unwrap_or_else(|_| usage("--max-crashes: a number")),
            "--into" => o.extra.insert(0, format!("--into={}", value())),
            s if s.starts_with("--") => usage(&format!("unknown option {s}")),
            s => {
                if o.target.is_empty() {
                    o.target = s.to_string();
                } else {
                    o.extra.push(s.to_string());
                }
            }
        }
        i += 1;
    }
    if o.corpus.as_os_str().is_empty() && !o.target.is_empty() {
        o.corpus = PathBuf::from("corpus").join(&o.target);
    }
    o
}

fn usage(msg: &str) -> ! {
    eprintln!("{msg}\n");
    eprintln!(
        "usage: pratique_fuzz <command>\n\
         \x20 list                                   the targets\n\
         \x20 check                                  is the coverage instrumentation there?\n\
         \x20 seed <target> <dir>                    write the target's seed inputs\n\
         \x20 run <target> [--corpus DIR] [--artifacts DIR] [--seconds N] [--execs N] [--seed N]\n\
         \x20                [--timeout SECS] [--max-len N] [--max-crashes N]\n\
         \x20 replay <target> <files...>             run saved inputs once (crashes, regressions)\n\
         \x20 merge <target> --into DIR <dirs...>    keep only inputs that add coverage"
    );
    std::process::exit(2);
}

// ------------------------------------------------------------------------------------ running

static EXEC_START_MS: AtomicU64 = AtomicU64::new(0);
static PANIC_NOTE: Mutex<String> = Mutex::new(String::new());
static EPOCH: Mutex<Option<Instant>> = Mutex::new(None);

fn now_ms() -> u64 {
    let mut e = EPOCH.lock().unwrap();
    let start = *e.get_or_insert_with(Instant::now);
    start.elapsed().as_millis() as u64 + 1
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "panic".to_string()
        };
        if let Ok(mut n) = PANIC_NOTE.lock() {
            *n = format!("{loc}: {}", msg.chars().take(120).collect::<String>());
        }
    }));
}

struct Runner {
    run: fn(&[u8]),
    regions: Vec<&'static mut [u8]>,
    current: Option<fs::File>,
    scratch: Vec<u8>,
}

enum Outcome {
    Fine,
    Panic(String),
}

impl Runner {
    fn new(target: &targets::Target, current_path: Option<&Path>) -> Runner {
        let current = current_path.map(|p| fs::OpenOptions::new().create(true).write(true).truncate(true).open(p).expect("cannot create the current-input file"));
        Runner { run: target.run, regions: regions(), current, scratch: Vec::new() }
    }

    /// Runs one input. Returns what happened and how much more memory the run needed at its peak.
    fn exec(&mut self, data: &[u8]) -> (Outcome, usize) {
        if let Some(f) = &self.current {
            self.scratch.clear();
            self.scratch.extend_from_slice(&(data.len() as u32).to_le_bytes());
            self.scratch.extend_from_slice(data);
            let _ = f.write_all_at(&self.scratch, 0);
        }
        reset_counters(&mut self.regions);
        let base = LIVE.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        EXEC_START_MS.store(now_ms(), Ordering::Relaxed);
        let r = catch_unwind(AssertUnwindSafe(|| (self.run)(data)));
        EXEC_START_MS.store(0, Ordering::Relaxed);
        let extra = PEAK.load(Ordering::Relaxed).saturating_sub(base);
        match r {
            Ok(()) => (Outcome::Fine, extra),
            Err(_) => (Outcome::Panic(std::mem::take(&mut *PANIC_NOTE.lock().unwrap())), extra),
        }
    }
}

/// Stops the process if one input runs longer than `timeout` seconds. With `parent` set it also
/// stops when the parent process is gone: a supervisor killed from outside (a campaign that was
/// interrupted) must not leave its child fuzzing for the rest of its time.
fn spawn_watchdog(timeout: u64, parent: Option<u32>) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(p) = parent {
            if std::os::unix::process::parent_id() != p {
                std::process::exit(0);
            }
        }
        let started = EXEC_START_MS.load(Ordering::Relaxed);
        if started != 0 && now_ms().saturating_sub(started) > timeout * 1000 {
            die(&format!("timeout: one input ran for more than {timeout} s"));
        }
    });
}

fn save(dir: &Path, prefix: &str, data: &[u8]) -> PathBuf {
    let _ = fs::create_dir_all(dir);
    let path = dir.join(format!("{prefix}-{:016x}", fnv(data)));
    let _ = fs::write(&path, data);
    path
}

fn read_dir_files(dir: &Path) -> Vec<Vec<u8>> {
    let mut names: Vec<_> = fs::read_dir(dir).map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default();
    names.sort();
    names.into_iter().filter_map(|p| fs::read(p).ok()).collect()
}

fn find_target(name: &str) -> targets::Target {
    targets::all().into_iter().chain(targets::selftests()).find(|t| t.name == name).unwrap_or_else(|| usage(&format!("unknown target {name:?}; try `list`")))
}

/// The fuzzing loop of one process (the supervisor runs this in a child).
fn child(o: &Options) -> i32 {
    let target = find_target(&o.target);
    install_panic_hook();
    if counter_total() == 0 {
        eprintln!("fuzz: no coverage counters found: build with the RUSTFLAGS in run_all.sh");
        return 2;
    }
    let pid = std::process::id();
    let _ = fs::create_dir_all(&o.artifacts);
    let current_path = o.artifacts.join(format!(".current-{pid}"));
    let reason_path = o.artifacts.join(format!(".reason-{pid}"));
    *REASON_FILE.lock().unwrap() = Some(reason_path);
    SINGLE_LIMIT.store(256 << 20, Ordering::Relaxed);
    LIVE_LIMIT.store(1 << 30, Ordering::Relaxed);
    spawn_watchdog(o.timeout, Some(std::os::unix::process::parent_id()));

    let max_len = o.max_len.unwrap_or(target.max_len);
    let mut runner = Runner::new(&target, Some(&current_path));
    let mut virgin = Virgin::new();
    let mut rng = Rng::new(o.seed ^ (pid as u64) << 20);
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    let mut seen_panics: HashSet<String> = HashSet::new();
    let mut crashes = 0usize;
    let mut bloat = 0usize;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(o.seconds);

    let mut initial = read_dir_files(&o.corpus);
    let from_disk = initial.len();
    initial.extend((target.seeds)());
    initial.push(Vec::new());
    for data in initial {
        let (outcome, extra) = runner.exec(&data);
        match outcome {
            Outcome::Fine => {
                virgin.absorb(&runner.regions);
                let _ = extra;
                corpus.push(data);
            }
            Outcome::Panic(note) => {
                eprintln!("fuzz: a seed or corpus input panics: {note}");
                if seen_panics.insert(note) {
                    let p = save(&o.artifacts, "crash", &data);
                    eprintln!("fuzz: saved as {}", p.display());
                    crashes += 1;
                }
            }
        }
    }
    eprintln!("fuzz[{}]: {} corpus files ({} from disk), {} edges so far", target.name, corpus.len(), from_disk, virgin.edges);

    let mut execs = 0u64;
    let mut last_report = Instant::now();
    let mut last_new = Instant::now();
    while execs < o.execs {
        if execs % 128 == 0 {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if now.duration_since(last_report) >= Duration::from_secs(10) {
                last_report = now;
                let rate = execs as f64 / started.elapsed().as_secs_f64();
                eprintln!(
                    "fuzz[{}]: #{execs} edges {} corpus {} exec/s {:.0} crashes {} bloat {} (last new coverage {} s ago)",
                    target.name,
                    virgin.edges,
                    corpus.len(),
                    rate,
                    crashes,
                    bloat,
                    last_new.elapsed().as_secs()
                );
            }
        }
        execs += 1;
        let mut data = corpus[if rng.chance(40) { corpus.len() - 1 - rng.below(corpus.len().min(8)) } else { rng.below(corpus.len()) }].clone();
        let other = if rng.chance(30) { corpus[rng.below(corpus.len())].clone() } else { Vec::new() };
        mutate(&mut rng, &mut data, &other, target.dict, max_len);
        let (outcome, extra) = runner.exec(&data);
        match outcome {
            Outcome::Fine => {
                let budget = target.alloc_base + target.alloc_per_byte * data.len();
                if extra > budget {
                    bloat += 1;
                    let p = save(&o.artifacts, "bloat", &data);
                    eprintln!("fuzz[{}]: {} bytes allocated for a {}-byte input (budget {}): {}", target.name, extra, data.len(), budget, p.display());
                    if bloat as usize >= o.max_crashes {
                        break;
                    }
                }
                if virgin.absorb(&runner.regions) {
                    last_new = Instant::now();
                    let path = o.corpus.join(format!("{:016x}", fnv(&data)));
                    let _ = fs::create_dir_all(&o.corpus);
                    let _ = fs::write(path, &data);
                    corpus.push(data);
                }
            }
            Outcome::Panic(note) => {
                if seen_panics.insert(note.clone()) {
                    let p = save(&o.artifacts, "crash", &data);
                    eprintln!("fuzz[{}]: PANIC {note}\n  input saved as {}", target.name, p.display());
                    crashes += 1;
                    if crashes >= o.max_crashes {
                        break;
                    }
                }
            }
        }
    }
    let secs = started.elapsed().as_secs_f64().max(0.001);
    eprintln!(
        "fuzz[{}]: done. {execs} execs in {:.0} s ({:.0}/s), {} edges, corpus {}, {} distinct panics, {} bloat inputs",
        target.name,
        secs,
        execs as f64 / secs,
        virgin.edges,
        corpus.len(),
        crashes,
        bloat
    );
    let _ = fs::remove_file(&current_path);
    if crashes > 0 || bloat > 0 {
        3
    } else {
        0
    }
}

/// Runs `child` repeatedly: when it dies without a word (stack overflow, abort, the watchdog) the
/// input it was running is recovered from its current-input file.
fn supervise(o: &Options) -> i32 {
    let exe = std::env::current_exe().expect("current_exe");
    let started = Instant::now();
    let mut restarts = 0;
    let mut findings = 0;
    loop {
        let elapsed = started.elapsed().as_secs();
        if elapsed >= o.seconds {
            return if findings > 0 { 3 } else { 0 };
        }
        let mut cmd = Command::new(&exe);
        cmd.arg("child").arg(&o.target);
        cmd.args(["--corpus", &o.corpus.to_string_lossy(), "--artifacts", &o.artifacts.to_string_lossy()]);
        cmd.args(["--seconds", &(o.seconds - elapsed).to_string(), "--timeout", &o.timeout.to_string()]);
        cmd.args(["--seed", &(o.seed.wrapping_add(restarts)).to_string(), "--max-crashes", &o.max_crashes.to_string()]);
        if o.execs != u64::MAX {
            cmd.args(["--execs", &o.execs.to_string()]);
        }
        if let Some(m) = o.max_len {
            cmd.args(["--max-len", &m.to_string()]);
        }
        let mut child = cmd.spawn().expect("cannot start the fuzzing process");
        let pid = child.id();
        let status = child.wait().expect("wait");
        let current = o.artifacts.join(format!(".current-{pid}"));
        let reason = o.artifacts.join(format!(".reason-{pid}"));
        match status.code() {
            Some(0) => return if findings > 0 { 3 } else { 0 },
            Some(3) => {
                // the child saw panics and said so itself; it stops at max_crashes or the deadline
                findings += 1;
                if started.elapsed().as_secs() >= o.seconds {
                    return 3;
                }
                restarts += 1;
                if restarts > 5 {
                    return 3;
                }
            }
            Some(2) => return 2,
            _ => {
                // killed: recover the input
                let data = fs::read(&current).ok().and_then(|raw| {
                    let n = u32::from_le_bytes(raw.get(..4)?.try_into().ok()?) as usize;
                    raw.get(4..4 + n).map(|d| d.to_vec())
                });
                let why = fs::read_to_string(&reason).unwrap_or_else(|_| "crash: the process died (stack overflow or abort)".into());
                let prefix = if why.starts_with("timeout") {
                    "timeout"
                } else if why.starts_with("oom") {
                    "oom"
                } else {
                    "crash"
                };
                match data {
                    Some(d) => {
                        let p = save(&o.artifacts, prefix, &d);
                        eprintln!("fuzz[{}]: {} ({} bytes): {}\n  input saved as {}", o.target, why, d.len(), status, p.display());
                    }
                    None => eprintln!("fuzz[{}]: the process died ({status}) and no input could be recovered: {why}", o.target),
                }
                let _ = fs::remove_file(&current);
                let _ = fs::remove_file(&reason);
                findings += 1;
                restarts += 1;
                if findings >= o.max_crashes {
                    return 3;
                }
            }
        }
    }
}

fn replay(o: &Options) -> i32 {
    let target = find_target(&o.target);
    install_panic_hook();
    SINGLE_LIMIT.store(256 << 20, Ordering::Relaxed);
    LIVE_LIMIT.store(1 << 30, Ordering::Relaxed);
    spawn_watchdog(o.timeout, None);
    let mut runner = Runner::new(&target, None);
    let mut bad = 0;
    for f in &o.extra {
        let data = fs::read(f).unwrap_or_else(|e| usage(&format!("{f}: {e}")));
        match runner.exec(&data).0 {
            Outcome::Fine => println!("ok      {f}"),
            Outcome::Panic(n) => {
                bad += 1;
                println!("PANIC   {f}: {n}");
            }
        }
    }
    if bad > 0 {
        1
    } else {
        0
    }
}

fn merge(o: &Options) -> i32 {
    let target = find_target(&o.target);
    install_panic_hook();
    let into = o.extra.iter().find_map(|a| a.strip_prefix("--into=")).map(PathBuf::from).unwrap_or_else(|| usage("merge needs --into DIR"));
    let sources: Vec<&String> = o.extra.iter().filter(|a| !a.starts_with("--into=")).collect();
    let mut runner = Runner::new(&target, None);
    let mut virgin = Virgin::new();
    let mut all: Vec<Vec<u8>> = read_dir_files(&into);
    for s in sources {
        all.extend(read_dir_files(Path::new(s)));
    }
    let before = all.len();
    all.sort_by_key(|d| (d.len(), fnv(d)));
    all.dedup();
    let _ = fs::create_dir_all(&into);
    let mut kept = 0;
    for data in all {
        if let (Outcome::Fine, _) = runner.exec(&data) {
            if virgin.absorb(&runner.regions) {
                let path = into.join(format!("{:016x}", fnv(&data)));
                let _ = fs::write(path, &data);
                kept += 1;
            }
        }
    }
    // inputs already in `into` that no longer add anything are removed, so the directory stays minimal
    let keep: HashSet<String> = {
        let mut k = HashSet::new();
        let mut runner = Runner::new(&target, None);
        let mut virgin = Virgin::new();
        let mut files: Vec<_> = read_dir_files(&into);
        files.sort_by_key(|d| (d.len(), fnv(d)));
        for d in files {
            if let (Outcome::Fine, _) = runner.exec(&d) {
                if virgin.absorb(&runner.regions) {
                    k.insert(format!("{:016x}", fnv(&d)));
                }
            }
        }
        k
    };
    if let Ok(rd) = fs::read_dir(&into) {
        for e in rd.filter_map(|e| e.ok()) {
            if !keep.contains(&e.file_name().to_string_lossy().to_string()) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    eprintln!("fuzz[{}]: {} inputs read, {} kept ({} edges)", target.name, before, keep.len().max(kept.min(keep.len())), virgin.edges);
    0
}

fn check() -> i32 {
    let n = counter_total();
    let regions = REGIONS.lock().unwrap().len();
    println!("{n} coverage counters in {regions} region(s)");
    if n == 0 {
        println!("none: build with the RUSTFLAGS in run_all.sh");
        return 1;
    }
    // coverage must respond to input: a certificate that parses reaches code a one-byte input does not
    let target = find_target("certificate");
    let mut runner = Runner::new(&target, None);
    let mut virgin = Virgin::new();
    runner.exec(&[0x30]);
    virgin.absorb(&runner.regions);
    let junk_edges = virgin.edges;
    let seed = (target.seeds)().into_iter().next().expect("a certificate seed");
    runner.exec(&seed);
    let found = virgin.absorb(&runner.regions);
    println!("a one-byte input reaches {junk_edges} edges; a real certificate reaches {} ({})", virgin.edges, if found { "feedback works" } else { "NO feedback" });
    if found {
        0
    } else {
        1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { usage("no command") };
    let code = match cmd.as_str() {
        "list" => {
            for t in targets::all() {
                println!("{}", t.name);
            }
            0
        }
        "check" => check(),
        "seed" => {
            let (name, dir) = (args.get(1).cloned().unwrap_or_default(), args.get(2).cloned().unwrap_or_default());
            let t = find_target(&name);
            for s in (t.seeds)() {
                save(Path::new(&dir), "seed", &s);
            }
            0
        }
        "run" => supervise(&parse_options(&args[1..])),
        "child" => child(&parse_options(&args[1..])),
        "replay" => replay(&parse_options(&args[1..])),
        "merge" => merge(&parse_options(&args[1..])),
        _ => usage(&format!("unknown command {cmd:?}")),
    };
    let _ = std::io::stderr().flush();
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::add_region;

    #[test]
    fn the_same_range_reported_many_times_is_one_region() {
        let mut l = Vec::new();
        for _ in 0..26 {
            add_region(&mut l, 1000, 5000);
        }
        assert_eq!(l, vec![(1000, 4000)]);
    }

    #[test]
    fn overlapping_and_touching_ranges_merge_and_separate_ones_do_not() {
        let mut l = Vec::new();
        add_region(&mut l, 100, 200);
        add_region(&mut l, 300, 400);
        assert_eq!(l.len(), 2);
        add_region(&mut l, 150, 250); // overlaps the first
        assert_eq!(l.len(), 2);
        add_region(&mut l, 250, 300); // touches both, joining them
        assert_eq!(l, vec![(100, 300)]);
        add_region(&mut l, 120, 130); // inside
        assert_eq!(l, vec![(100, 300)]);
        add_region(&mut l, 1000, 1010);
        l.sort();
        assert_eq!(l, vec![(100, 300), (1000, 10)]);
    }
}
