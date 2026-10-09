//! What `examples/bench.rs` and `examples/bench_net.rs` share: where the figures go, and how a time is taken.

use std::io::Write;
use std::time::Instant;

/// Where the figures go: the screen, and a TSV file if one was asked for.
pub struct Report {
    tsv: Option<std::fs::File>,
    label: String,
    date: String,
}

impl Report {
    pub fn from_args() -> Report {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let option = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
        let tsv = option("--tsv").map(|p| std::fs::OpenOptions::new().create(true).append(true).open(&p).unwrap_or_else(|e| panic!("cannot open {p}: {e}")));
        let label = option("--label").unwrap_or_else(|| "this machine".into());
        // (the other options are the example's own)
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        Report { tsv, label, date: date_of(secs) }
    }

    /// One figure: `name` (a stable name: the TSV and the comparison go by it), its value and unit.
    pub fn row(&mut self, name: &str, value: f64, unit: &str) {
        let shown = if value >= 100.0 { format!("{value:9.1}") } else if value >= 1.0 { format!("{value:9.2}") } else { format!("{value:9.4}") };
        println!("{name:<58} {shown} {unit}");
        if let Some(f) = &mut self.tsv {
            writeln!(f, "{}\t{}\t{name}\t{value}\t{unit}", self.label, self.date).expect("write the TSV");
        }
    }
}

/// The UTC date of a Unix time, as YYYY-MM-DD.
fn date_of(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // (the civil-from-days algorithm of Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The best time per call of `op`, in seconds: calls in batches of about 50 ms, the best batch of five after one that
/// warms up.
#[allow(dead_code)] // (`bench_net` times things its own way)
pub fn best_secs(mut op: impl FnMut()) -> f64 {
    let mut n = 1usize;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            op();
        }
        if t.elapsed().as_secs_f64() > 0.05 {
            break;
        }
        n *= 2;
    }
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..n {
            op();
        }
        best = best.min(t.elapsed().as_secs_f64() / n as f64);
    }
    best
}

/// Whether the command line has `flag`.
#[allow(dead_code)] // (not every example has flags of its own)
pub fn has_flag(flag: &str) -> bool {
    std::env::args().skip(1).any(|a| a == flag)
}
