//! This library as one of the judges of `tools/chain_judges.sh` (BACKLOG B-92, part 3): for each chain in a directory laid
//! out as `tests/data/real_chains` and `tests/data/chain_cases` are (`fixtures.tsv`, `chains/NAME.pem`, the anchors' files),
//! whether the library accepts it as a TLS server's chain for the case's host at the case's time, against a store that holds
//! that case's anchors and nothing else.
//!
//! ```text
//! cargo run --release --example chain_judge -- DIR
//! ```
//!
//! One line for each case: `NAME<TAB>ok`, or `NAME<TAB>no<TAB>why`.

use pratique::pem;
use pratique::x509::TrustStore;
use std::path::Path;

fn certs_in(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect())
}

/// The library's verdict on one case.
fn judge(dir: &Path, name: &str, host: &str, time: i64, anchor: &str) -> Result<(), String> {
    let chain = certs_in(&dir.join("chains").join(format!("{name}.pem")))?;
    if chain.is_empty() {
        return Err("the chain file holds no certificate".into());
    }
    let mut store = TrustStore::empty();
    if anchor != "-" {
        for der in certs_in(&dir.join(anchor))? {
            store.add_der(&der).map_err(|e| format!("the anchor does not parse: {e}"))?;
        }
    }
    store.verify_server_chain(&chain, host, time).map(|_| ()).map_err(|e| e.to_string())
}

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: chain_judge DIR   (a directory with fixtures.tsv, chains/ and the anchors' files)");
        std::process::exit(2);
    };
    let dir = Path::new(&dir);
    let text = std::fs::read_to_string(dir.join("fixtures.tsv")).unwrap_or_else(|e| {
        eprintln!("cannot read {}/fixtures.tsv: {e}", dir.display());
        std::process::exit(2);
    });
    for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 5 {
            eprintln!("fixtures.tsv: a line with fewer than 5 columns: {line}");
            std::process::exit(2);
        }
        let verdict = match c[2].parse::<i64>() {
            Ok(time) => judge(dir, c[0], c[1], time, c[4]),
            Err(_) => Err(format!("bad time {}", c[2])),
        };
        match verdict {
            Ok(()) => println!("{}\tok", c[0]),
            Err(why) => println!("{}\tno\t{}", c[0], why.replace(['\t', '\n'], " ")),
        }
    }
}
