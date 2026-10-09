//! Refreshes Sigstore's trust through its TUF repository (BACKLOG B-82): rotates the TUF root from the one built into the
//! crate (or a newer one kept from before), checks the timestamp, snapshot, targets and the `registry.npmjs.org`
//! delegation, fetches `trusted_root.json` and npm's keys, and reads both. Prints what it verified.
//!
//! ```text
//! cargo run --release --example tuf_refresh -- [--repo URL] [--state DIR] [--save DIR] [--cacert FILE] [--now UNIX]
//! ```
//!
//! `--state DIR` keeps the newest TUF root, the timestamp and the snapshot between runs (read first, written after a
//! successful refresh), so the next run starts from them and a repository that goes back to older metadata is caught.
//! `--save DIR` writes every file the repository served, as served (under `metadata/` and `targets/`), with the time and
//! the root the run started from (`now`, `bootstrap.json`): the capture that `tests/tuf_sigstore.rs` replays offline.

use std::cell::RefCell;
use std::error::Error;
use std::path::{Path, PathBuf};

use pratique::tls::ClientConfig;
use pratique::trust_root::{KeyRing, TrustedRoot};
use pratique::tuf::{self, Fetched, Local, Request, Updater};
use pratique::Client;

fn usage() -> ! {
    eprintln!("usage: tuf_refresh [--repo URL] [--state DIR] [--save DIR] [--cacert FILE] [--now UNIX]");
    std::process::exit(2);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn read(dir: &Option<PathBuf>, name: &str) -> Option<Vec<u8>> {
    dir.as_ref().and_then(|d| std::fs::read(d.join(name)).ok())
}

fn when(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let (z, s) = (days + 719_468, t.rem_euclid(86_400));
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s % 3600 / 60, s % 60)
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut repo = tuf::SIGSTORE_REPOSITORY.to_string();
    let (mut state, mut save, mut cacert, mut now) = (None::<PathBuf>, None::<PathBuf>, None::<String>, None::<i64>);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--repo" => repo = args.next().unwrap_or_else(|| usage()),
            "--state" => state = Some(args.next().unwrap_or_else(|| usage()).into()),
            "--save" => save = Some(args.next().unwrap_or_else(|| usage()).into()),
            "--cacert" => cacert = args.next(),
            "--now" => now = Some(args.next().and_then(|s| s.parse().ok()).unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }
    let repo = repo.trim_end_matches('/').to_string();
    let now = now.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after 1970").as_secs() as i64);
    let trust = match &cacert {
        Some(path) => pratique::sys::trust_store_from_pem_file(path)?,
        None => pratique::sys::system_trust_store()?,
    };
    // what TUF verifies is signed, so a plain-http mirror is as good (only its availability is trusted)
    let client = Client::with_tls_config(ClientConfig::new(trust)).proxy_from_env().allow_insecure_http(repo.starts_with("http://"));

    let bootstrap = read(&state, "root.json").unwrap_or_else(|| tuf::SIGSTORE_ROOT.to_vec());
    let (kept_timestamp, kept_snapshot) = (read(&state, "timestamp.json"), read(&state, "snapshot.json"));
    let served: RefCell<Vec<(String, Vec<u8>)>> = RefCell::new(Vec::new());
    let get = |dir: &'static str, r: &Request| -> Result<Fetched, String> {
        let url = format!("{repo}/{}{}", if dir == "targets" { "targets/" } else { "" }, r.path);
        let resp = client.request("GET", &url).max_body_bytes(r.max_length + 1).send().map_err(|e| e.to_string())?;
        println!("  GET {url}: {} ({} bytes)", resp.status, resp.body.len());
        match resp.status {
            200 => {
                served.borrow_mut().push((format!("{dir}/{}", r.path), resp.body.clone()));
                Ok(Fetched::Data(resp.body))
            }
            403 | 404 => Ok(Fetched::NotFound),
            s => Err(format!("HTTP {s}")),
        }
    };

    let mut u = Updater::new(&bootstrap, now)?;
    let start = u.root().common.version;
    println!("TUF repository {repo}, at {} ({now}), starting from root version {start}", when(now));
    let local = Local { timestamp: kept_timestamp.as_deref(), snapshot: kept_snapshot.as_deref() };
    let result = (|| -> Result<(Vec<u8>, Vec<u8>), tuf::Error> {
        tuf::refresh(&mut u, local, &mut |r| get("metadata", r))?;
        let (_, trusted_root) = tuf::fetch_target(&mut u, tuf::SIGSTORE_TRUSTED_ROOT_TARGET, &mut |r| get("metadata", r), &mut |r| get("targets", r))?;
        let (_, npm_keys) = tuf::fetch_target(&mut u, tuf::NPM_KEYS_TARGET, &mut |r| get("metadata", r), &mut |r| get("targets", r))?;
        Ok((trusted_root, npm_keys))
    })();
    // the capture is written whatever the outcome: a refusal is worth looking at too
    if let Some(dir) = &save {
        save_capture(dir, now, &bootstrap, &served.borrow())?;
        println!("saved {} files to {}", served.borrow().len(), dir.display());
    }
    let (trusted_root, npm_keys) = result?;

    let root = u.root();
    println!("root: version {} (rotated {} times), expires {}, {} root keys with a threshold of {}", root.common.version, root.common.version - start, when(root.common.expires), root.roles[0].keyids.len(), root.roles[0].threshold);
    let (t, _) = u.timestamp().expect("refreshed");
    println!("timestamp: version {}, expires {}", t.common.version, when(t.common.expires));
    let (s, _) = u.snapshot().expect("refreshed");
    println!("snapshot: version {}, expires {}, lists {}", s.common.version, when(s.common.expires), s.meta.keys().cloned().collect::<Vec<_>>().join(", "));
    let targets = u.targets("targets").expect("refreshed");
    println!("targets: version {}, expires {}, {} files", targets.common.version, when(targets.common.expires), targets.targets.len());
    let tr = TrustedRoot::parse(&trusted_root)?;
    println!("{}: {} bytes; {} transparency logs, {} CT logs, {} Fulcio CAs, {} time-stamp authorities", tuf::SIGSTORE_TRUSTED_ROOT_TARGET, trusted_root.len(), tr.tlogs.len(), tr.ctlogs.len(), tr.certificate_authorities.len(), tr.timestamp_authorities.len());
    let ring = KeyRing::from_tuf_npm_keys(&npm_keys, "npm:attestations")?;
    println!("{}: {} bytes; keys for npm attestations: {}", tuf::NPM_KEYS_TARGET, npm_keys.len(), ring.keys().iter().map(|k| k.id.as_str()).collect::<Vec<_>>().join(", "));

    if let Some(dir) = &state {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("root.json"), u.root_bytes())?;
        std::fs::write(dir.join("timestamp.json"), u.timestamp().expect("refreshed").1)?;
        std::fs::write(dir.join("snapshot.json"), u.snapshot().expect("refreshed").1)?;
        println!("kept the root, timestamp and snapshot in {}", dir.display());
    }
    Ok(())
}

fn save_capture(dir: &Path, now: i64, bootstrap: &[u8], served: &[(String, Vec<u8>)]) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("now"), format!("{now}\n"))?;
    std::fs::write(dir.join("bootstrap.json"), bootstrap)?;
    for (path, data) in served {
        // the paths are the repository's names (a version, a role name that is percent-encoded, a hash and a file name);
        // nothing here climbs out of the directory
        if path.split('/').any(|p| p == ".." || p.is_empty()) {
            return Err(format!("refusing to save {path:?}").into());
        }
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().expect("has a parent"))?;
        std::fs::write(file, data)?;
    }
    Ok(())
}
