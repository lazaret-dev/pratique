//! Looks a module version up in the Go checksum database and checks what comes back the way the
//! `go` command does (signed tree head, record hash, every tile authenticated), then prints the
//! verified `go.sum` lines.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --example sumdb -- [--base URL] [--state FILE] [--cacert FILE] [--key VKEY] MODULE VERSION
//! cargo run --release --example sumdb -- golang.org/x/mod v0.17.0
//! ```
//!
//! `--state FILE` keeps the latest tree head between runs (the file is read first and rewritten
//! after a successful check), so a database that later shows a history inconsistent with the head
//! saved earlier is caught as a fork. `--base` and `--key` point it at another server (the tests
//! use a local plain-http copy of a captured response).

use std::error::Error;

use pratique::sumdb::{self, Check};
use pratique::tlog::{Tile, TileSet};
use pratique::tls::ClientConfig;
use pratique::Client;

fn usage() -> ! {
    eprintln!("usage: sumdb [--base URL] [--state FILE] [--cacert FILE] [--key VKEY] MODULE VERSION");
    std::process::exit(2);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut base = "https://sum.golang.org".to_string();
    let (mut state, mut cacert, mut key) = (None::<String>, None::<String>, None::<String>);
    let mut names = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--base" => base = args.next().unwrap_or_else(|| usage()),
            "--state" => state = args.next(),
            "--cacert" => cacert = args.next(),
            "--key" => key = args.next(),
            "-h" | "--help" => usage(),
            _ => names.push(a),
        }
    }
    let [module, version] = names.as_slice() else { usage() };
    let base = base.trim_end_matches('/');

    let trust = match &cacert {
        Some(path) => pratique::sys::trust_store_from_pem_file(path)?,
        None => pratique::sys::system_trust_store()?,
    };
    // what the database says is signed and every tile is authenticated, so even a plain-http mirror is safe to ask
    let client = Client::with_tls_config(ClientConfig::new(trust)).proxy_from_env().allow_insecure_http(base.starts_with("http://"));
    // Ok(None): the server answered, but not with the file (a partial tile that is gone is a 404)
    let get = |path: &str| -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let r = client.get(&format!("{base}/{path}"))?;
        Ok(if r.status == 200 { Some(r.body) } else { None })
    };

    let verifier = match &key {
        Some(k) => pratique::note::Verifier::from_key(k)?,
        None => sumdb::verifier(),
    };
    let mut check = Check::new(verifier);
    if let Some(path) = &state {
        if let Ok(saved) = std::fs::read(path) {
            check.add_head(&saved)?;
            eprintln!("starting from the tree head saved in {path}");
        }
    }

    let path = sumdb::lookup_path(module, version)?;
    let response = get(&path)?.ok_or_else(|| format!("{base}/{path}: not found (is it a module version the database knows?)"))?;
    check.add_lookup(module, version, &response)?;

    // the tiles the check needs; a partial tile that is gone is served as the full tile
    let mut tiles = TileSet::new();
    let needed = check.tiles_needed()?;
    for tile in &needed {
        let (tile, data): (Tile, Vec<u8>) = match get(&tile.path())? {
            Some(d) if d.len() as u64 == tile.data_len() => (*tile, d),
            _ => (tile.full(), get(&tile.full().path())?.ok_or_else(|| format!("tile {} is not available", tile.path()))?),
        };
        tiles.insert(tile, data)?;
    }
    eprintln!("fetched {} tiles", needed.len());

    let outcome = check.finish(&tiles)?;
    for line in &outcome.records[0].lines {
        println!("{line}");
    }
    eprintln!("record {} verified against tree of {} records", outcome.records[0].id, outcome.latest.size);
    if let Some(path) = &state {
        std::fs::write(path, &outcome.latest_note)?;
    }
    Ok(())
}
