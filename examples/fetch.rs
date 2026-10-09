//! A tiny curl-like tool built on pratique.
//!
//! Usage: cargo run --release --example fetch -- [-i] [-I] [--http2] [--http3 | --alt-svc] [--stream] [--warm URL --idle-ms N] [--parallel N] [--repeat N] [--max-bytes N] [--cacert FILE] [--no-proxy] URL
//!
//! `--http3` tries QUIC first and goes over TCP if that does not work (as curl's does); `--alt-svc` goes over TCP first and over QUIC for
//! an origin that has said, in an `Alt-Svc` field, that it offers it (with `--repeat 2` the second request shows it). `-i` shows the protocol.

use std::io::Write;
use pratique::tls::ClientConfig;
use pratique::Client;

/// The CPU time this process has used (user + system, all threads), in seconds, read from `/proc/self/stat`; 0 where there is none.
fn cpu_time() -> f64 {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else { return 0.0 };
    // the fields after the command name (which is in parentheses and may hold spaces): utime and stime are the 12th and 13th after it
    let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else { return 0.0 };
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (ticks(11) + ticks(12)) / 100.0
}

/// For `FETCH_TIMES`: what each thread of this process has used so far, as "name user+system" in seconds.
fn thread_times() -> String {
    let mut out = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/task") {
        for e in dir.flatten() {
            let stat = std::fs::read_to_string(e.path().join("stat")).unwrap_or_default();
            let Some((head, rest)) = stat.rsplit_once(')') else { continue };
            let name = head.split_once('(').map_or("?", |(_, n)| n);
            let f: Vec<&str> = rest.split_whitespace().collect();
            let t = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0) / 100.0;
            out.push(format!("{name} {:.2}+{:.2}", t(11), t(12)));
        }
    }
    out.join(", ")
}

fn main() {
    let mut url = None;
    let mut include_headers = false;
    let mut head_only = false;
    let mut cacert: Option<String> = None;
    let mut use_proxy = true;
    let mut http2 = false;
    // 0: TCP only; 1: QUIC where an origin has said (in Alt-Svc) that it speaks it; 2: QUIC first, TCP if that does not work
    let mut http3 = 0u8;
    let mut stream = false;
    let mut parallel = 0usize;
    let mut repeat = 0usize;
    let mut max_bytes: Option<u64> = None;
    let mut warm: Option<String> = None;
    let mut idle_ms = 0u64;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-i" => include_headers = true,
            "-I" => {
                head_only = true;
                include_headers = true;
            }
            "--cacert" => cacert = args.next(),
            "--no-proxy" => use_proxy = false,
            "--http2" => http2 = true,
            "--alt-svc" => http3 = 1,
            "--http3" => http3 = 2,
            "--stream" => stream = true,
            "--warm" => warm = args.next(),
            "--idle-ms" => idle_ms = args.next().and_then(|n| n.parse().ok()).unwrap_or(0),
            "--max-bytes" => max_bytes = args.next().and_then(|n| n.parse().ok()),
            "--repeat" => repeat = args.next().and_then(|n| n.parse().ok()).unwrap_or(100),
            "--parallel" => parallel = args.next().and_then(|n| n.parse().ok()).unwrap_or(4),
            "-h" | "--help" => {
                eprintln!("usage: fetch [-i] [-I] [--http2] [--http3 | --alt-svc] [--stream] [--warm URL --idle-ms N] [--parallel N] [--repeat N] [--max-bytes N] [--cacert FILE] [--no-proxy] URL");
                return;
            }
            _ => url = Some(a),
        }
    }
    let Some(url) = url else {
        eprintln!("usage: fetch [-i] [-I] [--http2] [--http3 | --alt-svc] [--stream] [--warm URL --idle-ms N] [--parallel N] [--repeat N] [--max-bytes N] [--cacert FILE] [--no-proxy] URL");
        std::process::exit(2);
    };

    let result = (|| -> pratique::error::Result<pratique::Response> {
        let trust = match &cacert {
            Some(path) => pratique::sys::trust_store_from_pem_file(path)?,
            None => pratique::sys::system_trust_store()?,
        };
        let mut client = Client::with_tls_config(ClientConfig::new(trust)).http2(http2).http3(http3 > 0).http3_eager(http3 == 2);
        if use_proxy {
            client = client.proxy_from_env();
        }
        if let Some(n) = max_bytes {
            client = client.max_body_bytes(n);
        }
        if repeat > 0 {
            // the same request N times in a row (with --parallel P: P threads each making N / P), to time many small requests
            let threads = parallel.max(1);
            let per = repeat.div_ceil(threads);
            let started = std::time::Instant::now();
            let cpu_before = cpu_time();
            let mut results: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..threads)
                    .map(|_| {
                        scope.spawn(|| {
                            let mut last = None;
                            for _ in 0..per {
                                last = Some(client.get(&url));
                                if matches!(last, Some(Err(_))) {
                                    break;
                                }
                            }
                            last.unwrap()
                        })
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let wall = started.elapsed();
            eprintln!(
                "{} requests ({} threads): wall {:.3} s, cpu {:.3} s, {:.0} us per request",
                per * threads,
                threads,
                wall.as_secs_f64(),
                cpu_time() - cpu_before,
                wall.as_secs_f64() * 1e6 / (per * threads) as f64
            );
            return results.pop().unwrap();
        }
        if parallel > 0 {
            // the same request N times at once, to see whether they share a connection (HTTP/2) and how long it takes
            let started = std::time::Instant::now();
            let cpu_before = cpu_time();
            let mut results: Vec<_> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..parallel).map(|_| scope.spawn(|| client.get(&url))).collect();
                handles.into_iter().map(|h| h.join().unwrap()).collect()
            });
            let ok = results.iter().filter(|r| r.is_ok()).count();
            let first = results.iter().find_map(|r| r.as_ref().ok());
            eprintln!(
                "{parallel} requests at once: {ok} answered in {:?} (cpu {:.3} s); {}; first answer {} bytes",
                started.elapsed(),
                cpu_time() - cpu_before,
                first.map_or("no answer".to_string(), |r| format!("{} {}", r.version, r.status)),
                first.map_or(0, |r| r.body.len())
            );
            return match results.iter().position(|r| r.is_ok()) {
                Some(i) => results.swap_remove(i),
                None => results.pop().unwrap_or_else(|| Err(pratique::error::Error::Http("no request was made".into()))),
            };
        }
        if stream {
            // the body is read in pieces of 64 KiB and thrown away (the way a download to a file reads it), to time that path;
            // after a request to --warm (to have a connection) and a pause of --idle-ms (a connection that was left alone)
            if let Some(w) = &warm {
                client.get(w)?;
                std::thread::sleep(std::time::Duration::from_millis(idle_ms));
            }
            let started = std::time::Instant::now();
            let cpu_before = cpu_time();
            let mut s = client.get_stream(&url)?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                match std::io::Read::read(&mut s, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(e) => return Err(e.into()),
                }
            }
            eprintln!("streamed {total} bytes: wall {:.3} s, cpu {:.3} s  [{}]", started.elapsed().as_secs_f64(), cpu_time() - cpu_before, thread_times());
            std::process::exit(0);
        }
        let started = std::time::Instant::now();
        let cpu_before = cpu_time();
        let r = if head_only { client.head(&url) } else { client.get(&url) };
        if std::env::var_os("FETCH_TIMES").is_some() {
            eprintln!("wall {:.3} s, cpu {:.3} s  [{}]", started.elapsed().as_secs_f64(), cpu_time() - cpu_before, thread_times());
        }
        r
    })();

    match result {
        Ok(resp) => {
            let mut out = std::io::stdout().lock();
            if include_headers {
                let _ = writeln!(out, "{} {} {}", resp.version, resp.status, resp.reason);
                for (n, v) in &resp.headers {
                    let _ = writeln!(out, "{}: {}", n, v);
                }
                let _ = writeln!(out);
            }
            let _ = out.write_all(&resp.body);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}
