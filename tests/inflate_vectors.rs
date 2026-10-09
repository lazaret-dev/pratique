//! Replays tests/data/inflate_vectors.txt against `pratique::inflate`: streams made by zlib, gzip(1), zlib-flate, Go's
//! `compress/*` and by hand, which must come out as the data they were made from however the input and the output are cut up,
//! and damaged copies of some of them, for which this decoder must say what Python's zlib says (and never accept what zlib
//! refuses).
//!
//! The file is made by `tools/gen_inflate_vectors.py` (see there for the format of the lines). Go's readers judged the damaged
//! copies too. They agree with zlib on every one but the gzip headers that set a reserved flag bit, which Go ignores and zlib
//! (and RFC 1952) refuse; this decoder refuses them, and the test says so below.

use pratique::crypto::sha2::{Hash, Sha256};
use pratique::inflate::{decode_all, Error, Format, Inflater, Limits, Status};

const VECTORS: &str = include_str!("data/inflate_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    let s = if s == "-" { "" } else { s };
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn format_of(name: &str) -> Format {
    match name {
        "deflate" => Format::Deflate,
        "zlib" => Format::Zlib,
        "gzip" => Format::Gzip,
        other => panic!("format {other}"),
    }
}

/// What a reference decoder made of a stream: nothing, or the length and SHA-256 of the output.
type Verdict = Option<(usize, String)>;

fn verdict(text: &str) -> Verdict {
    if text == "err" {
        return None;
    }
    let mut p = text.strip_prefix("ok:").expect("ok: or err").splitn(2, ':');
    Some((p.next().unwrap().parse().unwrap(), p.next().unwrap().to_string()))
}

fn ours(r: &Result<Vec<u8>, Error>) -> Verdict {
    r.as_ref().ok().map(|out| (out.len(), hex(&Sha256::digest(out))))
}

/// Decompresses `data` the way a caller with small buffers would: the input in pieces of `inp` bytes, the output in a slice of
/// `out` bytes, and the same answer as `decode_all` is expected whatever the sizes.
fn run(format: Format, data: &[u8], inp: usize, out: usize, limits: Limits) -> Result<Vec<u8>, Error> {
    let mut inf = Inflater::new(format, limits);
    let mut result = Vec::new();
    let mut buf = vec![0u8; out];
    let mut pos: usize = 0;
    loop {
        let end = pos.saturating_add(inp).min(data.len());
        let p = inf.inflate(&data[pos..end], &mut buf)?;
        pos += p.consumed;
        result.extend_from_slice(&buf[..p.produced]);
        match p.status {
            Status::Done => {
                return if pos == data.len() && inf.take_unused().is_empty() { Ok(result) } else { Err(Error::Corrupt("data follows the end of the compressed stream")) };
            }
            Status::NeedOutput => {}
            Status::NeedInput => {
                if pos == data.len() {
                    inf.finish()?;
                    return Ok(result);
                }
            }
        }
    }
}

/// Applies a list of edits (`x:OFFSET:HEXBYTE` xor, `d:OFFSET:LENGTH` delete, `i:OFFSET:HEX` insert, `t:LENGTH:` cut,
/// `a:HEX:` append).
fn apply(base: &[u8], edits: &str) -> Vec<u8> {
    let mut b = base.to_vec();
    for e in edits.split(',') {
        let mut p = e.splitn(3, ':');
        let (kind, a, arg) = (p.next().unwrap(), p.next().unwrap(), p.next().unwrap());
        match kind {
            "x" => b[a.parse::<usize>().unwrap()] ^= unhex(arg)[0],
            "d" => {
                let off = a.parse::<usize>().unwrap();
                b.drain(off..off + arg.parse::<usize>().unwrap());
            }
            "i" => {
                let tail = b.split_off(a.parse().unwrap());
                b.extend(unhex(arg));
                b.extend(tail);
            }
            "t" => b.truncate(a.parse().unwrap()),
            "a" => b.extend(unhex(a)),
            _ => panic!("edit {e}"),
        }
    }
    b
}

#[test]
fn streams_made_by_other_programs_decompress_to_what_they_were_made_from() {
    let mut count = 0;
    let mut by_maker = std::collections::BTreeMap::<String, u32>::new();
    for line in VECTORS.lines().filter(|l| l.starts_with("ok ")) {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, format, len, sha) = (f[1], format_of(f[2]), f[3].parse::<usize>().unwrap(), f[4]);
        let stream = unhex(f[5]);
        let big = len > 100_000;
        // whole, a byte at a time, and odd sizes of both; a tiny output slice only where the output is short
        let mut cuts = vec![(usize::MAX, 65536), (1, 65536), (7, 3), (3, 4096), (usize::MAX, 1 << 20)];
        if !big {
            cuts.extend([(509, 1), (1, 1)]);
        }
        for (inp, out) in cuts {
            let r = run(format, &stream, inp, out, Limits::unlimited());
            let got = r.unwrap_or_else(|e| panic!("{name}: input in {inp}s, output in {out}s: {e}"));
            assert_eq!(got.len(), len, "{name}: length (input in {inp}s, output in {out}s)");
            assert_eq!(hex(&Sha256::digest(&got)), sha, "{name}: content (input in {inp}s, output in {out}s)");
        }
        // the limit on the output: exactly enough passes, one byte less is refused
        assert_eq!(decode_all(format, &stream, Limits::new(len as u64)).map(|o| o.len()), Ok(len), "{name}: limit equal to the size");
        if len > 0 {
            assert!(
                matches!(decode_all(format, &stream, Limits::new(len as u64 - 1)), Err(Error::OutputLimit { .. })),
                "{name}: limit one byte short"
            );
        }
        // the lenient format takes what the strict one takes, and a single gzip member is a member
        if f[2] == "zlib" {
            assert_eq!(decode_all(Format::ZlibOrDeflate, &stream, Limits::unlimited()).map(|o| o.len()), Ok(len), "{name}: zlib or deflate");
        }
        if f[2] == "gzip" && !name.contains("members") {
            assert_eq!(decode_all(Format::GzipMember, &stream, Limits::unlimited()).map(|o| o.len()), Ok(len), "{name}: one gzip member");
        }
        count += 1;
        *by_maker.entry(name.split('.').next().unwrap().to_string()).or_default() += 1;
    }
    println!("{count} valid streams: {by_maker:?}");
    assert!(count >= 200, "the vector file is cut short: {count} valid streams");
    for maker in ["py", "go", "gzipcli", "zlibflate", "hand"] {
        assert!(by_maker.contains_key(maker), "no streams from {maker}");
    }
}

#[test]
fn damaged_streams_get_the_verdict_of_zlib() {
    let mut bases = std::collections::HashMap::new();
    for line in VECTORS.lines().filter(|l| l.starts_with("base ")) {
        let f: Vec<&str> = line.split(' ').collect();
        bases.insert(f[1], (f[2], unhex(f[3])));
    }
    let (mut count, mut accepted, mut go_only) = (0, 0, 0);
    for line in VECTORS.lines().filter(|l| l.starts_with("mut ")) {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, edits) = (f[1], f[2]);
        let (zlib, go) = (verdict(f[3]), verdict(f[4]));
        let (fmt, base) = &bases[name];
        let format = format_of(fmt);
        let copy = apply(base, edits);
        let what = format!("{name} with {edits}");

        let whole = decode_all(format, &copy, Limits::unlimited());
        // the same answer, the same error, however the input and the output are cut
        for (inp, out) in [(1, 1), (1, 4096), (5, 3), (usize::MAX, 7)] {
            assert_eq!(run(format, &copy, inp, out, Limits::unlimited()), whole, "{what}: input in {inp}s, output in {out}s");
        }
        // what zlib accepts is accepted and gives the same bytes, and what zlib refuses is refused
        assert_eq!(ours(&whole), zlib, "{what}: zlib says {zlib:?}, this decoder {:?}", whole.as_ref().map(|o| o.len()));
        // Go refuses what zlib refuses, bar the reserved flag bits of a gzip header, and gives the same bytes when it accepts
        if go.is_some() && zlib.is_none() {
            assert_eq!(*fmt, "gzip", "{what}: Go accepts what zlib refuses");
            assert!(copy[3] & 0xe0 != 0, "{what}: Go accepts what zlib refuses, and no reserved flag is set");
            go_only += 1;
        }
        if zlib.is_some() {
            assert_eq!(go, zlib, "{what}: Go and zlib disagree on the bytes");
            accepted += 1;
        }
        count += 1;
    }
    println!("{count} damaged copies, {accepted} still valid, {go_only} that only Go accepts");
    assert!(count >= 900, "the vector file is cut short: {count} damaged copies");
    assert!(accepted >= 100 && count - accepted >= 600, "the mix of verdicts changed: {accepted} accepted of {count}");
    assert!(go_only >= 1);
}
