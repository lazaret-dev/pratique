//! TUF repositories made with python-tuf (tests/data/tuf/synthetic.json, from tools/gen_tuf_fixtures.py; BACKLOG B-82),
//! each judged by pratique's client as the case expects, and as python-tuf's own client judged the same bytes at the same
//! time (except where a case says why pratique differs on purpose). Then every byte of the files a good case fetches is
//! damaged in turn, and none of the damaged repositories may give a target that is not the case's.

use std::collections::BTreeMap;

use pratique::json::{self, Value};
use pratique::pem::base64_decode_strict;
use pratique::tuf::{self, Error, Fetched, Local, Request, Updater};

const DATA: &[u8] = include_bytes!("data/tuf/synthetic.json");

struct Case {
    name: String,
    bootstrap: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
    local: BTreeMap<String, Vec<u8>>,
    target: String,
    content: Vec<u8>,
    expect: String,
    reason: Option<String>,
    python: String,
    differs: Option<String>,
}

fn cases() -> (i64, Vec<Case>) {
    let doc = json::parse(DATA).unwrap();
    let blobs = doc.get("blobs").and_then(Value::as_object).unwrap();
    let blob = |h: &Value| base64_decode_strict(blobs.get(h.as_str().unwrap()).and_then(Value::as_str).unwrap()).unwrap();
    let map = |v: &Value| -> BTreeMap<String, Vec<u8>> { v.as_object().unwrap().iter().map(|(k, h)| (k.to_string(), blob(h))).collect() };
    let s = |c: &Value, n: &str| c.get(n).and_then(Value::as_str).map(str::to_string);
    let list = doc.get("cases").and_then(Value::as_array).unwrap();
    let out = list
        .iter()
        .map(|c| Case {
            name: s(c, "name").unwrap(),
            bootstrap: blob(c.get("bootstrap").unwrap()),
            files: map(c.get("files").unwrap()),
            local: map(c.get("local").unwrap()),
            target: s(c, "target").unwrap(),
            content: blob(c.get("content").unwrap()),
            expect: s(c, "expect").unwrap(),
            reason: s(c, "reason"),
            python: s(c, "python").unwrap(),
            differs: s(c, "differs"),
        })
        .collect();
    (doc.get("now").and_then(Value::as_int64).unwrap(), out)
}

/// What the client makes of a repository: the target's bytes, "not found", or the error.
fn run(now: i64, bootstrap: &[u8], files: &BTreeMap<String, Vec<u8>>, local: &BTreeMap<String, Vec<u8>>, target: &str) -> Result<Vec<u8>, Error> {
    run_recording(now, bootstrap, files, local, target, &std::cell::RefCell::new(Vec::new()))
}

/// The same, noting the path of every file asked for.
fn run_recording(
    now: i64,
    bootstrap: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    local: &BTreeMap<String, Vec<u8>>,
    target: &str,
    asked: &std::cell::RefCell<Vec<String>>,
) -> Result<Vec<u8>, Error> {
    let serve = |prefix: &'static str| {
        move |r: &Request| -> Result<Fetched, String> {
            asked.borrow_mut().push(format!("{prefix}/{}", r.path));
            Ok(match files.get(&format!("{prefix}/{}", r.path)) {
                // a server gives no more than was asked for (the client then sees the excess, if any, as a mismatch)
                Some(d) => Fetched::Data(d[..d.len().min(r.max_length as usize + 1)].to_vec()),
                None => Fetched::NotFound,
            })
        }
    };
    let mut u = Updater::new(bootstrap, now)?;
    let local = Local { timestamp: local.get("timestamp").map(Vec::as_slice), snapshot: local.get("snapshot").map(Vec::as_slice) };
    tuf::refresh(&mut u, local, &mut serve("metadata"))?;
    let (info, data) = tuf::fetch_target(&mut u, target, &mut serve("metadata"), &mut serve("targets"))?;
    assert_eq!(info.path, target);
    Ok(data)
}

fn kind(e: &Error) -> String {
    format!("{e:?}").chars().take_while(|c| c.is_ascii_alphanumeric()).collect()
}

#[test]
fn every_case_is_judged_as_expected_and_as_python_tuf_judged_it() {
    let (now, cases) = cases();
    assert!(cases.len() >= 50, "{}", cases.len());
    let mut wrong = Vec::new();
    let (mut ok, mut refused, mut not_found, mut differ) = (0, 0, 0, 0);
    for c in &cases {
        let got = run(now, &c.bootstrap, &c.files, &c.local, &c.target);
        let verdict = match &got {
            Ok(data) if *data == c.content => "ok".to_string(),
            Ok(_) => "ok with other bytes".to_string(),
            Err(Error::NotFound(_)) => "notfound".to_string(),
            Err(e) => kind(e),
        };
        if verdict != c.expect {
            wrong.push(format!("{}: {verdict} ({:?}), expected {}", c.name, got.as_ref().err().map(|e| e.to_string()), c.expect));
            continue;
        }
        if let (Some(reason), Err(e)) = (&c.reason, &got) {
            if !e.to_string().contains(reason.as_str()) {
                wrong.push(format!("{}: refused, but not for {reason:?}: {e}", c.name));
            }
        }
        // python-tuf's verdict on the same bytes: the same unless the case says why not
        let python = if c.python == "ok" || c.python == "notfound" { c.python.as_str() } else { "error" };
        let ours = if verdict == "ok" || verdict == "notfound" { verdict.as_str() } else { "error" };
        match (&c.differs, python == ours) {
            (None, false) => wrong.push(format!("{}: {ours}, python-tuf: {}", c.name, c.python)),
            (Some(why), true) => wrong.push(format!("{}: said to differ from python-tuf ({why}), but it does not", c.name)),
            (Some(_), false) => differ += 1,
            (None, true) => {}
        }
        match verdict.as_str() {
            "ok" => ok += 1,
            "notfound" => not_found += 1,
            _ => refused += 1,
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
    assert!(ok >= 20 && refused >= 25 && not_found >= 3 && differ >= 1, "{ok} {refused} {not_found} {differ}");
    eprintln!("{} cases: {ok} give the target, {not_found} not found, {refused} refused; {differ} differ from python-tuf on purpose", cases.len());
}

/// Every byte of every file a good case's client fetches, changed in turn (one bit of it), and every such file removed:
/// the client never gives other bytes than the case's target, and refuses every one of them but the removal of a root
/// in the middle of a rotation that changed no key. (A changed bit of JSON white space is no longer white space, every
/// signature these files carry is needed, and everything else is signed or is the target itself.)
#[test]
fn no_damaged_repository_gives_another_target() {
    let (now, cases) = cases();
    let (mut changed, mut still_ok) = (0, 0);
    let mut survivors: BTreeMap<String, usize> = BTreeMap::new();
    for c in cases.iter().filter(|c| c.expect == "ok" && c.local.is_empty()).take(5) {
        let asked = std::cell::RefCell::new(Vec::new());
        run_recording(now, &c.bootstrap, &c.files, &c.local, &c.target, &asked).unwrap();
        let fetched: Vec<String> = asked.into_inner().into_iter().filter(|p| c.files.contains_key(p)).collect();
        assert!(fetched.len() >= 4, "{}: {fetched:?}", c.name);
        for path in &fetched {
            let data = &c.files[path];
            let mut check = |files: &BTreeMap<String, Vec<u8>>, what: String| {
                if let Ok(got) = run(now, &c.bootstrap, files, &c.local, &c.target) {
                    assert_eq!(got, c.content, "{}: {what} gave other bytes", c.name);
                    still_ok += 1;
                    *survivors.entry(what).or_default() += 1;
                }
                changed += 1;
            };
            let mut files = c.files.clone();
            files.remove(path);
            check(&files, format!("removing {path}"));
            // every byte of the smaller files; every second or third of the larger ones, to stay within the time
            for i in (0..data.len()).step_by(data.len() / 1200 + 1) {
                let mut files = c.files.clone();
                files.get_mut(path).unwrap()[i] ^= 0x01;
                check(&files, format!("{}: {:?} at {i} of {path}", c.name, data[i] as char));
            }
        }
    }
    assert!(changed > 10_000, "{changed}");
    // the one change that may go unnoticed: a root that is taken away ends the rotation before it, and the older root is
    // as good when the keys did not change (only the last root's expiry guards against holding a client back)
    survivors.retain(|what, _| !(what.starts_with("removing metadata/") && what.ends_with(".root.json")));
    assert!(survivors.is_empty(), "changes that were not noticed: {survivors:?}");
    eprintln!("{changed} damaged repositories, {still_ok} not noticed (roots taken away), every other one refused");
}

/// The embedded root of Sigstore's repository is real: it signs itself with three of its five keys, and loses that when
/// any signature or signed byte changes.
#[test]
fn sigstores_root_signs_itself_and_nothing_else_does() {
    let u = Updater::new(tuf::SIGSTORE_ROOT, now_ish()).unwrap();
    assert_eq!(u.root().common.version, 15);
    let text = std::str::from_utf8(tuf::SIGSTORE_ROOT).unwrap();
    let doc = json::parse(tuf::SIGSTORE_ROOT).unwrap();
    let sigs: Vec<String> = doc.get("signatures").and_then(Value::as_array).unwrap().iter().map(|s| s.get("sig").and_then(Value::as_str).unwrap().to_string()).collect();
    assert_eq!(sigs.len(), 5);
    // three good signatures are needed: spoiling any three of the five leaves two
    for skip in [[0, 1, 2], [2, 3, 4], [0, 2, 4]] {
        let mut t = text.to_string();
        for i in skip {
            let bad: String = sigs[i].chars().rev().collect();
            t = t.replace(&sigs[i], &bad);
        }
        match Updater::new(t.as_bytes(), now_ish()) {
            Err(Error::Signature { verified: 2, threshold: 3, .. }) => {}
            other => panic!("{:?}", other.err()),
        }
    }
    // spoiling two leaves three
    let mut t = text.to_string();
    for i in [1, 3] {
        t = t.replace(&sigs[i], &sigs[i].chars().rev().collect::<String>());
    }
    Updater::new(t.as_bytes(), now_ish()).unwrap();
    // a changed signed value (the expiry) breaks every signature
    let t = text.replacen("\"expires\": \"2026-11-20T13:58:18Z\"", "\"expires\": \"2036-11-20T13:58:18Z\"", 1);
    assert_ne!(t, text);
    assert!(matches!(Updater::new(t.as_bytes(), now_ish()), Err(Error::Signature { verified: 0, .. })));
    // re-indenting changes nothing that is signed
    let compact = json::canonical(&doc).unwrap();
    Updater::new(&compact, now_ish()).unwrap();
}

fn now_ish() -> i64 {
    1_791_000_000
}
