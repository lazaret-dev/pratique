//! Shared by the Sigstore integration tests: editing a parsed JSON document and damaging every part of a
//! bundle in turn.

#![allow(dead_code)]

use pratique::json::{self, Object, Value};
use pratique::sigstore::{Error, Verified};

// ------------------------------------------------------------------------------------ editing JSON

#[derive(Clone, Debug)]
pub enum Step {
    Key(&'static str),
    KeyOwned(String),
    Index(usize),
}
pub use Step::{Index, Key};

pub fn show(path: &[Step]) -> String {
    let mut out = String::new();
    for s in path {
        match s {
            Key(k) => out.push_str(&format!(".{k}")),
            Step::KeyOwned(k) => out.push_str(&format!(".{k}")),
            Index(i) => out.push_str(&format!("[{i}]")),
        }
    }
    out.trim_start_matches('.').to_string()
}

pub fn matches_step(s: &Step, name: &str) -> bool {
    match s {
        Key(k) => *k == name,
        Step::KeyOwned(k) => k == name,
        Index(_) => false,
    }
}

/// `v` with the node at `path` replaced by `new`, or removed when `new` is `None`.
pub fn edit(v: &Value, path: &[Step], new: Option<Value>) -> Value {
    let Some((first, rest)) = path.split_first() else { return new.expect("the root cannot be removed") };
    match (v, first) {
        (Value::Object(o), s) if !matches!(s, Index(_)) => {
            let mut out = Object::new();
            for (name, x) in o.iter() {
                if matches_step(s, name) {
                    if rest.is_empty() {
                        if let Some(n) = &new {
                            out.insert(name, n.clone());
                        }
                    } else {
                        out.insert(name, edit(x, rest, new.clone()));
                    }
                } else {
                    out.insert(name, x.clone());
                }
            }
            Value::Object(out)
        }
        (Value::Array(a), Index(i)) => {
            let mut out = Vec::new();
            for (j, x) in a.iter().enumerate() {
                if j != *i {
                    out.push(x.clone());
                } else if rest.is_empty() {
                    if let Some(n) = &new {
                        out.push(n.clone());
                    }
                } else {
                    out.push(edit(x, rest, new.clone()));
                }
            }
            Value::Array(out)
        }
        _ => panic!("no {} in the document", show(path)),
    }
}

pub fn at<'a>(v: &'a Value, path: &[Step]) -> &'a Value {
    let mut cur = v;
    for s in path {
        cur = match (cur, s) {
            (Value::Object(o), Key(k)) => o.get(k).unwrap(),
            (Value::Object(o), Step::KeyOwned(k)) => o.get(k).unwrap(),
            (Value::Array(a), Index(i)) => &a[*i],
            _ => panic!(),
        };
    }
    cur
}

/// The paths of every member and element in the document.
pub fn all_paths(v: &Value, path: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o.iter() {
                path.push(Step::KeyOwned(k.to_string()));
                out.push(path.clone());
                all_paths(x, path, out);
                path.pop();
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                path.push(Index(i));
                out.push(path.clone());
                all_paths(x, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

/// A character of `s` near `pos` changed to another one, if there is a letter or digit to change.
pub fn bumped(s: &str, pos: usize) -> Option<String> {
    let chars: Vec<char> = s.chars().collect();
    let at = (pos..chars.len()).find(|&i| chars[i].is_ascii_alphanumeric())?;
    let c = chars[at];
    let new = if c == 'A' { 'B' } else if c.is_ascii_digit() { if c == '9' { '8' } else { (c as u8 + 1) as char } } else { 'A' };
    let mut out = chars;
    out[at] = new;
    Some(out.into_iter().collect())
}

/// The ways to damage one string.
pub fn damaged(s: &str) -> Vec<String> {
    let n = s.chars().count();
    let mut out: Vec<String> = [0, n / 3, 2 * n / 3, n.saturating_sub(2)].iter().filter_map(|&p| bumped(s, p)).collect();
    if n > 0 {
        out.push(s.chars().take(n - 1).collect());
    }
    out.push(format!("{s}A"));
    out.push(String::new());
    out.retain(|d| d != s);
    out
}


/// Changes or removes every member and element of the document, one at a time, and every string in several
/// ways; `verify_one(document, n)` verifies attestation `n` of what comes out (`None` if it is not
/// readable). A change that still verifies must be to something `allowed` says nothing authenticates.
pub fn damage_every_part(
    doc_bytes: &[u8],
    target: &dyn Fn(&[Step]) -> usize,
    verify_one: &dyn Fn(&[u8], usize) -> Option<Result<Verified, Error>>,
    allowed: &dyn Fn(&str, &Value, Option<&Value>) -> bool,
) -> usize {
    let doc = json::parse(doc_bytes).unwrap();
    let mut paths = Vec::new();
    all_paths(&doc, &mut Vec::new(), &mut paths);
    let mut tried = 0;
    for path in &paths {
        let node = at(&doc, path);
        let mut variants: Vec<Option<Value>> = vec![None];
        if let Value::String(s) = node {
            variants.extend(damaged(s).into_iter().map(|d| Some(Value::String(d))));
        }
        for new in variants {
            let mutated = json::canonical(&edit(&doc, path, new.clone())).unwrap();
            tried += 1;
            // removing a whole attestation shifts the next one into its place: nothing to check
            if new.is_none() && path.len() == 2 && matches!(&path[1], Index(_)) {
                continue;
            }
            if let Some(Ok(v)) = verify_one(&mutated, target(path)) {
                assert!(
                    allowed(&show(path), node, new.as_ref()),
                    "{} {:?} still verifies ({:?}): something authenticated is not checked",
                    show(path),
                    new.as_ref().map(|n| format!("{n:?}")),
                    v.statement.predicate_type
                );
            }
        }
    }
    tried
}

