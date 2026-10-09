//! A strict JSON reader and a canonical writer, for data that is signed.
//!
//! JSON that a signature covers must mean one thing to everyone who reads it: if this reader and the
//! one that made the signature (or the one a downstream tool will use) disagree about a duplicated
//! name, a number or a string, an attacker chooses which reading wins. So this reader refuses what
//! lax readers let through, and keeps nothing it cannot keep exactly:
//!
//! * the grammar is RFC 8259's and nothing else: no comments, no trailing commas, no `NaN`, no
//!   leading zeros or `+`, no single quotes, no control characters inside a string, whitespace only
//!   space, tab, line feed and carriage return, no byte order mark, nothing after the value;
//! * the text must be valid UTF-8 (overlong forms and encoded surrogates are not), and a `\u`
//!   escape must not make a lone surrogate (RFC 7493, I-JSON, section 2.1): a high surrogate is
//!   followed by an escaped low one, and that pair is one character;
//! * an object may not name a member twice (after unescaping, so `"a"` and `"\u0061"` are the same
//!   name): RFC 7493 section 2.3, and the cause of a family of "parser differential" bugs, since
//!   Python and JavaScript keep the last such member and many readers the first;
//! * numbers are kept as the text that was written, and [`Number::as_i64`] / [`Number::as_u64`] are
//!   exact (`None`, never a rounded value, when the text has a fraction or an exponent, is `-0`, or does
//!   not fit): there is no floating-point reading at all, so `9007199254740993` is that integer and
//!   not `9007199254740992`;
//! * nesting is limited ([`DEFAULT_MAX_DEPTH`], 32 levels, or what the caller asks for up to
//!   [`HARD_MAX_DEPTH`]) so that no input makes the reader recurse deeply.
//!
//! Protocol Buffers' JSON mapping writes 64-bit integers as decimal strings (`"logIndex": "123"`):
//! [`Value::as_int64`] reads both a number and such a string, exactly, and refuses leading zeros and
//! signs other than `-`, so there is one spelling per value.
//!
//! [`canonical`] writes a value the way RFC 8785 (the JSON Canonicalization Scheme) does, for the
//! subset this crate needs: members in order of their names as UTF-16 code units, no white space,
//! the shortest string escapes, integers in the I-JSON safe range, `-0` as `0` (any other number is an error).
//! Sigstore's v0.1 bundles sign `{body, integratedTime, logID, logIndex}` in that form.
//!
//! This module has no I/O and no dependencies, and is part of the pure build.

use std::fmt;

/// The nesting limit if the caller gives none: arrays and objects inside arrays and objects, 32 deep.
pub const DEFAULT_MAX_DEPTH: usize = 32;
/// The largest nesting limit a caller can ask for.
pub const HARD_MAX_DEPTH: usize = 256;

/// Why a text is not acceptable JSON, and where (the byte offset into the input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub offset: usize,
    pub kind: ErrorKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The input is not valid UTF-8, or starts with a byte order mark.
    Utf8,
    /// The text ends inside a value, or is empty.
    Eof,
    /// A byte that the grammar does not allow there.
    Syntax,
    /// A number that is not in RFC 8259's grammar (a leading zero, `+`, `.5`, `1.`, `1e`...).
    Number,
    /// A bad escape, a control character in a string, or a lone surrogate.
    String,
    /// An object names the same member twice.
    DuplicateName,
    /// More nesting than allowed.
    Depth,
    /// Something after the value other than white space.
    TrailingData,
    /// A value that cannot be written canonically (a number that is not a safe integer).
    NotCanonical,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ErrorKind::Utf8 => "not valid UTF-8 (or a byte order mark)",
            ErrorKind::Eof => "the text ends too soon",
            ErrorKind::Syntax => "not JSON here",
            ErrorKind::Number => "a number that is not in the JSON grammar",
            ErrorKind::String => "a bad string (escape, control character or lone surrogate)",
            ErrorKind::DuplicateName => "an object names a member twice",
            ErrorKind::Depth => "nested too deeply",
            ErrorKind::TrailingData => "data after the end of the value",
            ErrorKind::NotCanonical => "cannot be written in canonical form",
        };
        write!(f, "JSON, byte {}: {}", self.offset, what)
    }
}

impl std::error::Error for Error {}

/// A JSON number, as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number {
    text: String,
}

impl Number {
    /// The characters of the number, as they were in the input.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the text is an integer: no fraction and no exponent.
    pub fn is_integer(&self) -> bool {
        !self.text.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
    }

    /// The value as an `i64`, only if the text is an integer that fits, and is not `-0`.
    pub fn as_i64(&self) -> Option<i64> {
        if !self.is_integer() || self.text == "-0" {
            return None;
        }
        self.text.parse().ok()
    }

    /// The value as a `u64`, only if the text is a non-negative integer that fits.
    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_integer() || self.text.starts_with('-') {
            return None;
        }
        self.text.parse().ok()
    }
}

/// The members of an object, in the order they were written; no name occurs twice.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl Object {
    pub fn new() -> Object {
        Object { members: Vec::new() }
    }

    /// Adds a member. Panics if the name is already there (a program error, not an input error).
    pub fn insert(&mut self, name: &str, value: Value) {
        assert!(self.get(name).is_none(), "duplicate member name {name:?}");
        self.members.push((name.to_string(), value));
    }

    pub fn get(&self, name: &str) -> Option<&Value> {
        self.members.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.members.iter().map(|(n, v)| (n.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

/// A JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

impl Value {
    /// A string value.
    pub fn string(s: &str) -> Value {
        Value::String(s.to_string())
    }

    /// An integer value.
    pub fn int(n: i64) -> Value {
        Value::Number(Number { text: n.to_string() })
    }

    /// The member of an object, if this is one that has it.
    pub fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Object(o) => o.get(name),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// An integer, exactly: a JSON number that is an integer fitting an `i64`, or a string of the
    /// decimal digits of one (Protocol Buffers' JSON form of 64-bit integers: optional `-`, no `+`,
    /// no leading zeros, no `-0`, no white space).
    pub fn as_int64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => decimal_i64(s),
            _ => None,
        }
    }

    /// As [`as_int64`](Self::as_int64) for a `u64`.
    pub fn as_uint64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => decimal_u64(s),
            _ => None,
        }
    }
}

fn decimal_u64(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    s.parse().ok()
}

fn decimal_i64(s: &str) -> Option<i64> {
    match s.strip_prefix('-') {
        Some(rest) => {
            // "-0" is not the spelling of anything
            if rest == "0" {
                return None;
            }
            let n = decimal_u64(rest)?;
            0i64.checked_sub_unsigned(n)
        }
        None => i64::try_from(decimal_u64(s)?).ok(),
    }
}

// ================================================================================================ reading

/// Reads exactly one JSON value from `input`, with the default nesting limit.
pub fn parse(input: &[u8]) -> Result<Value, Error> {
    parse_with_depth(input, DEFAULT_MAX_DEPTH)
}

/// Reads exactly one JSON value, allowing at most `max_depth` levels of arrays and objects
/// (at most [`HARD_MAX_DEPTH`]).
pub fn parse_with_depth(input: &[u8], max_depth: usize) -> Result<Value, Error> {
    let text = match std::str::from_utf8(input) {
        Ok(t) => t,
        Err(e) => return Err(Error { offset: e.valid_up_to(), kind: ErrorKind::Utf8 }),
    };
    if text.starts_with('\u{feff}') {
        return Err(Error { offset: 0, kind: ErrorKind::Utf8 });
    }
    let mut p = Parser { s: text.as_bytes(), text, pos: 0, max_depth: max_depth.min(HARD_MAX_DEPTH) };
    p.skip_ws();
    let v = p.value(0)?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(p.err(ErrorKind::TrailingData));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    pos: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn err(&self, kind: ErrorKind) -> Error {
        Error { offset: self.pos, kind }
    }

    fn skip_ws(&mut self) {
        while matches!(self.s.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Result<u8, Error> {
        self.s.get(self.pos).copied().ok_or_else(|| self.err(ErrorKind::Eof))
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, Error> {
        if self.s[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(v)
        } else if word.starts_with(&self.s[self.pos..]) {
            Err(self.err(ErrorKind::Eof))
        } else {
            Err(self.err(ErrorKind::Syntax))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::String(self.string()?)),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.err(ErrorKind::Syntax)),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= self.max_depth {
            return Err(self.err(ErrorKind::Depth));
        }
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err(ErrorKind::Syntax)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= self.max_depth {
            return Err(self.err(ErrorKind::Depth));
        }
        self.pos += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(Value::Object(Object { members }));
        }
        let start_of_members = self.pos;
        loop {
            self.skip_ws();
            if self.peek()? != b'"' {
                return Err(self.err(ErrorKind::Syntax));
            }
            let name = self.string()?;
            self.skip_ws();
            if self.peek()? != b':' {
                return Err(self.err(ErrorKind::Syntax));
            }
            self.pos += 1;
            self.skip_ws();
            let v = self.value(depth + 1)?;
            members.push((name, v));
            self.skip_ws();
            match self.peek()? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(self.err(ErrorKind::Syntax)),
            }
        }
        // no name twice: sort the names (cheap for the small objects there are, and n log n for a hostile one)
        let mut order: Vec<usize> = (0..members.len()).collect();
        order.sort_by(|&a, &b| members[a].0.cmp(&members[b].0));
        if order.windows(2).any(|w| members[w[0]].0 == members[w[1]].0) {
            return Err(Error { offset: start_of_members, kind: ErrorKind::DuplicateName });
        }
        Ok(Value::Object(Object { members }))
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        let bad = |p: &Parser| Error { offset: p.pos, kind: ErrorKind::Number };
        if self.s[self.pos] == b'-' {
            self.pos += 1;
        }
        match self.s.get(self.pos) {
            Some(b'0') => {
                self.pos += 1;
                // a leading zero may not be followed by another digit
                if matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                    return Err(bad(self));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(bad(self)),
        }
        if self.s.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if !matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                return Err(bad(self));
            }
            while matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.s.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.s.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                return Err(bad(self));
            }
            while matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        // the number must end here: `1x`, `01`, `1.5.2` and the like are not numbers followed by something
        if matches!(self.s.get(self.pos), Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')) {
            return Err(bad(self));
        }
        Ok(Value::Number(Number { text: self.text[start..self.pos].to_string() }))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut n = 0u32;
        for _ in 0..4 {
            let d = match self.peek()? {
                c @ b'0'..=b'9' => c - b'0',
                c @ b'a'..=b'f' => c - b'a' + 10,
                c @ b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(self.err(ErrorKind::String)),
            };
            n = n * 16 + u32::from(d);
            self.pos += 1;
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, Error> {
        debug_assert_eq!(self.s[self.pos], b'"');
        self.pos += 1;
        let mut out = String::new();
        loop {
            // copy the run of plain characters in one go (the input is valid UTF-8 and the run
            // stops at an ASCII byte, so it ends on a character boundary)
            let run = self.pos;
            while let Some(&b) = self.s.get(self.pos) {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            out.push_str(&self.text[run..self.pos]);
            match self.peek()? {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let c = self.peek()?;
                    self.pos += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = match hi {
                                0xD800..=0xDBFF => {
                                    // must be followed by an escaped low surrogate
                                    if self.s.get(self.pos) != Some(&b'\\') || self.s.get(self.pos + 1) != Some(&b'u') {
                                        return Err(self.err(ErrorKind::String));
                                    }
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..=0xDFFF).contains(&lo) {
                                        return Err(self.err(ErrorKind::String));
                                    }
                                    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                                }
                                0xDC00..=0xDFFF => return Err(self.err(ErrorKind::String)),
                                _ => char::from_u32(hi),
                            };
                            out.push(ch.ok_or_else(|| self.err(ErrorKind::String))?);
                        }
                        _ => {
                            self.pos -= 1;
                            return Err(self.err(ErrorKind::String));
                        }
                    }
                }
                _ => return Err(self.err(ErrorKind::String)), // a control character
            }
        }
    }
}

// ================================================================================================ writing

/// The largest integer the I-JSON range (and a 64-bit float) holds exactly: 2^53 - 1.
const SAFE_INT: i64 = (1 << 53) - 1;

/// Writes `value` in the canonical form of RFC 8785 (for the values this crate has): object members
/// sorted by name as UTF-16 code units, no white space, strings with the shortest escapes (`\"`, `\\`,
/// `\b`, `\t`, `\n`, `\f`, `\r`, other control characters as `\u00xx` in lower case, everything else
/// as the UTF-8 characters themselves) and integers in decimal.
///
/// A number that is not an integer, or not within plus or minus 2^53 - 1, is an error
/// ([`ErrorKind::NotCanonical`]): this crate has no use for the number formatting of ECMAScript.
pub fn canonical(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => match n.as_i64() {
            Some(i) if (-SAFE_INT..=SAFE_INT).contains(&i) => out.extend_from_slice(i.to_string().as_bytes()),
            // ECMAScript writes minus zero as `0`, so RFC 8785 does
            None if n.text == "-0" => out.push(b'0'),
            _ => return Err(Error { offset: 0, kind: ErrorKind::NotCanonical }),
        },
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out)?;
            }
            out.push(b']');
        }
        Value::Object(o) => {
            let mut members: Vec<&(String, Value)> = o.members.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (i, (name, x)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(name, out);
                out.push(b':');
                write_canonical(x, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Value {
        parse(s.as_bytes()).unwrap_or_else(|e| panic!("{s:?}: {e}"))
    }

    fn bad(s: &str) -> ErrorKind {
        match parse(s.as_bytes()) {
            Ok(v) => panic!("{s:?} parsed as {v:?}"),
            Err(e) => e.kind,
        }
    }

    #[test]
    fn what_json_is() {
        assert_eq!(ok("null"), Value::Null);
        assert_eq!(ok(" true\n"), Value::Bool(true));
        assert_eq!(ok("\t[1, 2 ,3]\r\n").as_array().unwrap().len(), 3);
        assert_eq!(ok("{}"), Value::Object(Object::new()));
        assert_eq!(ok("[]"), Value::Array(vec![]));
        let v = ok(r#"{"a":{"b":[true,null,"x"]},"c":-12}"#);
        assert_eq!(v.get("a").unwrap().get("b").unwrap().as_array().unwrap()[2].as_str(), Some("x"));
        assert_eq!(v.get("c").unwrap().as_int64(), Some(-12));
        assert_eq!(v.get("zz"), None);
        // members stay in the order written
        let v = ok(r#"{"b":1,"a":2,"c":3}"#);
        let names: Vec<&str> = v.as_object().unwrap().iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["b", "a", "c"]);
    }

    #[test]
    fn the_grammar_is_rfc_8259_and_nothing_else() {
        for s in [
            "", " ", "nul", "nulL", "True", "TRUE", "NaN", "Infinity", "-Infinity", "undefined", "'a'", "[1,]", "[,1]", "[1 2]", "{\"a\":1,}", "{,}", "{\"a\"}", "{\"a\":}", "{a:1}",
            "{'a':1}", "[1}", "{\"a\":1]", "[", "{", "]", "}", "\"", "\"abc", "// c\n1", "/* c */1", "1 // c", "[1]]", "1 2", "{} {}", "\u{a0}1", "\u{b}1", "\u{c}1", "1\u{0}",
        ] {
            let k = bad(s);
            assert!(matches!(k, ErrorKind::Eof | ErrorKind::Syntax | ErrorKind::TrailingData | ErrorKind::Number | ErrorKind::String), "{s:?} {k:?}");
        }
        assert_eq!(bad("1 2"), ErrorKind::TrailingData);
        assert_eq!(bad("[1]]"), ErrorKind::TrailingData);
        assert_eq!(bad("[1,"), ErrorKind::Eof);
        assert_eq!(bad("tru"), ErrorKind::Eof);
        assert_eq!(bad("\u{feff}1"), ErrorKind::Utf8);
        // white space is these four and no others
        assert_eq!(ok(" \t\n\r1\r\n\t "), Value::Number(Number { text: "1".into() }));
    }

    #[test]
    fn numbers_are_the_grammar_and_exact() {
        for s in ["0", "-0", "1", "-1", "10", "123456789012345678901234567890", "0.5", "-0.5", "1e5", "1E+5", "1e-5", "0e0", "1.5E3", "0.0", "-0.0e-0"] {
            ok(s);
        }
        for s in [
            "01", "-01", "00", "+1", "1.", ".5", "-.5", "1.e5", "1e", "1e+", "1e-", "--1", "-", "0x10", "1_0", "1,0", "0b1", "٣", "1.5.2", "1e5e5", "0.5e", "Infinity", "-NaN", "1f", "1d", "1L", "- 1", "1 .5",
        ] {
            bad(s);
        }
        // integers are exact, and only integers are integers
        let n = |s: &str| match ok(s) {
            Value::Number(n) => n,
            _ => panic!(),
        };
        assert_eq!(n("9007199254740993").as_i64(), Some(9_007_199_254_740_993)); // not 9007199254740992
        assert_eq!(n("9223372036854775807").as_i64(), Some(i64::MAX));
        assert_eq!(n("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(n("9223372036854775808").as_i64(), None);
        assert_eq!(n("9223372036854775808").as_u64(), Some(9_223_372_036_854_775_808));
        assert_eq!(n("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(n("18446744073709551616").as_u64(), None);
        assert_eq!(n("-1").as_u64(), None);
        assert_eq!(n("-0").as_i64(), None);
        assert_eq!(n("0").as_i64(), Some(0));
        for s in ["1.0", "1e2", "1E2", "100e-2", "0.0", "-0.0"] {
            assert_eq!(n(s).as_i64(), None, "{s}");
            assert_eq!(n(s).as_u64(), None, "{s}");
            assert!(!n(s).is_integer());
        }
        // and what was written is what is kept
        assert_eq!(n("1.50E+2").text(), "1.50E+2");
    }

    #[test]
    fn protobuf_json_writes_64_bit_integers_as_decimal_strings() {
        let v = ok(r#"{"s":"3075544565","n":3075544565,"neg":"-5","big":"9223372036854775808","bigu":"18446744073709551615"}"#);
        assert_eq!(v.get("s").unwrap().as_int64(), Some(3_075_544_565));
        assert_eq!(v.get("n").unwrap().as_int64(), Some(3_075_544_565));
        assert_eq!(v.get("neg").unwrap().as_int64(), Some(-5));
        assert_eq!(v.get("big").unwrap().as_int64(), None);
        assert_eq!(v.get("big").unwrap().as_uint64(), Some(9_223_372_036_854_775_808));
        assert_eq!(v.get("bigu").unwrap().as_uint64(), Some(u64::MAX));
        for s in ["", "+1", "01", "00", "-0", " 1", "1 ", "1.0", "1e3", "0x1", "١", "-", "--1", "-01", "1_000", "9223372036854775808", "-9223372036854775809", "NaN"] {
            assert_eq!(Value::string(s).as_int64(), None, "{s:?}");
        }
        assert_eq!(Value::string("-9223372036854775808").as_int64(), Some(i64::MIN));
        assert_eq!(Value::string("0").as_int64(), Some(0));
        assert_eq!(Value::Null.as_int64(), None);
        assert_eq!(Value::Bool(true).as_uint64(), None);
    }

    #[test]
    fn strings_escapes_and_surrogates() {
        assert_eq!(ok(r#""a\"b\\c\/d\b\f\n\r\t""#).as_str(), Some("a\"b\\c/d\u{8}\u{c}\n\r\t"));
        assert_eq!(ok(r#""\u0041\u00e9\u20AC""#).as_str(), Some("A\u{e9}\u{20ac}"));
        assert_eq!(ok(r#""\ud83d\ude00""#).as_str(), Some("\u{1f600}"));
        assert_eq!(ok(r#""\uD83D\uDE00""#).as_str(), Some("\u{1f600}"));
        assert_eq!(ok("\"\u{1f600} \u{e9} \u{20ac}\"").as_str(), Some("\u{1f600} \u{e9} \u{20ac}"));
        assert_eq!(ok(r#""\u0000""#).as_str(), Some("\0"));
        assert_eq!(ok(r#""\uffff \ufffe""#).as_str(), Some("\u{ffff} \u{fffe}"));
        // lone and misordered surrogates are refused, however they are written
        for s in [
            r#""\ud800""#, r#""\udbff""#, r#""\udc00""#, r#""\udfff""#, r#""\ud800a""#, r#""\ud800\u0041""#, r#""\ud800\ud800""#, r#""\udc00\ud800""#, r#""\ud800\\udc00""#, r#""\ud800 \udc00""#, r#""\ud800\n""#,
            r#""\udc00\udc00""#,
        ] {
            assert_eq!(bad(s), ErrorKind::String, "{s}");
        }
        // bad escapes, control characters, bad hex
        for s in [r#""\x41""#, r#""\a""#, r#""\u12""#, r#""\u12G4""#, r#""\u""#, r#""\ ""#, r#""\'""#, r#""\U0041""#, "\"\\u+041\"", "\"a\u{1}b\"", "\"a\nb\"", "\"a\tb\"", "\"\u{0}\"", "\"\u{1f}\"", "\"\\"] {
            assert!(matches!(bad(s), ErrorKind::String | ErrorKind::Eof), "{s:?}");
        }
        // DEL and other printable-ish characters are fine
        assert_eq!(ok("\"\u{7f}\"").as_str(), Some("\u{7f}"));
    }

    #[test]
    fn the_input_must_be_utf_8() {
        for bytes in [
            &b"\"\xff\""[..],
            b"\"\xc0\xaf\"",      // overlong '/'
            b"\"\xc1\x81\"",      // overlong 'A'
            b"\"\xe0\x80\xaf\"",  // overlong
            b"\"\xed\xa0\x80\"",  // an encoded surrogate
            b"\"\xed\xbf\xbf\"",  // an encoded surrogate
            b"\"\xf4\x90\x80\x80\"", // beyond U+10FFFF
            b"\"\xf8\x88\x80\x80\x80\"",
            b"\"\x80\"",
            b"\"\xe2\x82\"",
            b"\"abc\xe2\"",
            b"\xef\xbb\xbf1",     // a byte order mark
            b"\xff\xfe1\x00",      // UTF-16
        ] {
            let e = parse(bytes).unwrap_err();
            assert_eq!(e.kind, ErrorKind::Utf8, "{bytes:?}");
        }
        // an encoded U+FEFF inside a string is just a character
        assert_eq!(ok("\"\u{feff}\"").as_str(), Some("\u{feff}"));
    }

    #[test]
    fn an_object_may_not_name_a_member_twice() {
        for s in [
            r#"{"a":1,"a":2}"#, r#"{"a":1,"a":1}"#, r#"{"a":1,"b":2,"a":3}"#, r#"{"a":1,"\u0061":2}"#, r#"{"\u0061":1,"a":2}"#, r#"{"a":{"b":1,"b":2}}"#, r#"[{"a":1,"a":2}]"#,
            r#"{"é":1,"\u00e9":2}"#, r#"{"\ud83d\ude00":1,"😀":2}"#, r#"{"":1,"":2}"#, r#"{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"a":10}"#,
        ] {
            assert_eq!(bad(s), ErrorKind::DuplicateName, "{s}");
        }
        // different names, or the same name in different objects, are fine
        ok(r#"{"a":1,"A":2,"a ":3,"":4}"#);
        ok(r#"{"a":{"a":1},"b":{"a":2}}"#);
        ok(r#"[{"a":1},{"a":2}]"#);
        // a hostile object with many members is still quick (n log n)
        let mut s = String::from("{");
        for i in 0..50_000 {
            s.push_str(&format!("\"k{i}\":{i},"));
        }
        s.push_str("\"k7\":0}");
        assert_eq!(bad(&s), ErrorKind::DuplicateName);
    }

    #[test]
    fn nesting_is_limited() {
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        ok(&nest(32));
        assert_eq!(bad(&nest(33)), ErrorKind::Depth);
        let mut s = String::new();
        for _ in 0..33 {
            s.push_str("{\"a\":");
        }
        s.push('1');
        s.push_str(&"}".repeat(33));
        assert_eq!(bad(&s), ErrorKind::Depth);
        // a caller can ask for more or less, up to a hard limit
        assert!(parse_with_depth(nest(64).as_bytes(), 64).is_ok());
        assert_eq!(parse_with_depth(nest(5).as_bytes(), 4).unwrap_err().kind, ErrorKind::Depth);
        assert!(parse_with_depth(nest(256).as_bytes(), 100_000).is_ok());
        assert_eq!(parse_with_depth(nest(257).as_bytes(), 100_000).unwrap_err().kind, ErrorKind::Depth);
        // a million levels do not overflow the stack
        assert_eq!(bad(&"[".repeat(1_000_000)), ErrorKind::Depth);
        assert_eq!(bad(&format!("{}1", "{\"a\":".repeat(1_000_000))), ErrorKind::Depth);
    }

    #[test]
    fn error_offsets_point_at_the_trouble() {
        assert_eq!(parse(b"[1, x]").unwrap_err().offset, 4);
        assert_eq!(parse(b"{\"a\":1} x").unwrap_err().offset, 8);
        assert_eq!(parse(b"01").unwrap_err().offset, 1);
        assert_eq!(parse(b"[1,2").unwrap_err().kind, ErrorKind::Eof);
        assert_eq!(parse(b"\"ab\xff\"").unwrap_err().offset, 3);
        assert!(parse(b"[").unwrap_err().to_string().contains("byte 1"));
    }

    #[test]
    fn canonical_form_is_rfc_8785() {
        let c = |s: &str| String::from_utf8(canonical(&ok(s)).unwrap()).unwrap();
        // the example of RFC 8785 section 3.2.3 (sorting), with numbers that are integers
        assert_eq!(c(r#"{ "b" : [ 1 , 2 ] , "a" : "x" , "" : null }"#), r#"{"":null,"a":"x","b":[1,2]}"#);
        // sorted by UTF-16 code units, not by code points or UTF-8 bytes: U+20AC (€) before U+1F600 (a surrogate pair d83d)
        assert_eq!(c("{\"\u{1f600}\":1,\"\u{20ac}\":2,\"\u{ffff}\":3,\"a\":4}"), "{\"a\":4,\"\u{20ac}\":2,\"\u{1f600}\":1,\"\u{ffff}\":3}");
        // escapes
        assert_eq!(c(r#""\u0041\/\u00e9\u0001\u001f\u007f\"\\\b\f\n\r\t""#), "\"A/\u{e9}\\u0001\\u001f\u{7f}\\\"\\\\\\b\\f\\n\\r\\t\"");
        assert_eq!(c("\"\u{2028}\u{2029}\""), "\"\u{2028}\u{2029}\""); // written as they are
        assert_eq!(c("[true,false,null,0,-1,9007199254740991,-9007199254740991]"), "[true,false,null,0,-1,9007199254740991,-9007199254740991]");
        assert_eq!(c("{\"a\":{\"c\":1,\"b\":2},\"0\":[ ]}"), "{\"0\":[],\"a\":{\"b\":2,\"c\":1}}");
        // numbers outside what is written exactly are refused
        assert_eq!(c("-0"), "0");
        for s in ["1.5", "1e3", "1.0", "9007199254740992", "-9007199254740992", "18446744073709551615"] {
            assert_eq!(canonical(&ok(s)).unwrap_err().kind, ErrorKind::NotCanonical, "{s}");
        }
        // writing and reading again gives the same bytes
        let v = ok(r#"{"z":[1,{"y":"\u00e9\ud83d\ude00","x":null}],"a":"\n"}"#);
        let once = canonical(&v).unwrap();
        assert_eq!(canonical(&parse(&once).unwrap()).unwrap(), once);
    }

    #[test]
    fn sigstores_signed_entry_timestamp_payload() {
        // Rekor signs this object in canonical form (see sigstore.rs for the real thing)
        let mut o = Object::new();
        o.insert("logIndex", Value::int(8_668_626));
        o.insert("integratedTime", Value::int(1_670_516_322));
        o.insert("logID", Value::string("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"));
        o.insert("body", Value::string("eyJhcGk="));
        assert_eq!(
            String::from_utf8(canonical(&Value::Object(o)).unwrap()).unwrap(),
            r#"{"body":"eyJhcGk=","integratedTime":1670516322,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d","logIndex":8668626}"#
        );
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// 2,762 texts (tests/data/json_vectors.txt, made by tools/gen_json_vectors.py): valid and damaged ones, with
    /// the verdict of a strict reader made from Python's `json` (UTF-8 strictly, no BOM, no NaN, duplicate names and
    /// lone surrogates refused) and the canonical form made by the independent `rfc8785` package.
    #[test]
    fn agrees_with_python_and_rfc8785() {
        let (mut accepted, mut refused, mut canon) = (0, 0, 0);
        for line in include_str!("../tests/data/json_vectors.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = line.split(' ').collect();
            assert_eq!(f[0], "case");
            let text = unhex(f[1]);
            let mine = parse(&text);
            match f[2] {
                "bad" => {
                    assert!(mine.is_err(), "Python refuses {:?}, this reader accepts", String::from_utf8_lossy(&text));
                    refused += 1;
                }
                _ => {
                    let v = mine.unwrap_or_else(|e| panic!("Python accepts {:?}, this reader refuses: {e}", String::from_utf8_lossy(&text)));
                    accepted += 1;
                    match f[3] {
                        "-" => assert!(canonical(&v).is_err(), "{:?}", String::from_utf8_lossy(&text)),
                        want => {
                            assert_eq!(hex(&canonical(&v).unwrap()), want, "{:?}", String::from_utf8_lossy(&text));
                            canon += 1;
                        }
                    }
                }
            }
        }
        assert!(accepted > 600 && refused > 1500 && canon > 400, "{accepted} {refused} {canon}");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A tiny generator of documents and damage, with no randomness crate: an LCG.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn gen(rng: &mut Rng, depth: u32, out: &mut String) {
        match if depth > 3 { rng.below(5) } else { rng.below(7) } {
            0 => out.push_str("null"),
            1 => out.push_str(if rng.below(2) == 0 { "true" } else { "false" }),
            2 => out.push_str(&format!("{}", rng.next() as i64 - (1 << 30))),
            3 => {
                out.push('"');
                for _ in 0..rng.below(8) {
                    out.push_str(["a", "b", "\\n", "\\u00e9", "\\ud83d\\ude00", "é", "😀", "\\\"", " ", "\\/"][rng.below(10) as usize]);
                }
                out.push('"');
            }
            4 => out.push_str(["0", "-0", "1.5", "1e3", "-2.5E-3", "0.0"][rng.below(6) as usize]),
            5 => {
                out.push('[');
                for i in 0..rng.below(4) {
                    if i > 0 {
                        out.push(',');
                    }
                    gen(rng, depth + 1, out);
                }
                out.push(']');
            }
            _ => {
                out.push('{');
                for i in 0..rng.below(4) {
                    if i > 0 {
                        out.push_str(" , ");
                    }
                    out.push_str(&format!("\"k{}\" : ", i));
                    gen(rng, depth + 1, out);
                }
                out.push('}');
            }
        }
    }

    #[test]
    fn whatever_parses_is_unique_and_stable_and_nothing_panics() {
        let mut rng = Rng(7);
        let mut parsed = 0;
        for _ in 0..4000 {
            let mut s = String::new();
            gen(&mut rng, 0, &mut s);
            let mut bytes = s.into_bytes();
            // damage a few
            for _ in 0..rng.below(3) {
                if bytes.is_empty() {
                    break;
                }
                let i = rng.below(bytes.len() as u64) as usize;
                match rng.below(4) {
                    0 => bytes[i] ^= 1 << rng.below(8),
                    1 => {
                        bytes.remove(i);
                    }
                    2 => {
                        let junk = b"{}[]\",:\\0e-+. \n";
                        bytes.insert(i, junk[rng.below(junk.len() as u64) as usize]);
                    }
                    _ => bytes.truncate(i),
                }
            }
            if let Ok(v) = parse(&bytes) {
                parsed += 1;
                // names are unique in every object
                fn check(v: &Value) {
                    match v {
                        Value::Object(o) => {
                            let mut names: Vec<&str> = o.iter().map(|(n, _)| n).collect();
                            names.sort();
                            names.dedup();
                            assert_eq!(names.len(), o.len());
                            o.iter().for_each(|(_, x)| check(x));
                        }
                        Value::Array(a) => a.iter().for_each(check),
                        _ => {}
                    }
                }
                check(&v);
                if let Ok(c) = canonical(&v) {
                    assert_eq!(canonical(&parse(&c).unwrap()).unwrap(), c);
                }
            }
        }
        assert!(parsed > 500, "{parsed}");
    }
}
