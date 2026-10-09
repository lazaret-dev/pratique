//! Internationalized host names: Punycode (RFC 3492) and a conservative conversion of a host name to the form DNS,
//! TLS and certificates use (A-labels, `xn--...`).
//!
//! A certificate names hosts in ASCII only (a dNSName is an IA5String, and an internationalized label is written as
//! its A-label), and so does TLS (the server name, RFC 6066) and this crate's URL parser, which refuses a host that is
//! not ASCII. [`to_ascii`] is for a caller that has a host name in Unicode, `bücher.example` say, and needs
//! `xn--bcher-kva.example`; [`to_unicode`] goes the other way, for showing a name to a person.
//!
//! What [`to_ascii`] does, label by label: an ASCII label is lower-cased and kept (an `xn--` label must be a valid
//! A-label: it decodes, it is not all ASCII once decoded, and encoding the result gives it back); a label with other
//! characters is lower-cased character by character (Rust's `char::to_lowercase`, which is Unicode's simple case
//! mapping) and encoded. Ideographic and full-width full stops separate labels like `.`.
//!
//! What it does not do, because it needs Unicode tables this crate does not carry: the mapping of UTS #46 (full-width
//! letters to ASCII, compatibility characters, `ß` to `ss` in its transitional form), normalization to NFC, and the
//! context, script and bidirectional rules of IDNA2008 (RFC 5892, RFC 5893). So it refuses instead of guessing: a
//! character that is not a letter or a digit (as `char::is_alphanumeric` sees it) or a hyphen, one whose lower case is
//! more than one character (`İ`), a hyphen at either end of a label, `--` in the third and fourth places of a label
//! that is not an A-label, and names or labels that are too long for DNS. Give it NFC text, which is what keyboards and
//! most sources produce. A name it converts is one that a browser converts the same way (IDNA2008 with UTS #46
//! non-transitional processing); a name that needs more than the above is an error, never a different name.
//!
//! None of this decides anything about trust: the A-label is what is looked up, sent and checked against the
//! certificate, which holds A-labels itself. Two names that look alike to a person (a Latin `a` and a Cyrillic `а`)
//! are different names here, as they are in DNS.

use std::fmt;

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

/// The longest label DNS allows, in bytes of its A-label.
const MAX_LABEL: usize = 63;
/// The longest name DNS allows, in bytes, without a trailing dot.
const MAX_NAME: usize = 253;

fn adapt(mut delta: u32, points: u32, first: bool) -> u32 {
    delta /= if first { DAMP } else { 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
}

fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

fn digit_char(d: u32) -> char {
    debug_assert!(d < BASE);
    if d < 26 {
        (b'a' + d as u8) as char
    } else {
        (b'0' + (d - 26) as u8) as char
    }
}

fn digit_value(c: u8) -> Option<u32> {
    match c {
        b'a'..=b'z' => Some((c - b'a') as u32),
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'0'..=b'9' => Some((c - b'0') as u32 + 26),
        _ => None,
    }
}

/// The Punycode of `input` (RFC 3492 section 6.3): its ASCII characters as they are, then `-` if there were any, then
/// the rest encoded, in lower case. `None` only if the arithmetic would overflow (an input of millions of characters).
pub fn punycode_encode(input: &[char]) -> Option<String> {
    let mut out: String = input.iter().filter(|c| c.is_ascii()).collect();
    let basic = out.len() as u32;
    if basic > 0 {
        out.push('-');
    }
    let total = u32::try_from(input.len()).ok()?;
    let (mut n, mut delta, mut bias, mut handled) = (INITIAL_N, 0u32, INITIAL_BIAS, basic);
    while handled < total {
        let m = input.iter().map(|&c| c as u32).filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in input {
            let c = c as u32;
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    out.push(digit_char(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit_char(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// The characters Punycode `input` stands for (RFC 3492 section 6.2), or `None` if it is not valid Punycode: a byte
/// that is not ASCII, a digit that is not one, an encoding that ends in the middle of a number, a number that
/// overflows, or one that decodes to an ASCII character or to something that is not a Unicode scalar value. Upper
/// and lower case digits are the same (the RFC's mixed-case annotation is ignored).
pub fn punycode_decode(input: &str) -> Option<Vec<char>> {
    if !input.is_ascii() {
        return None;
    }
    // the last hyphen ends the ASCII part; one at the very start is not a delimiter (RFC 3492 section 6.2: "b" is 0
    // and nothing is consumed), so it is read as a digit, which it is not
    let (basic, rest) = match input.rfind('-') {
        Some(at) if at > 0 => (&input[..at], &input[at + 1..]),
        _ => ("", input),
    };
    let mut out: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (INITIAL_N, 0u32, INITIAL_BIAS);
    let mut bytes = rest.bytes().peekable();
    while bytes.peek().is_some() {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let digit = digit_value(bytes.next()?)?;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let len = u32::try_from(out.len()).ok()? + 1;
        bias = adapt(i - old_i, len, old_i == 0);
        n = n.checked_add(i / len)?;
        i %= len;
        if n < INITIAL_N {
            return None;
        }
        out.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(out)
}

/// Why [`to_ascii`] refused a name.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdnaError {
    /// The name, or one of its labels, is empty (a single trailing dot is allowed).
    EmptyLabel,
    /// A label is longer than 63 bytes once converted.
    LabelTooLong,
    /// The name is longer than 253 bytes once converted.
    NameTooLong,
    /// A character that is not a letter, a digit or a hyphen, or that needs more than a simple case mapping.
    Character(char),
    /// A label starts or ends with a hyphen, or has `--` in its third and fourth places without being an A-label.
    Hyphen,
    /// A label that starts with `xn--` is not a valid A-label.
    ALabel,
}

impl fmt::Display for IdnaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdnaError::EmptyLabel => write!(f, "a host name with an empty label"),
            IdnaError::LabelTooLong => write!(f, "a label longer than 63 bytes"),
            IdnaError::NameTooLong => write!(f, "a host name longer than 253 bytes"),
            IdnaError::Character(c) => write!(f, "the character {:?} (U+{:04X}) cannot be converted without Unicode tables this crate does not have", c, *c as u32),
            IdnaError::Hyphen => write!(f, "a label that starts or ends with a hyphen, or has \"--\" in its third and fourth places"),
            IdnaError::ALabel => write!(f, "a label that starts with \"xn--\" but is not a valid A-label"),
        }
    }
}

impl std::error::Error for IdnaError {}

/// The full stops that separate labels (UTS #46 section 4, step 1 maps the last three to `.`).
fn is_dot(c: char) -> bool {
    matches!(c, '.' | '\u{3002}' | '\u{ff0e}' | '\u{ff61}')
}

/// The U-label rules this code can check without tables: letters and digits of any script (and hyphens), each with a
/// one-character lower case; no hyphen at either end.
fn u_label(label: &str) -> Result<Vec<char>, IdnaError> {
    let mut chars = Vec::with_capacity(label.len());
    for c in label.chars() {
        let mut lower = c.to_lowercase();
        let (Some(l), None) = (lower.next(), lower.next()) else { return Err(IdnaError::Character(c)) };
        if !(l.is_alphanumeric() || l == '-') {
            return Err(IdnaError::Character(c));
        }
        chars.push(l);
    }
    if chars.first() == Some(&'-') || chars.last() == Some(&'-') {
        return Err(IdnaError::Hyphen);
    }
    Ok(chars)
}

/// `label` (ASCII, lower case) if it is a valid A-label: Punycode after `xn--` that decodes to a label with something
/// other than ASCII in it, that passes the U-label rules above, and that encodes back to exactly this.
fn a_label(label: &str) -> Result<(), IdnaError> {
    let encoded = &label[4..];
    let decoded = punycode_decode(encoded).ok_or(IdnaError::ALabel)?;
    if decoded.is_empty() || decoded.iter().all(char::is_ascii) {
        return Err(IdnaError::ALabel);
    }
    let text: String = decoded.iter().collect();
    let checked = u_label(&text).map_err(|_| IdnaError::ALabel)?;
    if checked != decoded || punycode_encode(&decoded).as_deref() != Some(encoded) {
        return Err(IdnaError::ALabel);
    }
    Ok(())
}

/// `name` with every label in the form DNS and certificates use: see the [module documentation](self) for what is
/// converted and what is refused. An IP address literal is not a host name; give it to the caller's IP path instead.
/// A trailing dot is kept.
///
/// ```
/// use pratique::idna::to_ascii;
/// assert_eq!(to_ascii("Bücher.Example").unwrap(), "xn--bcher-kva.example");
/// assert_eq!(to_ascii("пример.испытание").unwrap(), "xn--e1afmkfd.xn--80akhbyknj4f");
/// assert_eq!(to_ascii("crates.io").unwrap(), "crates.io");
/// assert!(to_ascii("exa mple.com").is_err());
/// ```
pub fn to_ascii(name: &str) -> Result<String, IdnaError> {
    let (body, dot) = match name.char_indices().last() {
        Some((at, c)) if is_dot(c) => (&name[..at], "."),
        _ => (name, ""),
    };
    if body.is_empty() {
        return Err(IdnaError::EmptyLabel);
    }
    let mut out = String::with_capacity(body.len());
    for label in body.split(is_dot) {
        if label.is_empty() {
            return Err(IdnaError::EmptyLabel);
        }
        if !out.is_empty() {
            out.push('.');
        }
        if label.is_ascii() {
            let lower = label.to_ascii_lowercase();
            if !lower.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                let bad = lower.chars().find(|&c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')).unwrap_or('?');
                return Err(IdnaError::Character(bad));
            }
            if lower.starts_with('-') || lower.ends_with('-') {
                return Err(IdnaError::Hyphen);
            }
            if lower.starts_with("xn--") {
                a_label(&lower)?;
            } else if lower.get(2..4) == Some("--") {
                return Err(IdnaError::Hyphen);
            }
            if lower.len() > MAX_LABEL {
                return Err(IdnaError::LabelTooLong);
            }
            out.push_str(&lower);
        } else {
            let chars = u_label(label)?;
            let encoded = punycode_encode(&chars).ok_or(IdnaError::LabelTooLong)?;
            if 4 + encoded.len() > MAX_LABEL {
                return Err(IdnaError::LabelTooLong);
            }
            out.push_str("xn--");
            out.push_str(&encoded);
        }
    }
    if out.len() > MAX_NAME {
        return Err(IdnaError::NameTooLong);
    }
    out.push_str(dot);
    Ok(out)
}

/// `name` with each valid A-label replaced by the Unicode label it stands for, for showing to a person. Labels that
/// are not valid A-labels are left as they are, so this never fails; what it returns is for display only, and the
/// name to connect to and to check certificates against is the ASCII one.
pub fn to_unicode(name: &str) -> String {
    name.split('.')
        .map(|label| {
            let lower = label.to_ascii_lowercase();
            if lower.starts_with("xn--") && a_label(&lower).is_ok() {
                punycode_decode(&lower[4..]).map(|cs| cs.into_iter().collect()).unwrap_or_else(|| label.to_string())
            } else {
                label.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tests/data/punycode_vectors.txt: (code points, encoding).
    fn vectors() -> Vec<(Vec<char>, String)> {
        include_str!("../tests/data/punycode_vectors.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| {
                let (cps, enc) = l.split_once('\t').expect("a tab");
                let chars = if cps == "-" { Vec::new() } else { cps.split(' ').map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap()).collect() };
                (chars, enc.to_string())
            })
            .collect()
    }

    #[test]
    fn the_rfc_samples_and_pythons_encodings_both_ways() {
        let all = vectors();
        assert_eq!(all.len(), 220);
        for (chars, enc) in &all {
            // the encoder writes lower case; the RFC's samples I, D, J, K... carry upper-case annotations or basic letters
            let got = punycode_encode(chars).unwrap();
            let want_lower: String = enc.chars().map(|c| if c.is_ascii_uppercase() && !chars.contains(&c) { c.to_ascii_lowercase() } else { c }).collect();
            assert_eq!(got, want_lower, "{chars:?}");
            assert_eq!(punycode_decode(enc).as_ref(), Some(chars), "{enc}");
            // and with the digits in upper case, the same characters
            let upper: String = match enc.rfind('-') {
                Some(at) => format!("{}{}", &enc[..=at], enc[at + 1..].to_ascii_uppercase()),
                None => enc.to_ascii_uppercase(),
            };
            assert_eq!(punycode_decode(&upper).as_ref(), Some(chars), "{upper}");
        }
    }

    #[test]
    fn invalid_punycode_is_refused() {
        assert_eq!(punycode_decode("a-é"), None, "not ASCII");
        assert_eq!(punycode_decode("ab!"), None, "not a digit");
        assert_eq!(punycode_decode("9999999999a"), None, "a number too large for 32 bits");
        assert_eq!(punycode_decode("99999999999"), None, "a number that does not end");
        assert_eq!(punycode_decode("z"), None, "a digit at or above the threshold with nothing after it");
        assert_eq!(punycode_decode("a9999999a"), None, "a code point beyond Unicode");
        assert_eq!(punycode_decode("-5"), None, "a hyphen at the start is not a delimiter, and not a digit");
        // what does decode encodes back to the same (in lower case)
        for s in ["a", "aaa-a", "AAA-A", "-> $1.00 <--", "", "abc-"] {
            let chars = punycode_decode(s).unwrap_or_else(|| panic!("{s:?}"));
            let back = punycode_encode(&chars).unwrap();
            assert_eq!(back.to_ascii_lowercase(), s.to_ascii_lowercase(), "{s:?}");
        }
        assert_eq!(punycode_decode("a"), Some(vec!['\u{80}']));
    }

    #[test]
    fn host_names_to_ascii() {
        for (input, want) in [
            ("bücher.example", "xn--bcher-kva.example"),
            ("BÜCHER.Example", "xn--bcher-kva.example"),
            ("münchen.de", "xn--mnchen-3ya.de"),
            ("пример.испытание", "xn--e1afmkfd.xn--80akhbyknj4f"),
            ("例え.テスト", "xn--r8jz45g.xn--zckzah"),
            ("ελληνικά.gr", "xn--hxargifdar.gr"),
            ("faß.de", "xn--fa-hia.de"),
            ("crates.io", "crates.io"),
            ("Registry.NPMJS.org.", "registry.npmjs.org."),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("XN--BCHER-KVA.example", "xn--bcher-kva.example"),
            ("bücher。example", "xn--bcher-kva.example"),
            ("_dmarc.example.com", "_dmarc.example.com"),
            ("a-b.example", "a-b.example"),
            ("123.example", "123.example"),
        ] {
            assert_eq!(to_ascii(input).as_deref(), Ok(want), "{input}");
        }
    }

    #[test]
    fn what_to_ascii_refuses() {
        for (input, why) in [
            ("", IdnaError::EmptyLabel),
            (".", IdnaError::EmptyLabel),
            ("a..b", IdnaError::EmptyLabel),
            (".example", IdnaError::EmptyLabel),
            ("example..", IdnaError::EmptyLabel),
            ("exa mple.com", IdnaError::Character(' ')),
            ("exa/mple.com", IdnaError::Character('/')),
            ("-a.example", IdnaError::Hyphen),
            ("a-.example", IdnaError::Hyphen),
            ("ab--c.example", IdnaError::Hyphen),
            ("-ü.example", IdnaError::Hyphen),
            ("☃.example", IdnaError::Character('☃')),
            ("a\u{200d}b.example", IdnaError::Character('\u{200d}')),
            ("e\u{301}.example", IdnaError::Character('\u{301}')),
            ("İstanbul.example", IdnaError::Character('İ')),
            ("xn--.example", IdnaError::Hyphen),
            ("xn--abc-.example", IdnaError::Hyphen),
            ("xn--a.example", IdnaError::ALabel),
            ("xn--zzzzzzzzzzzzzzzzzzzzzzzzzz.example", IdnaError::ALabel),
            // an A-label whose Unicode form is not lower case, or not one this code could have made
            ("xn--bcher-2pa.example", IdnaError::ALabel),
            ("xn--ls8h.example", IdnaError::ALabel),
        ] {
            assert_eq!(to_ascii(input), Err(why), "{input:?}");
        }
        let long = "a".repeat(64);
        assert_eq!(to_ascii(&format!("{long}.example")), Err(IdnaError::LabelTooLong));
        assert_eq!(to_ascii(&format!("{}.example", "ü".repeat(60))), Err(IdnaError::LabelTooLong));
        let name = vec!["abcdefghi"; 26].join(".");
        assert_eq!(to_ascii(&name), Err(IdnaError::NameTooLong));
        assert!(to_ascii(&vec!["abcdefghi"; 25].join(".")).is_ok());
    }

    #[test]
    fn to_unicode_shows_valid_a_labels_only() {
        assert_eq!(to_unicode("xn--bcher-kva.example"), "bücher.example");
        assert_eq!(to_unicode("xn--e1afmkfd.xn--80akhbyknj4f"), "пример.испытание");
        assert_eq!(to_unicode("xn--abc-.example"), "xn--abc-.example");
        assert_eq!(to_unicode("crates.io"), "crates.io");
        for name in ["bücher.example", "例え.テスト", "faß.de"] {
            assert_eq!(to_unicode(&to_ascii(name).unwrap()), name);
        }
    }
}
