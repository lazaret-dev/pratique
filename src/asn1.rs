//! A minimal strict DER reader: just enough ASN.1 for X.509 and ECDSA signatures.

use crate::verify_error::{Error, Result};

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_IA5_STRING: u8 = 0x16;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

/// One decoded tag-length-value element.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
    /// The full encoding (tag + length + content); needed to hash signed structures.
    pub raw: &'a [u8],
}

pub struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Der { data, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn next(&mut self) -> Result<Tlv<'a>> {
        let start = self.pos;
        let tag = *self.data.get(self.pos).ok_or(Error::Asn1("unexpected end of data"))?;
        if tag & 0x1f == 0x1f {
            return Err(Error::Asn1("high tag numbers are not supported"));
        }
        self.pos += 1;
        let first = *self.data.get(self.pos).ok_or(Error::Asn1("missing length"))?;
        self.pos += 1;
        let len = if first < 0x80 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 {
                return Err(Error::Asn1("indefinite lengths are not allowed in DER"));
            }
            if n > 4 {
                return Err(Error::Asn1("length too large"));
            }
            let bytes = self.data.get(self.pos..self.pos + n).ok_or(Error::Asn1("truncated length"))?;
            self.pos += n;
            if bytes[0] == 0 {
                return Err(Error::Asn1("non-minimal length encoding"));
            }
            let mut len = 0usize;
            for b in bytes {
                len = (len << 8) | *b as usize;
            }
            if len < 0x80 {
                return Err(Error::Asn1("non-minimal length encoding"));
            }
            len
        };
        let end = self.pos.checked_add(len).ok_or(Error::Asn1("length overflow"))?;
        let content = self.data.get(self.pos..end).ok_or(Error::Asn1("content exceeds buffer"))?;
        self.pos = end;
        Ok(Tlv { tag, content, raw: &self.data[start..end] })
    }

    /// Reads the next element and requires a specific tag.
    pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>> {
        let t = self.next()?;
        if t.tag != tag {
            return Err(Error::Asn1("unexpected tag"));
        }
        Ok(t)
    }

    pub fn sequence(&mut self) -> Result<Der<'a>> {
        Ok(Der::new(self.expect(TAG_SEQUENCE)?.content))
    }

    /// If the next element has `tag`, consumes and returns it.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            Ok(Some(self.next()?))
        } else {
            Ok(None)
        }
    }

    pub fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Asn1("trailing data"))
        }
    }
}

/// The value of a BOOLEAN's content octets. DER writes FALSE as `00` and TRUE as `ff`, and nothing else is a
/// BOOLEAN here. (BER lets a reader take any non-zero octet for TRUE, and OpenSSL does; Go refuses the
/// certificate. A reader that took `01` for "not true" would let a critical extension through that both of
/// them stop at.)
pub fn boolean_content(content: &[u8]) -> Result<bool> {
    match content {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Error::Asn1("BOOLEAN is not 00 or ff")),
    }
}

/// The value of a BOOLEAN element, see [`boolean_content`].
pub fn boolean(t: &Tlv) -> Result<bool> {
    if t.tag != TAG_BOOLEAN {
        return Err(Error::Asn1("expected BOOLEAN"));
    }
    boolean_content(t.content)
}

/// Returns the magnitude bytes of a non-negative INTEGER, with the sign-padding zero removed.
pub fn unsigned_integer(t: &Tlv) -> Result<Vec<u8>> {
    if t.tag != TAG_INTEGER {
        return Err(Error::Asn1("expected INTEGER"));
    }
    let c = t.content;
    if c.is_empty() {
        return Err(Error::Asn1("empty INTEGER"));
    }
    if c[0] & 0x80 != 0 {
        return Err(Error::Asn1("negative INTEGER where unsigned expected"));
    }
    if c.len() > 1 && c[0] == 0 && c[1] & 0x80 == 0 {
        return Err(Error::Asn1("non-minimal INTEGER"));
    }
    let start = if c.len() > 1 && c[0] == 0 { 1 } else { 0 };
    Ok(c[start..].to_vec())
}

/// Returns the payload of a BIT STRING that has zero unused bits.
pub fn bit_string_bytes<'a>(t: &Tlv<'a>) -> Result<&'a [u8]> {
    if t.tag != TAG_BIT_STRING || t.content.is_empty() {
        return Err(Error::Asn1("expected BIT STRING"));
    }
    if t.content[0] != 0 {
        return Err(Error::Asn1("BIT STRING with unused bits"));
    }
    Ok(&t.content[1..])
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Reads exactly the ASCII digits in `b` as a number. Unlike `str::parse` this refuses signs,
/// whitespace and anything non-ASCII, and it works on bytes, so it cannot split a character.
fn digits(b: &[u8]) -> Result<i64> {
    if b.is_empty() || !b.iter().all(|c| c.is_ascii_digit()) {
        return Err(Error::Asn1("bad time digit"));
    }
    Ok(b.iter().fold(0i64, |a, c| a * 10 + (c - b'0') as i64))
}

/// Parses UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) into a Unix timestamp. As in RFC 5280, the
/// zone is Z and the seconds are there; a second 60 (a leap second) is refused, as Go and OpenSSL refuse it.
pub fn parse_time(t: &Tlv) -> Result<i64> {
    let b = t.content;
    let (year, rest) = match t.tag {
        TAG_UTC_TIME => {
            if b.len() != 13 {
                return Err(Error::Asn1("bad UTCTime length"));
            }
            let yy = digits(&b[0..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &b[2..])
        }
        TAG_GENERALIZED_TIME => {
            if b.len() != 15 {
                return Err(Error::Asn1("bad GeneralizedTime length"));
            }
            (digits(&b[0..4])?, &b[4..])
        }
        _ => return Err(Error::Asn1("expected time")),
    };
    // `rest` is now MMDDHHMMSSZ: ten digits and the zone letter.
    if rest[10] != b'Z' {
        return Err(Error::Asn1("time must be UTC (Z)"));
    }
    let num = |a: usize| digits(&rest[a..a + 2]);
    let (mo, d, h, mi, sec) = (num(0)?, num(2)?, num(4)?, num(6)?, num(8)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return Err(Error::Asn1("time field out of range"));
    }
    // a real calendar day (found by the fuzzer: 30 February used to parse, as 2 March)
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match mo {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if d > days_in_month {
        return Err(Error::Asn1("day does not exist in that month"));
    }
    Ok(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + sec)
}

/// The dotted form (`1.3.6.1.4.1.57264.1.8`) of an OBJECT IDENTIFIER's content octets. An encoding
/// that is not a valid OID (empty, or ending in the middle of an arc) comes back as `<invalid OID>`.
pub fn oid_to_string(content: &[u8]) -> String {
    let mut arcs: Vec<u128> = Vec::new();
    let mut acc: u128 = 0;
    let mut pending = false;
    for &b in content {
        if acc > (u128::MAX >> 7) {
            return "<invalid OID>".to_string();
        }
        acc = (acc << 7) | (b & 0x7f) as u128;
        pending = b & 0x80 != 0;
        if !pending {
            if arcs.is_empty() {
                // the first subidentifier carries the first two arcs
                let (first, second) = if acc < 80 { (acc / 40, acc % 40) } else { (2, acc - 80) };
                arcs.push(first);
                arcs.push(second);
            } else {
                arcs.push(acc);
            }
            acc = 0;
        }
    }
    if pending || arcs.is_empty() {
        return "<invalid OID>".to_string();
    }
    arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
}

/// The content octets of the OBJECT IDENTIFIER written in dotted form, or `None` if `s` is not one
/// (fewer than two arcs, a non-numeric arc, a first arc above 2, a second arc of 40 or more under
/// arcs 0 and 1, or an arc too large for this code).
pub fn oid_from_string(s: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u64> = s.split('.').map(|a| a.parse::<u64>().ok()).collect::<Option<Vec<_>>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) || arcs[1] > u64::MAX - 80 {
        return None;
    }
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = [0u8; 10];
        let mut n = 0;
        loop {
            tmp[n] = (v & 0x7f) as u8;
            n += 1;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            out.push(tmp[i] | if i > 0 { 0x80 } else { 0 });
        }
    };
    push(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        push(a);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_convert_both_ways() {
        let cases: [(&str, &[u8]); 5] = [
            ("1.3.6.1.5.5.7.3.3", &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03]),
            ("1.3.6.1.4.1.57264.1.8", &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01, 0x08]),
            ("2.5.29.37", &[0x55, 0x1d, 0x25]),
            ("2.999.1", &[0x88, 0x37, 0x01]),
            ("1.2.840.113549.1.1.11", &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
        ];
        for (text, der) in cases {
            assert_eq!(oid_to_string(der), text);
            assert_eq!(oid_from_string(text).as_deref(), Some(der), "{}", text);
        }
        for bad in ["", "1", "3.1", "1.40", "1..2", "1.x", "1.2.", "-1.2", "1.18446744073709551615"] {
            assert_eq!(oid_from_string(bad), None, "{:?}", bad);
        }
        for bad in [&[][..], &[0x2b, 0x86], &[0x80]] {
            assert_eq!(oid_to_string(bad), "<invalid OID>");
        }
        // an arc wider than 64 bits is still printed, not truncated
        assert_eq!(oid_to_string(&[0x2b, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]), "1.3.18446744073709551616");
    }

    #[test]
    fn a_boolean_is_00_or_ff_and_nothing_else() {
        assert!(!boolean_content(&[0x00]).unwrap());
        assert!(boolean_content(&[0xff]).unwrap());
        for bad in [&[][..], &[0x01], &[0x7f], &[0x80], &[0xfe], &[0xff, 0xff], &[0x00, 0x00]] {
            assert!(boolean_content(bad).is_err(), "{bad:?}");
        }
        let data = [0x01, 0x01, 0xff, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00];
        let mut d = Der::new(&data);
        assert!(boolean(&d.next().unwrap()).unwrap());
        assert!(boolean(&d.next().unwrap()).is_err());
        assert!(boolean(&d.next().unwrap()).is_err()); // an INTEGER is not a BOOLEAN
    }

    #[test]
    fn parses_nested_sequence() {
        // SEQUENCE { INTEGER 5, OCTET STRING "hi" }
        let data = [0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, b'h', b'i'];
        let mut d = Der::new(&data);
        let mut seq = d.sequence().unwrap();
        d.finish().unwrap();
        assert_eq!(unsigned_integer(&seq.expect(TAG_INTEGER).unwrap()).unwrap(), vec![5]);
        assert_eq!(seq.expect(TAG_OCTET_STRING).unwrap().content, b"hi");
        seq.finish().unwrap();
    }

    #[test]
    fn long_form_lengths() {
        let mut data = vec![0x04, 0x81, 0x80];
        data.extend(std::iter::repeat(7u8).take(128));
        assert_eq!(Der::new(&data).next().unwrap().content.len(), 128);
        // non-minimal: long form for a short length
        assert!(Der::new(&[0x04, 0x81, 0x01, 0x00]).next().is_err());
        // truncated
        assert!(Der::new(&[0x04, 0x05, 0x00]).next().is_err());
    }

    #[test]
    fn time_parsing() {
        let t = Tlv { tag: TAG_UTC_TIME, content: b"700101000000Z", raw: &[] };
        assert_eq!(parse_time(&t).unwrap(), 0);
        let t = Tlv { tag: TAG_GENERALIZED_TIME, content: b"20000301120000Z", raw: &[] };
        assert_eq!(parse_time(&t).unwrap(), 951912000);
        let t = Tlv { tag: TAG_UTC_TIME, content: b"260101000000Z", raw: &[] };
        assert_eq!(parse_time(&t).unwrap(), 1767225600);
    }

    #[test]
    fn days_that_do_not_exist_are_refused() {
        let utc = |s: &'static [u8]| parse_time(&Tlv { tag: TAG_UTC_TIME, content: s, raw: &[] });
        let gen = |s: &'static [u8]| parse_time(&Tlv { tag: TAG_GENERALIZED_TIME, content: s, raw: &[] });
        for bad in [&b"260231000000Z"[..], b"260230120000Z", b"250229000000Z", b"260431000000Z", b"260631000000Z", b"260931000000Z", b"261131000000Z", b"260100000000Z", b"260132000000Z"] {
            assert!(utc(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        for bad in [&b"21000229000000Z"[..], b"19000229000000Z", b"20260431000000Z"] {
            assert!(gen(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        // leap days, and the ends of the other months, are fine
        for good in [&b"240229000000Z"[..], b"280229235959Z", b"260131000000Z", b"260228000000Z", b"260430000000Z", b"261231235959Z"] {
            utc(good).unwrap();
        }
        for good in [&b"20000229000000Z"[..], b"20240229000000Z", b"20261130000000Z"] {
            gen(good).unwrap();
        }
        assert_eq!(utc(b"240229000000Z").unwrap() + 86400, utc(b"240301000000Z").unwrap());
    }

    #[test]
    fn a_minute_has_no_second_sixty() {
        // Go (time.Parse) and OpenSSL (ASN1_TIME_check) both refuse :60, and the ASN.1 of RFC 5280 certificates
        // has no leap seconds; read as the next minute it would move a validity bound by a second
        let utc = |s: &'static [u8]| parse_time(&Tlv { tag: TAG_UTC_TIME, content: s, raw: &[] });
        let gen = |s: &'static [u8]| parse_time(&Tlv { tag: TAG_GENERALIZED_TIME, content: s, raw: &[] });
        for bad in [&b"260101000060Z"[..], b"261231235960Z", b"260101000061Z", b"260101000099Z"] {
            assert!(utc(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        for bad in [&b"20260101000060Z"[..], b"20261231235960Z"] {
            assert!(gen(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        // :59 is the last second, and the one after it is the first of the next minute
        assert_eq!(utc(b"260101000059Z").unwrap() + 1, utc(b"260101000100Z").unwrap());
        assert_eq!(gen(b"20261231235959Z").unwrap() + 1, gen(b"20270101000000Z").unwrap());
        // the year in which UTCTime turns over: 49 is 2049 and 50 is 1950
        assert_eq!(utc(b"491231235959Z").unwrap(), gen(b"20491231235959Z").unwrap());
        assert_eq!(utc(b"500101000000Z").unwrap(), gen(b"19500101000000Z").unwrap());
        assert_eq!(utc(b"500101000000Z").unwrap(), -631_152_000);
    }

    #[test]
    fn malformed_times_are_errors_not_panics() {
        for bad in [
            &b"260101000\xc3\xa90Z"[..], // multi-byte character straddling a field boundary (panicked before)
            b"\xc3\xa9\xc3\xa9010100000Z",
            b"+60101000000Z",             // a sign is not a digit
            b" 60101000000Z",
            b"260101000000X",
            b"261301000000Z",             // month 13
            b"260101240000Z",             // hour 24
            b"260101000000",              // too short
        ] {
            let t = Tlv { tag: TAG_UTC_TIME, content: bad, raw: &[] };
            assert!(parse_time(&t).is_err(), "{:?}", bad);
        }
        let t = Tlv { tag: TAG_GENERALIZED_TIME, content: "2026010100000\u{e9}Z".as_bytes(), raw: &[] };
        assert!(parse_time(&t).is_err());
    }
}
