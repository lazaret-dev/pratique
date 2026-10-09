//! A BER reader, for the formats that are DER on paper and BER in the wild: CMS and PKCS#7
//! (RFC 5652, RFC 2315) written by a streaming signer (`openssl cms -stream`, `jarsigner`, some HSM
//! vendors) use indefinite lengths and constructed OCTET STRINGs, and Authenticode signatures embed
//! a DER signed-attribute block inside a BER envelope.
//!
//! [`parse`] reads one element into a tree of [`Node`]s. The tree is built once, with bounds on
//! nesting, and the signature code asks it for three things:
//!
//! * [`Node::octets`], the content of an OCTET STRING whichever way it is split into chunks;
//! * [`Node::der`] / [`Node::der_as`], the element written again with definite lengths and primitive
//!   OCTET STRINGs: what a certificate parser and the digest of signed attributes need, and
//!   byte-for-byte identical to the input when the input already was DER;
//! * [`Node::items`], a cursor over the children, with the same shape as [`crate::asn1::Der`].
//!
//! What it accepts beyond DER: indefinite lengths on constructed elements, long-form lengths that
//! are longer than they need to be, and constructed OCTET STRINGs. What it still refuses: tags above
//! 30, a constructed form of any string type other than OCTET STRING (when asked for DER), a
//! primitive element with an indefinite length, end-of-contents octets where an element must start,
//! and nesting deeper than [`MAX_DEPTH`]. Being a reader of BER it makes no promise that the input
//! is canonical; whatever a signature covers is re-encoded in the way the signer's format says, and
//! the caller says which element that is.

use std::borrow::Cow;

use crate::asn1::Tlv;
use crate::verify_error::{Error, Result};

/// How deeply constructed elements may nest. A CMS message with a certificate chain, signed
/// attributes and a nested counter-signature is about a dozen levels deep.
pub const MAX_DEPTH: usize = 48;

/// One BER element: its identifier octet and either its content octets or its children.
#[derive(Clone, Debug)]
pub struct Node<'a> {
    tag: u8,
    body: Body<'a>,
}

#[derive(Clone, Debug)]
enum Body<'a> {
    Primitive { content: &'a [u8], raw: &'a [u8] },
    Constructed(Vec<Node<'a>>),
}

/// Reads one element from the start of `data` and returns it with what follows it.
pub fn parse(data: &[u8]) -> Result<(Node<'_>, &[u8])> {
    let mut pos = 0;
    let node = read(data, &mut pos, 0)?;
    Ok((node, &data[pos..]))
}

/// Reads `data` as exactly one element.
pub fn parse_exact(data: &[u8]) -> Result<Node<'_>> {
    let (node, rest) = parse(data)?;
    if rest.is_empty() {
        Ok(node)
    } else {
        Err(Error::Asn1("trailing data"))
    }
}

fn byte(data: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *data.get(*pos).ok_or(Error::Asn1("unexpected end of data"))?;
    *pos += 1;
    Ok(b)
}

fn read<'a>(data: &'a [u8], pos: &mut usize, depth: usize) -> Result<Node<'a>> {
    let start = *pos;
    let tag = byte(data, pos)?;
    if tag & 0x1f == 0x1f {
        return Err(Error::Asn1("high tag numbers are not supported"));
    }
    if tag == 0 {
        return Err(Error::Asn1("end-of-contents octets where an element must start"));
    }
    let constructed = tag & 0x20 != 0;
    let first = byte(data, pos)?;

    if first == 0x80 {
        if !constructed {
            return Err(Error::Asn1("indefinite length on a primitive element"));
        }
        if depth >= MAX_DEPTH {
            return Err(Error::Asn1("nesting too deep"));
        }
        let mut children = Vec::new();
        loop {
            if data.get(*pos..*pos + 2) == Some(&[0, 0]) {
                *pos += 2;
                break;
            }
            children.push(read(data, pos, depth + 1)?);
        }
        return Ok(Node { tag, body: Body::Constructed(children) });
    }

    let len = if first < 0x80 {
        first as usize
    } else {
        if first == 0xff {
            return Err(Error::Asn1("reserved length octet"));
        }
        let n = (first & 0x7f) as usize;
        let bytes = data.get(*pos..*pos + n).ok_or(Error::Asn1("truncated length"))?;
        *pos += n;
        let mut len = 0usize;
        for b in bytes {
            // leading zero octets are allowed (BER), a value that does not fit is not
            if len > usize::MAX >> 8 {
                return Err(Error::Asn1("length too large"));
            }
            len = (len << 8) | *b as usize;
        }
        len
    };
    let end = pos.checked_add(len).ok_or(Error::Asn1("length overflow"))?;
    let content = data.get(*pos..end).ok_or(Error::Asn1("content exceeds buffer"))?;
    *pos = end;
    if !constructed {
        return Ok(Node { tag, body: Body::Primitive { content, raw: &data[start..end] } });
    }
    if depth >= MAX_DEPTH {
        return Err(Error::Asn1("nesting too deep"));
    }
    let mut children = Vec::new();
    let mut p = 0;
    while p < content.len() {
        children.push(read(content, &mut p, depth + 1)?);
    }
    Ok(Node { tag, body: Body::Constructed(children) })
}

impl<'a> Node<'a> {
    /// The identifier octet (class, constructed bit, tag number).
    pub fn tag(&self) -> u8 {
        self.tag
    }

    pub fn is_constructed(&self) -> bool {
        matches!(self.body, Body::Constructed(_))
    }

    /// The children of a constructed element.
    pub fn children(&self) -> Result<&[Node<'a>]> {
        match &self.body {
            Body::Constructed(c) => Ok(c),
            Body::Primitive { .. } => Err(Error::Asn1("expected a constructed element")),
        }
    }

    /// A cursor over the children of a constructed element.
    pub fn items(&self) -> Result<Items<'_, 'a>> {
        Ok(Items { nodes: self.children()?, pos: 0 })
    }

    /// The content octets of a primitive element.
    pub fn content(&self) -> Result<&'a [u8]> {
        match &self.body {
            Body::Primitive { content, .. } => Ok(content),
            Body::Constructed(_) => Err(Error::Asn1("expected a primitive element")),
        }
    }

    /// A primitive element as a [`Tlv`], for the readers in [`crate::asn1`] (integers, OIDs, times).
    pub fn tlv(&self) -> Result<Tlv<'a>> {
        match &self.body {
            Body::Primitive { content, raw } => Ok(Tlv { tag: self.tag, content, raw }),
            Body::Constructed(_) => Err(Error::Asn1("expected a primitive element")),
        }
    }

    /// `Some(self)` if the identifier octet is `tag`.
    pub fn with_tag(&self, tag: u8) -> Result<&Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(Error::Asn1("unexpected tag"))
        }
    }

    /// The octets of an OCTET STRING, or of anything with the same encoding rules (an implicitly
    /// tagged OCTET STRING): the content itself when the element is primitive, the chunks put
    /// together, in order, when it is constructed. The caller checks the element's own tag; the
    /// chunks must be OCTET STRINGs themselves, possibly constructed in turn.
    pub fn octets(&self) -> Result<Cow<'a, [u8]>> {
        match &self.body {
            Body::Primitive { content, .. } => Ok(Cow::Borrowed(content)),
            Body::Constructed(children) => {
                let mut out = Vec::new();
                collect_chunks(children, &mut out)?;
                Ok(Cow::Owned(out))
            }
        }
    }

    /// The element written with definite lengths: what DER would call it, provided the input used
    /// minimal lengths and (for a SET OF) sorted its members, neither of which is checked. A
    /// constructed universal OCTET STRING becomes a primitive one (an implicitly tagged one keeps its
    /// chunks; use [`octets`](Self::octets) for those). For input that is DER this is the input.
    pub fn der(&self) -> Result<Vec<u8>> {
        self.der_as(self.tag)
    }

    /// Like [`der`](Self::der) with another identifier octet on the outside: signed attributes are
    /// sent as `[0] IMPLICIT SET OF` (0xa0) and digested as `SET OF` (0x31).
    pub fn der_as(&self, tag: u8) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(tag, &mut out)?;
        Ok(out)
    }

    /// The content octets of [`der`](Self::der): the encoding without its identifier and length.
    /// PKCS#7 digests the content of a `ContentInfo` that is not an OCTET STRING this way.
    pub fn der_content(&self) -> Result<Vec<u8>> {
        match &self.body {
            Body::Primitive { content, .. } => Ok(content.to_vec()),
            Body::Constructed(children) => {
                if self.tag == 0x24 {
                    return Ok(self.octets()?.into_owned());
                }
                self.refuse_constructed_string()?;
                let mut out = Vec::new();
                for c in children {
                    c.encode(c.tag, &mut out)?;
                }
                Ok(out)
            }
        }
    }

    /// BER lets every string type (and the two time types) be sent in pieces; only OCTET STRING is
    /// put together here, because only that one is needed for CMS.
    fn refuse_constructed_string(&self) -> Result<()> {
        if self.tag & 0xc0 == 0 && matches!(self.tag & 0x1f, 3 | 12 | 18..=30) {
            return Err(Error::Asn1("a constructed string type other than OCTET STRING"));
        }
        Ok(())
    }

    fn encode(&self, tag: u8, out: &mut Vec<u8>) -> Result<()> {
        match &self.body {
            Body::Primitive { content, .. } => put(out, tag, content),
            Body::Constructed(children) => {
                if self.tag == 0x24 {
                    // constructed OCTET STRING: one primitive string
                    let all = self.octets()?;
                    put(out, if tag == 0x24 { 0x04 } else { tag & !0x20 }, &all);
                    return Ok(());
                }
                self.refuse_constructed_string()?;
                let mut body = Vec::new();
                for c in children {
                    c.encode(c.tag, &mut body)?;
                }
                put(out, tag, &body);
            }
        }
        Ok(())
    }
}

fn collect_chunks(children: &[Node<'_>], out: &mut Vec<u8>) -> Result<()> {
    for c in children {
        match (&c.body, c.tag) {
            (Body::Primitive { content, .. }, 0x04) => out.extend_from_slice(content),
            (Body::Constructed(grandchildren), 0x24) => collect_chunks(grandchildren, out)?,
            _ => return Err(Error::Asn1("a chunk of a constructed OCTET STRING is not an OCTET STRING")),
        }
    }
    Ok(())
}

fn put(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
}

/// A cursor over the children of a constructed element.
pub struct Items<'n, 'a> {
    nodes: &'n [Node<'a>],
    pos: usize,
}

impl<'n, 'a> Items<'n, 'a> {
    pub fn is_empty(&self) -> bool {
        self.pos >= self.nodes.len()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.nodes.get(self.pos).map(|n| n.tag)
    }

    pub fn next(&mut self) -> Result<&'n Node<'a>> {
        let n = self.nodes.get(self.pos).ok_or(Error::Asn1("unexpected end of data"))?;
        self.pos += 1;
        Ok(n)
    }

    pub fn expect(&mut self, tag: u8) -> Result<&'n Node<'a>> {
        let n = self.next()?;
        n.with_tag(tag)
    }

    /// If the next element has `tag`, consumes and returns it.
    pub fn optional(&mut self, tag: u8) -> Option<&'n Node<'a>> {
        if self.peek_tag() == Some(tag) {
            self.pos += 1;
            self.nodes.get(self.pos - 1)
        } else {
            None
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = parts.concat();
        let mut v = vec![0x30];
        v.push(body.len() as u8);
        v.extend(body);
        v
    }

    #[test]
    fn der_input_comes_back_byte_for_byte() {
        // SEQUENCE { INTEGER 5, OCTET STRING "hi", SEQUENCE {}, [0] { NULL } }
        let der = seq(&[&[0x02, 1, 5], &[0x04, 2, b'h', b'i'], &[0x30, 0], &[0xa0, 2, 0x05, 0]]);
        let n = parse_exact(&der).unwrap();
        assert_eq!(n.der().unwrap(), der);
        assert_eq!(n.der_content().unwrap(), der[2..]);
        let mut items = n.items().unwrap();
        assert_eq!(items.expect(0x02).unwrap().content().unwrap(), [5]);
        assert_eq!(&*items.expect(0x04).unwrap().octets().unwrap(), b"hi");
        assert!(items.optional(0x31).is_none());
        assert!(items.optional(0x30).is_some());
        assert!(!items.is_empty());
        items.expect(0xa0).unwrap();
        items.finish().unwrap();
        assert!(items.next().is_err());
    }

    #[test]
    fn indefinite_lengths_become_definite() {
        // SEQUENCE (indefinite) { INTEGER 1, SEQUENCE (indefinite) { NULL } }
        let ber = [0x30, 0x80, 0x02, 1, 1, 0x30, 0x80, 0x05, 0, 0, 0, 0, 0];
        let n = parse_exact(&ber).unwrap();
        assert_eq!(n.der().unwrap(), [0x30, 7, 0x02, 1, 1, 0x30, 2, 0x05, 0]);
        // the same element with a [0] tag on the outside, as signed attributes are digested
        assert_eq!(n.der_as(0xa0).unwrap(), [0xa0, 7, 0x02, 1, 1, 0x30, 2, 0x05, 0]);
        assert_eq!(n.der_content().unwrap(), [0x02, 1, 1, 0x30, 2, 0x05, 0]);
    }

    #[test]
    fn long_form_lengths_need_not_be_minimal() {
        for ber in [&[0x04u8, 0x81, 0x02, 7, 8][..], &[0x04, 0x82, 0x00, 0x02, 7, 8], &[0x04, 0x84, 0, 0, 0, 2, 7, 8]] {
            let n = parse_exact(ber).unwrap();
            assert_eq!(&*n.octets().unwrap(), [7, 8]);
            assert_eq!(n.der().unwrap(), [0x04, 2, 7, 8]);
        }
        // a length that does not fit in a usize is refused, not wrapped
        let mut big = vec![0x04, 0x89];
        big.extend([0xff; 9]);
        assert!(parse(&big).is_err());
        big[2] = 0x01;
        big[3] = 0;
        assert!(parse(&big).is_err());
        // and a length that is longer than the data
        assert!(parse(&[0x04, 0x05, 1, 2]).is_err());
        assert!(parse(&[0x04, 0x82, 0x01]).is_err());
        assert!(parse(&[0x04, 0xff, 1]).is_err());
    }

    #[test]
    fn constructed_octet_strings_are_put_together() {
        // indefinite, chunks of 2, 0 and 3 bytes, and a nested constructed chunk
        let ber = [0x24, 0x80, 0x04, 2, 1, 2, 0x04, 0, 0x24, 0x80, 0x04, 1, 3, 0x04, 2, 4, 5, 0, 0, 0, 0];
        let n = parse_exact(&ber).unwrap();
        assert_eq!(n.tag(), 0x24);
        assert!(n.is_constructed());
        assert_eq!(&*n.octets().unwrap(), [1, 2, 3, 4, 5]);
        assert_eq!(n.der().unwrap(), [0x04, 5, 1, 2, 3, 4, 5]);
        assert_eq!(n.der_content().unwrap(), [1, 2, 3, 4, 5]);
        // definite length with the same chunks
        let ber = [0x24, 0x07, 0x04, 2, 1, 2, 0x04, 1, 3];
        assert_eq!(&*parse_exact(&ber).unwrap().octets().unwrap(), [1, 2, 3]);
        // an implicitly tagged one: [0] constructed, chunks are still universal OCTET STRINGs
        let ber = [0xa0, 0x80, 0x04, 1, 9, 0x04, 1, 8, 0, 0];
        let n = parse_exact(&ber).unwrap();
        assert_eq!(&*n.octets().unwrap(), [9, 8]);
        assert_eq!(n.der().unwrap(), [0xa0, 6, 0x04, 1, 9, 0x04, 1, 8]);
        // a chunk that is not an OCTET STRING
        assert!(parse_exact(&[0x24, 0x03, 0x02, 1, 7]).unwrap().octets().is_err());
        assert!(parse_exact(&[0x24, 0x02, 0xa0, 0x00]).unwrap().octets().is_err());
    }

    #[test]
    fn other_constructed_strings_are_not_re_encoded() {
        // constructed UTF8String and BIT STRING
        for tag in [0x2c, 0x23, 0x37, 0x3e] {
            let ber = [tag, 0x80, 0x0c, 1, b'a', 0, 0];
            let n = parse_exact(&ber).unwrap();
            assert!(n.der().is_err(), "{tag:#x}");
            assert!(n.der_content().is_err(), "{tag:#x}");
        }
        // but the structure types are fine, whatever the class
        assert!(parse_exact(&[0x31, 0x80, 0, 0]).unwrap().der().is_ok());
        assert!(parse_exact(&[0xbe, 0x80, 0, 0]).unwrap().der().is_ok());
    }

    #[test]
    fn malformed_input_is_refused() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x80],                      // indefinite and no end
            &[0x30, 0x80, 0x00],                // half an end-of-contents
            &[0x30, 0x80, 0x02, 1, 1],          // no end after a child
            &[0x04, 0x80, 0x01, 0, 0],          // indefinite primitive
            &[0x00, 0x00],                      // end-of-contents where an element starts
            &[0x1f, 0x01, 0x00],                // high tag number
            &[0x30, 0x03, 0x02, 1],             // child longer than its parent
            &[0x30, 0x04, 0x02, 1, 1, 0x05],    // a child that stops short
            &[0x30, 0x03, 0x00, 0x00, 0x00],    // end-of-contents octets inside a definite element
            &[0x30, 0x80, 0x30, 0x03, 0, 0, 0], // an end-of-contents that belongs to nobody
        ] {
            assert!(parse_exact(bad).is_err(), "{bad:02x?}");
        }
        assert!(parse_exact(&[0x05, 0, 0]).is_err()); // trailing data
        let (n, rest) = parse(&[0x05, 0, 0xde, 0xad]).unwrap();
        assert_eq!(n.tag(), 0x05);
        assert_eq!(rest, [0xde, 0xad]);
        // wrong kind of access
        assert!(parse_exact(&[0x05, 0]).unwrap().children().is_err());
        assert!(parse_exact(&[0x30, 0]).unwrap().content().is_err());
        assert!(parse_exact(&[0x30, 0]).unwrap().tlv().is_err());
        assert!(parse_exact(&[0x05, 0]).unwrap().with_tag(0x06).is_err());
        let t = parse_exact(&[0x02, 1, 7]).unwrap().tlv().unwrap();
        assert_eq!((t.tag, t.content, t.raw), (0x02, &[7u8][..], &[0x02u8, 1, 7][..]));
    }

    #[test]
    fn nesting_is_bounded() {
        // MAX_DEPTH levels of indefinite sequences are fine, one more is not, and neither can overflow the stack
        let nested = |levels: usize| {
            let mut v = Vec::new();
            for _ in 0..levels {
                v.extend([0x30, 0x80]);
            }
            v.extend([0x05, 0]);
            v.extend(std::iter::repeat(0).take(2 * levels));
            v
        };
        assert!(parse_exact(&nested(MAX_DEPTH)).is_ok());
        assert!(parse_exact(&nested(MAX_DEPTH + 1)).is_err());
        assert!(parse_exact(&nested(100_000)).is_err());
        // the same with definite lengths, which have to be built from the inside
        let mut v = vec![0x05, 0];
        for _ in 0..MAX_DEPTH + 1 {
            let mut w = vec![0x30];
            if v.len() < 0x80 {
                w.push(v.len() as u8);
            } else {
                w.extend([0x82, (v.len() >> 8) as u8, v.len() as u8]);
            }
            w.extend(v);
            v = w;
        }
        assert!(parse_exact(&v).is_err());
        // a long run of siblings is no problem
        let mut v = vec![0x30, 0x80];
        for _ in 0..50_000 {
            v.extend([0x05, 0]);
        }
        v.extend([0, 0]);
        let n = parse_exact(&v).unwrap();
        assert_eq!(n.children().unwrap().len(), 50_000);
        assert_eq!(n.der().unwrap().len(), 100_000 + 5);
    }

    #[test]
    fn long_contents_are_re_encoded_with_long_lengths() {
        let content = vec![0xaa; 70_000];
        let mut ber = vec![0x24, 0x80, 0x04, 0x83, 0x01, 0x11, 0x70];
        ber.extend(&content);
        ber.extend([0, 0]);
        let n = parse_exact(&ber).unwrap();
        let der = n.der().unwrap();
        assert_eq!(&der[..5], [0x04, 0x83, 0x01, 0x11, 0x70]);
        assert_eq!(der.len(), 5 + 70_000);
        let again = parse_exact(&der).unwrap();
        assert_eq!(again.der().unwrap(), der);
    }
}
