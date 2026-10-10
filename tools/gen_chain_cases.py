#!/usr/bin/env python3
"""Writes tests/data/chain_cases/: certificate chains that each differ from a good one in one thing, for comparing this
library's chain validation with OpenSSL's, Go's and Apple's (tools/chain_judges.sh; BACKLOG B-92, part 3).

The layout is that of the captured real chains (tests/data/real_chains), so that the same judges read both:

    fixtures.tsv        name, host, time (Unix seconds), expect, anchor file, and what the one change is
    chains/NAME.pem     the leaf first, then what a server would send after it (in the order a server might)
    anchors/NAME.pem    the trust anchors (one or more)

expect is what the standards say a TLS client should conclude:
    ok       RFC 5280 path validation and the CA/Browser Forum's rules for TLS servers both accept it
    refuse   one of them refuses it
    either   left to the verifier, or verifiers differ on purpose (old CN matching, a trust anchor's own validity and
             constraints, policies on key sizes and algorithms); listed so that what each one does is on record

Run from the repository root: python3 tools/gen_chain_cases.py   (needs Python `cryptography`). Keys are random and are not
written; the files hold public certificates only. Every case is judged at TIME below.
"""
import datetime
import os
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = "tests/data/chain_cases"
UTC = datetime.timezone.utc
TIME = datetime.datetime(2026, 6, 1, tzinfo=UTC)
NB = datetime.datetime(2026, 1, 1, tzinfo=UTC)
NA = datetime.datetime(2026, 12, 31, tzinfo=UTC)
HOST = "host.test"
DAY = datetime.timedelta(days=1)
SECOND = datetime.timedelta(seconds=1)
SERVER = [ExtendedKeyUsageOID.SERVER_AUTH]
CASES = []


# ----------------------------------------------------------------------------- keys and names
def key(kind="ec"):
    if kind == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "p384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "rsa1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(kind)


def name(cn, enc=None):
    attr = x509.NameAttribute(NameOID.COMMON_NAME, cn, _type=enc) if enc else x509.NameAttribute(NameOID.COMMON_NAME, cn)
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pratique chain cases"), attr])


def hash_for(signer, h):
    if isinstance(signer, ed25519.Ed25519PrivateKey):
        return None
    return h or (hashes.SHA384() if isinstance(signer, ec.EllipticCurvePrivateKey) and signer.curve.name == "secp384r1" else hashes.SHA256())


KU_CA = dict(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False,
             key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False)
KU_LEAF = dict(KU_CA, key_cert_sign=False, crl_sign=False, digital_signature=True)


def cert(subject, issuer, pub, signer, *, ca, nb=NB, na=NA, pathlen=None, bc=True, bc_critical=True, ku="auto", ku_critical=True,
         eku="auto", san="auto", san_critical=False, aki=None, ski=True, extra=(), h=None, serial=None, issuer_name=None):
    """A certificate for `subject` (a Name) with key `pub`, issued by `issuer` (a Name) and signed by `signer`."""
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name or issuer).public_key(pub)
         .serial_number(serial or x509.random_serial_number()).not_valid_before(nb).not_valid_after(na))
    if bc:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=bc_critical)
    if ku == "auto":
        ku = KU_CA if ca else KU_LEAF
    if ku:
        b = b.add_extension(x509.KeyUsage(**ku), critical=ku_critical)
    if eku == "auto":
        eku = None if ca else SERVER
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san == "auto":
        san = None if ca else [x509.DNSName(HOST)]
    if san:
        b = b.add_extension(x509.SubjectAlternativeName(san), critical=san_critical)
    if ski:
        b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
    if aki:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(aki), critical=False)
    for ext, critical in extra:
        b = b.add_extension(ext, critical=critical)
    return b.sign(signer, hash_for(signer, h))


class CA:
    """A key and a name that can issue."""

    def __init__(self, cn, kind="ec", enc=None):
        self.key = key(kind)
        self.name = name(cn, enc)
        self.pub = self.key.public_key()


def root(cn="Case Root", kind="ec", **kw):
    ca = CA(cn, kind)
    ca.cert = cert(ca.name, ca.name, ca.pub, ca.key, ca=True, **kw)
    return ca


def inter(parent, cn="Case Intermediate", kind="ec", **kw):
    ca = CA(cn, kind)
    ca.cert = cert(ca.name, parent.name, ca.pub, parent.key, ca=True, aki=parent.pub, **kw)
    return ca


def leaf(parent, cn=HOST, kind="ec", **kw):
    k = key(kind)
    kw.setdefault("aki", parent.pub)
    return cert(name(cn), parent.name, k.public_key(), parent.key, ca=False, **kw)


def add(label, expect, what, chain, anchors, host=HOST, when=TIME):
    """A case: `chain` (certificates or DER, leaf first), `anchors` (certificates or DER)."""
    CASES.append((label, host, int(when.timestamp()), expect, what, [der(c) for c in chain], [der(a) for a in anchors]))


def der(c):
    return c if isinstance(c, bytes) else c.public_bytes(serialization.Encoding.DER)


# ----------------------------------------------------------------------------- DER, for what `cryptography` will not write
def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def items(b):
    """The elements of a DER string of elements: (tag, whole element, content)."""
    out, i = [], 0
    while i < len(b):
        tag, n, j = b[i], b[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[j:j + k], "big")
            j += k
        out.append((tag, b[i:j + n], b[j:j + n]))
        i = j + n
    return out


def sign_tbs(tbs, signer, h=None, outer_alg=None):
    """A certificate of `tbs` signed by `signer` (the signature algorithm written outside is `outer_alg`, if given, else the
    one inside the TBS)."""
    h = hash_for(signer, h)
    if isinstance(signer, ec.EllipticCurvePrivateKey):
        sig = signer.sign(tbs, ec.ECDSA(h))
    elif isinstance(signer, rsa.RSAPrivateKey):
        sig = signer.sign(tbs, padding.PKCS1v15(), h)
    else:
        sig = signer.sign(tbs)
    alg = outer_alg or items(items(tbs)[0][2])[2][1]
    return tlv(0x30, tbs + alg + tlv(0x03, b"\x00" + sig))


def tbs_of(c):
    return c.tbs_certificate_bytes


def edit_tbs(c, signer, change, h=None, outer_alg=None):
    """`c` with its TBS fields changed by `change` (a function of the list of the TBS's elements, each a whole DER element),
    signed again."""
    fields = [e[1] for e in items(items(tbs_of(c))[0][2])]
    fields = change(fields)
    return sign_tbs(tlv(0x30, b"".join(fields)), signer, h, outer_alg)


def edit_extensions(fields, change):
    """`fields` with the extensions (the [3] element) changed by `change` (a function of the list of whole extensions)."""
    out = []
    for f in fields:
        if f[0] == 0xA3:
            exts = [e[1] for e in items(items(items(f)[0][2])[0][2])]
            f = tlv(0xA3, tlv(0x30, b"".join(change(exts))))
        out.append(f)
    return out


def flip_last_byte(c):
    d = bytearray(der(c))
    d[-1] ^= 0x01
    return bytes(d)


OID_SAN = bytes.fromhex("0603551d11")
OID_BC = bytes.fromhex("0603551d13")
ALG_ECDSA_SHA256 = bytes.fromhex("300a06082a8648ce3d040302")
ALG_ECDSA_SHA384 = bytes.fromhex("300a06082a8648ce3d040303")
ALG_RSA_SHA1 = bytes.fromhex("300d06092a864886f70d0101050500")


# ----------------------------------------------------------------------------- the cases
def base():
    for kind in ("ec", "rsa", "p384", "ed25519"):
        r = root(kind=kind)
        i = inter(r, kind=kind)
        add(f"ok_{kind}", "either" if kind == "ed25519" else "ok", f"a good chain, every key {kind}" + (" (Ed25519 is not in the CA/B Forum's rules)" if kind == "ed25519" else ""),
            [leaf(i, kind=kind), i.cert], [r.cert])
    r = root()
    add("ok_no_intermediate", "ok", "the leaf issued by the anchor itself", [leaf(r)], [r.cert])
    i1 = inter(r, "Case Intermediate 1")
    i2 = inter(i1, "Case Intermediate 2")
    add("ok_two_intermediates", "ok", "two intermediates", [leaf(i2), i2.cert, i1.cert], [r.cert])
    add("ok_intermediates_reversed", "ok", "two intermediates, sent in the wrong order", [leaf(i2), i1.cert, i2.cert], [r.cert])
    other = root("Unrelated Root")
    add("ok_extra_unrelated_cert", "ok", "an unrelated certificate sent among the intermediates", [leaf(i2), i2.cert, other.cert, i1.cert], [r.cert])
    add("ok_root_sent_too", "ok", "the anchor sent at the end of the chain as well", [leaf(i2), i2.cert, i1.cert, r.cert], [r.cert])
    add("refuse_missing_intermediate", "refuse", "an intermediate left out", [leaf(i2), i2.cert], [r.cert])
    add("refuse_wrong_anchor", "refuse", "a good chain, judged against another root", [leaf(i2), i2.cert, i1.cert], [other.cert])


def times():
    r = root()
    i = inter(r)
    add("refuse_leaf_expired", "refuse", "the leaf expired a day before", [leaf(i, na=TIME - DAY), i.cert], [r.cert])
    add("refuse_leaf_not_yet_valid", "refuse", "the leaf is valid from a day after", [leaf(i, nb=TIME + DAY), i.cert], [r.cert])
    add("ok_leaf_not_after_is_now", "ok", "the leaf's notAfter is the moment of the check (inclusive, RFC 5280 4.1.2.5)", [leaf(i, na=TIME), i.cert], [r.cert])
    add("ok_leaf_not_before_is_now", "ok", "the leaf's notBefore is the moment of the check (inclusive)", [leaf(i, nb=TIME), i.cert], [r.cert])
    add("refuse_leaf_expired_a_second_ago", "refuse", "the leaf's notAfter a second before the check", [leaf(i, na=TIME - SECOND), i.cert], [r.cert])
    ie = inter(r, na=TIME - DAY)
    add("refuse_intermediate_expired", "refuse", "the intermediate expired", [leaf(ie), ie.cert], [r.cert])
    old = root(na=TIME - DAY)
    io = inter(old)
    add("either_anchor_expired", "either", "the trust anchor's own certificate expired (RFC 5280 does not check an anchor; most verifiers do)", [leaf(io), io.cert], [old.cert])
    # a GeneralizedTime before 2050, where DER (RFC 5280 4.1.2.5) says UTCTime
    c = leaf(i)

    def gen_time(fields):
        nb, na = items(items(fields[4])[0][2])
        assert na[0] == 0x17 and len(na[2]) == 13, na
        return fields[:4] + [tlv(0x30, nb[1] + tlv(0x18, b"20" + na[2]))] + fields[5:]

    add("either_generalized_time_before_2050", "either", "the leaf's notAfter written as GeneralizedTime before 2050 (DER says UTCTime)", [edit_tbs(c, i.key, gen_time), i.cert], [r.cert])


def hostnames():
    r = root()
    i = inter(r)
    def L(san=None, cn=HOST, **kw):
        return [leaf(i, cn=cn, san=san if san is not None else [x509.DNSName(HOST)], **kw), i.cert]
    add("refuse_host_mismatch", "refuse", "the leaf names other.test", L([x509.DNSName("other.test")]), [r.cert])
    add("ok_wildcard", "ok", "*.example.test for a.example.test", L([x509.DNSName("*.example.test")]), [r.cert], host="a.example.test")
    add("refuse_wildcard_apex", "refuse", "*.example.test for example.test", L([x509.DNSName("*.example.test")]), [r.cert], host="example.test")
    add("refuse_wildcard_two_labels", "refuse", "*.example.test for a.b.example.test", L([x509.DNSName("*.example.test")]), [r.cert], host="a.b.example.test")
    add("either_wildcard_partial_label", "either", "f*.example.test for foo.example.test (RFC 6125 allows, the CA/B Forum does not)", L([x509.DNSName("f*.example.test")]), [r.cert], host="foo.example.test")
    add("refuse_wildcard_not_leftmost", "refuse", "a.*.example.test for a.b.example.test", L([x509.DNSName("a.*.example.test")]), [r.cert], host="a.b.example.test")
    add("either_wildcard_public_suffix", "either", "*.test for x.test (a wildcard of a whole top-level domain)", L([x509.DNSName("*.test")]), [r.cert], host="x.test")
    add("either_common_name_only", "either", "no subjectAltName, the host in the common name only (the CA/B Forum and browsers refuse)", [leaf(i, san=None), i.cert], [r.cert])
    add("refuse_cn_matches_san_does_not", "refuse", "the common name is the host, the subjectAltName another name", L([x509.DNSName("other.test")]), [r.cert])
    add("ok_san_upper_case", "ok", "HOST.TEST in the subjectAltName for host.test", L([x509.DNSName("HOST.TEST")]), [r.cert])
    add("either_host_trailing_dot", "either", "the host asked for is host.test. (with the root's dot)", L(), [r.cert], host="host.test.")
    add("ok_ip_san", "ok", "an iPAddress entry for the address asked for", L([x509.IPAddress(__import__("ipaddress").ip_address("192.0.2.10"))]), [r.cert], host="192.0.2.10")
    add("refuse_ip_in_dns_san", "refuse", "the address written as a dNSName, asked for as an address", L([x509.DNSName("192.0.2.10")]), [r.cert], host="192.0.2.10")
    add("ok_idn_a_label", "ok", "an internationalized name in its xn-- form", L([x509.DNSName("xn--bcher-kva.test")]), [r.cert], host="xn--bcher-kva.test")
    add("ok_empty_subject_critical_san", "ok", "an empty subject and a critical subjectAltName (RFC 5280 4.2.1.6)",
        [cert(x509.Name([]), i.name, key().public_key(), i.key, ca=False, aki=i.pub, san=[x509.DNSName(HOST)], san_critical=True), i.cert], [r.cert])


def constraints():
    r = root()
    def I(**kw):
        return inter(r, **kw)
    i = I(bc=False)
    add("refuse_intermediate_without_basic_constraints", "refuse", "the intermediate has no basicConstraints", [leaf(i), i.cert], [r.cert])
    i = I(ku=KU_CA)
    i.cert = cert(i.name, r.name, i.pub, r.key, ca=False, aki=r.pub, ku=KU_CA, eku=None, san=None)
    add("refuse_intermediate_ca_false", "refuse", "the intermediate says cA FALSE", [leaf(i), i.cert], [r.cert])
    i = I(bc_critical=False)
    add("either_intermediate_basic_constraints_not_critical", "either", "the intermediate's basicConstraints is not critical (CAs MUST mark it; RFC 5280's validation does not check)", [leaf(i), i.cert], [r.cert])
    i1 = I(pathlen=0)
    i2 = inter(i1, "Case Intermediate 2")
    add("refuse_path_length_exceeded", "refuse", "pathLenConstraint 0 with another intermediate below it", [leaf(i2), i2.cert, i1.cert], [r.cert])
    add("ok_path_length_zero", "ok", "pathLenConstraint 0 and the leaf straight below", [leaf(i1), i1.cert], [r.cert])
    r0 = root(pathlen=0)
    i0 = inter(r0)
    add("either_anchor_path_length_zero", "either", "the anchor says pathLenConstraint 0 and has an intermediate below it (an anchor's constraints are the verifier's choice)", [leaf(i0), i0.cert], [r0.cert])
    i = I()
    add("either_leaf_is_ca", "either", "the leaf says cA TRUE (RFC 5280 allows; the CA/B Forum does not)",
        [cert(name(HOST), i.name, key().public_key(), i.key, ca=True, aki=i.pub, ku=dict(KU_LEAF, key_cert_sign=True), eku=SERVER, san=[x509.DNSName(HOST)]), i.cert], [r.cert])
    i = I(ku=dict(KU_CA, key_cert_sign=False, digital_signature=True))
    add("refuse_intermediate_without_key_cert_sign", "refuse", "the intermediate's keyUsage lacks keyCertSign", [leaf(i), i.cert], [r.cert])
    i = I(ku=None)
    add("either_intermediate_without_key_usage", "either", "the intermediate has no keyUsage (RFC 5280 allows it; the CA/B Forum wants one)", [leaf(i), i.cert], [r.cert])
    i = I()
    add("either_leaf_key_usage_cert_sign_only", "either", "the leaf's keyUsage is keyCertSign alone (no digitalSignature for an ECDSA key)", [leaf(i, ku=dict(KU_CA, crl_sign=False)), i.cert], [r.cert])
    add("ok_leaf_without_key_usage", "ok", "the leaf has no keyUsage", [leaf(i, ku=None), i.cert], [r.cert])
    add("refuse_leaf_eku_client_only", "refuse", "the leaf's extendedKeyUsage is clientAuth alone", [leaf(i, eku=[ExtendedKeyUsageOID.CLIENT_AUTH]), i.cert], [r.cert])
    add("either_leaf_without_eku", "either", "the leaf has no extendedKeyUsage (RFC 5280: any use; the CA/B Forum requires serverAuth)", [leaf(i, eku=None), i.cert], [r.cert])
    add("either_leaf_eku_any", "either", "the leaf's extendedKeyUsage is anyExtendedKeyUsage alone", [leaf(i, eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]), i.cert], [r.cert])
    add("either_leaf_eku_server_and_any", "either", "the leaf's extendedKeyUsage is serverAuth and anyExtendedKeyUsage (RFC 5280: any use; the CA/B Forum forbids anyExtendedKeyUsage)", [leaf(i, eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]), i.cert], [r.cert])
    ic = I(eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    add("either_intermediate_eku_client_only", "either", "the intermediate's extendedKeyUsage is clientAuth alone, the leaf's serverAuth (EKU nesting is not in RFC 5280; browsers apply it)", [leaf(ic), ic.cert], [r.cert])
    unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x05\x00")
    add("refuse_leaf_unknown_critical_extension", "refuse", "an extension nobody knows, marked critical, in the leaf", [leaf(i, extra=[(unknown, True)]), i.cert], [r.cert])
    iu = I(extra=[(unknown, True)])
    add("refuse_intermediate_unknown_critical_extension", "refuse", "an extension nobody knows, marked critical, in the intermediate", [leaf(iu), iu.cert], [r.cert])
    add("ok_leaf_unknown_extension_not_critical", "ok", "an extension nobody knows, not critical, in the leaf", [leaf(i, extra=[(unknown, False)]), i.cert], [r.cert])


def name_constraints():
    r = root()
    def NC(permitted=None, excluded=None, critical=True):
        return [(x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded), critical)]
    import ipaddress
    i = inter(r, extra=NC([x509.DNSName("example.test")]))
    add("ok_nc_permitted", "ok", "the intermediate permits example.test; the leaf is a.example.test", [leaf(i, san=[x509.DNSName("a.example.test")]), i.cert], [r.cert], host="a.example.test")
    add("refuse_nc_not_permitted", "refuse", "the intermediate permits example.test; the leaf is a.other.test", [leaf(i, san=[x509.DNSName("a.other.test")]), i.cert], [r.cert], host="a.other.test")
    add("refuse_nc_one_name_not_permitted", "refuse", "the intermediate permits example.test; the leaf names a.example.test and evil.test", [leaf(i, san=[x509.DNSName("a.example.test"), x509.DNSName("evil.test")]), i.cert], [r.cert], host="a.example.test")
    add("refuse_nc_suffix_without_dot", "refuse", "the intermediate permits example.test; the leaf is badexample.test", [leaf(i, san=[x509.DNSName("badexample.test")]), i.cert], [r.cert], host="badexample.test")
    add("either_nc_common_name_only", "either", "the intermediate permits example.test; the leaf has no subjectAltName and evil.test in its common name", [leaf(i, cn="evil.test", san=None), i.cert], [r.cert], host="evil.test")
    i = inter(r, extra=NC(None, [x509.DNSName("bad.example.test")]))
    add("refuse_nc_excluded", "refuse", "the intermediate excludes bad.example.test; the leaf is x.bad.example.test", [leaf(i, san=[x509.DNSName("x.bad.example.test")]), i.cert], [r.cert], host="x.bad.example.test")
    add("ok_nc_excluded_other", "ok", "the intermediate excludes bad.example.test; the leaf is good.example.test", [leaf(i, san=[x509.DNSName("good.example.test")]), i.cert], [r.cert], host="good.example.test")
    i = inter(r, extra=NC([x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))]))
    add("ok_nc_ip_only_dns_leaf", "ok", "the intermediate constrains addresses only; the leaf is a DNS name (no constraint of that type)", [leaf(i), i.cert], [r.cert])
    add("refuse_nc_ip_outside", "refuse", "the intermediate permits 192.0.2.0/24; the leaf is 198.51.100.1", [leaf(i, san=[x509.IPAddress(ipaddress.ip_address("198.51.100.1"))]), i.cert], [r.cert], host="198.51.100.1")
    rn = root(extra=NC([x509.DNSName("example.test")]))
    i = inter(rn)
    add("either_nc_on_anchor", "either", "the anchor permits example.test; the leaf is host.test (an anchor's constraints are the verifier's choice)", [leaf(i), i.cert], [rn.cert])
    i = inter(r, extra=NC([x509.DNSName("example.test")], critical=False))
    add("either_nc_not_critical", "either", "the intermediate's nameConstraints is not critical (CAs MUST mark it) and does not permit the leaf", [leaf(i, san=[x509.DNSName("a.other.test")]), i.cert], [r.cert], host="a.other.test")
    up = inter(r, "Case Upper", extra=NC([x509.DNSName("example.test")]))
    low = inter(up, "Case Lower")
    add("refuse_nc_from_a_higher_intermediate", "refuse", "the upper of two intermediates permits example.test; the leaf is a.other.test", [leaf(low, san=[x509.DNSName("a.other.test")]), low.cert, up.cert], [r.cert], host="a.other.test")


def signatures():
    r = root()
    i = inter(r)
    add("refuse_leaf_signature_flipped", "refuse", "the last bit of the leaf's signature flipped", [flip_last_byte(leaf(i)), i.cert], [r.cert])
    add("refuse_intermediate_signature_flipped", "refuse", "the last bit of the intermediate's signature flipped", [leaf(i), flip_last_byte(i.cert)], [r.cert])
    impostor = CA("Case Intermediate")
    add("refuse_leaf_signed_by_another_key", "refuse", "the leaf names the intermediate as issuer and is signed by another key", [cert(name(HOST), i.name, key().public_key(), impostor.key, ca=False), i.cert], [r.cert])
    c = leaf(i)
    add("refuse_outer_algorithm_differs", "refuse", "the signature algorithm outside the TBS (SHA-384) differs from the one inside (SHA-256)",
        [sign_tbs(tbs_of(c), i.key, hashes.SHA256(), outer_alg=ALG_ECDSA_SHA384), i.cert], [r.cert])
    rr = root(kind="rsa")
    ir = inter(rr, kind="rsa")
    add("either_leaf_signed_sha1", "either", "the leaf signed with RSA and SHA-1 (refused by the CA/B Forum and browsers)", [edit_tbs(leaf(ir, kind="rsa"), ir.key, lambda f: f[:2] + [ALG_RSA_SHA1] + f[3:], hashes.SHA1()), ir.cert], [rr.cert])
    add("either_leaf_rsa_1024", "either", "the leaf's key is RSA-1024 (refused by the CA/B Forum and browsers)", [leaf(ir, kind="rsa1024"), ir.cert], [rr.cert])
    ik = CA("Case Intermediate", "rsa1024")
    ik.cert = cert(ik.name, rr.name, ik.pub, rr.key, ca=True, aki=rr.pub)
    add("either_intermediate_rsa_1024", "either", "the intermediate's key is RSA-1024", [leaf(ik), ik.cert], [rr.cert])


def names():
    r = root()
    i = inter(r, "Case Intermediate")
    # the leaf names its issuer in another case, with another string type, or with spaces RFC 4518 ignores
    def issued(issuer_name):
        k = key()
        return cert(name(HOST), i.name, k.public_key(), i.key, ca=False, aki=i.pub, issuer_name=issuer_name)
    add("either_issuer_name_case", "either", "the leaf names its issuer \"case intermediate\" (RFC 5280 7.1 compares without case; Go compares bytes)", [issued(name("case intermediate")), i.cert], [r.cert])
    add("either_issuer_name_printable_string", "either", "the leaf names its issuer as a PrintableString, the intermediate's own name is a UTF8String", [issued(name("Case Intermediate", _ASN1Type.PrintableString)), i.cert], [r.cert])
    add("either_issuer_name_spaces", "either", "the leaf names its issuer \"Case  Intermediate\" (two spaces, which RFC 4518 folds)", [issued(name("Case  Intermediate")), i.cert], [r.cert])
    add("refuse_issuer_name_other", "refuse", "the leaf names another issuer (signed by the intermediate's key)", [issued(name("Some Other CA")), i.cert], [r.cert])
    c = leaf(i)
    other = CA("x")
    def wrong_aki(fields):
        return edit_extensions(fields, lambda exts: [e for e in exts if b"\x06\x03\x55\x1d\x23" not in e[:8]] +
                               [der_ext("2.5.29.35", tlv(0x30, tlv(0x80, x509.SubjectKeyIdentifier.from_public_key(other.pub).digest)))])
    add("either_authority_key_id_mismatch", "either", "the leaf's authorityKeyIdentifier is not the intermediate's key identifier (names and signature match)", [edit_tbs(c, i.key, wrong_aki), i.cert], [r.cert])
    add("either_no_authority_key_id", "either", "the leaf has no authorityKeyIdentifier (RFC 5280 allows it; the CA/B Forum wants one)", [leaf(i, aki=False), i.cert], [r.cert])


def der_ext(oid, value, critical=False):
    o = x509.ObjectIdentifier(oid)
    enc = ObjectIdentifier_der(o)
    return tlv(0x30, enc + (tlv(0x01, b"\xff") if critical else b"") + tlv(0x04, value))


def ObjectIdentifier_der(o):
    parts = [int(p) for p in o.dotted_string.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(chunk)
    return tlv(0x06, body)


def paths():
    r = root()
    i = inter(r)
    # the same intermediate (name and key) issued twice: once expired, once valid; the expired one is sent first
    expired = cert(i.name, r.name, i.pub, r.key, ca=True, aki=r.pub, na=TIME - DAY)
    add("ok_two_issuers_one_expired", "ok", "the intermediate sent twice, an expired copy first (path building has to try the other)", [leaf(i), expired, i.cert], [r.cert])
    # a cross-signed intermediate: issued by an old root (expired) and by the anchor; the cross certificate is sent
    old = root("Case Old Root", na=TIME - DAY)
    cross = cert(i.name, old.name, i.pub, old.key, ca=True, aki=old.pub)
    add("ok_cross_signed_to_the_anchor", "ok", "the intermediate's cross certificate to another root sent first; the anchor issued it too", [leaf(i), cross, i.cert], [r.cert])
    add("refuse_only_the_cross_path", "refuse", "only the cross certificate to a root that is not an anchor is sent", [leaf(i), cross], [r.cert])
    # self-signed leaves
    k = key()
    me = name(HOST)
    selfie = cert(me, me, k.public_key(), k, ca=False)
    add("refuse_self_signed_leaf", "refuse", "a self-signed leaf, judged against another root", [selfie], [r.cert])
    add("either_self_signed_leaf_is_the_anchor", "either", "a self-signed leaf that is itself the trust anchor", [selfie], [selfie])


def encodings():
    r = root()
    i = inter(r)
    c = leaf(i)
    def serial(value):
        return lambda fields: [fields[0], tlv(0x02, value)] + fields[2:]
    add("either_serial_zero", "either", "the leaf's serial number is 0 (RFC 5280: positive; most verifiers accept)", [edit_tbs(c, i.key, serial(b"\x00")), i.cert], [r.cert])
    add("either_serial_negative", "either", "the leaf's serial number is -1", [edit_tbs(c, i.key, serial(b"\xff")), i.cert], [r.cert])
    add("either_serial_21_bytes", "either", "the leaf's serial number is 21 bytes long (RFC 5280: at most 20)", [edit_tbs(c, i.key, serial(b"\x01" * 21)), i.cert], [r.cert])
    def dup_san(fields):
        return edit_extensions(fields, lambda exts: exts + [e for e in exts if OID_SAN in e[:8]])
    add("refuse_duplicate_extension", "refuse", "the leaf has its subjectAltName twice (RFC 5280 4.2: at most once)", [edit_tbs(c, i.key, dup_san), i.cert], [r.cert])
    def bc_false_explicit(fields):
        return edit_extensions(fields, lambda exts: [der_ext("2.5.29.19", tlv(0x30, tlv(0x01, b"\x00")), True) if OID_BC in e[:8] else e for e in exts])
    add("either_basic_constraints_false_written", "either", "the leaf's basicConstraints writes cA FALSE, which DER leaves out (a default value)", [edit_tbs(c, i.key, bc_false_explicit), i.cert], [r.cert])
    def tbs_alg(fields):
        return fields[:2] + [ALG_ECDSA_SHA384] + fields[3:]
    add("refuse_inner_algorithm_differs", "refuse", "the signature algorithm inside the TBS (SHA-384) differs from the one outside (SHA-256), signed with SHA-256",
        [edit_tbs(c, i.key, tbs_alg, hashes.SHA256(), outer_alg=ALG_ECDSA_SHA256), i.cert], [r.cert])
    def v2(fields):
        return [tlv(0xA0, tlv(0x02, b"\x01"))] + fields[1:]
    add("refuse_version_2_with_extensions", "refuse", "the leaf says version 2 and has extensions (RFC 5280 4.1.2.1: extensions need version 3)", [edit_tbs(c, i.key, v2), i.cert], [r.cert])


def write():
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(f"{OUT}/chains")
    os.makedirs(f"{OUT}/anchors")
    seen = set()
    with open(f"{OUT}/fixtures.tsv", "w") as f:
        f.write("# Made by tools/gen_chain_cases.py: certificate chains that differ from a good one in one thing each.\n")
        f.write("# name\thost\ttime\texpect\tanchor\twhat\n")
        for label, host, when, expect, what, chain, anchors in CASES:
            assert label not in seen, label
            seen.add(label)
            with open(f"{OUT}/chains/{label}.pem", "w") as c:
                c.write("".join(pem(d) for d in chain))
            with open(f"{OUT}/anchors/{label}.pem", "w") as a:
                a.write("".join(pem(d) for d in anchors))
            f.write(f"{label}\t{host}\t{when}\t{expect}\tanchors/{label}.pem\t{what}\n")
    print(f"wrote {len(CASES)} cases to {OUT}/")


def pem(d):
    import base64
    b = base64.b64encode(d).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


if __name__ == "__main__":
    base()
    times()
    hostnames()
    constraints()
    name_constraints()
    signatures()
    names()
    paths()
    encodings()
    write()
