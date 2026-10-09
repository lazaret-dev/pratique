#!/usr/bin/env python3
"""Regenerates tests/data/rv_fixtures.txt: the certificates behind the regression tests for the first
independent-style review of src/x509.rs (SECURITY_REVIEW.md, BACKLOG.md B-93, and B-94 for the
directoryName and intermediate-name cases).

Run from the repository root: python3 tools/gen_review_fixtures.py
Keys are random and are not written; the file holds public certificates only, one per line as
`name base64(DER)`. Every certificate is valid 2020..2120, so the tests' fixed clock applies.

Some of these are deliberately malformed (a BOOLEAN written as 0x01, a dNSName with a line feed, a
name constraint with a trailing dot, a version 1 certificate), which Python `cryptography` will not
write, so the DER is built by hand here and signed with the issuer's key.
"""
import base64, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

NB = datetime.datetime(2020, 1, 1)
NA = datetime.datetime(2120, 1, 1)
OID_SAN = x509.ObjectIdentifier("2.5.29.17")
OID_NC = x509.ObjectIdentifier("2.5.29.30")
OUT = {}


# ----------------------------------------------------------------------------- DER by hand
def tlv(tag, content=b""):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def san_value(*entries):
    return seq(*entries)


def nc_value(permitted=(), excluded=()):
    out = b""
    if permitted:
        out += tlv(0xA0, b"".join(seq(b) for b in permitted))
    if excluded:
        out += tlv(0xA1, b"".join(seq(b) for b in excluded))
    return seq(out)


def dns(s):
    return tlv(0x82, s if isinstance(s, bytes) else s.encode("latin-1"))


def email(s):
    return tlv(0x81, s if isinstance(s, bytes) else s.encode("latin-1"))


def children(b):
    """The (tag, whole element) children of one DER element."""
    def head(buf, i):
        n = buf[i + 1]
        j = i + 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[j:j + k], "big")
            j += k
        return j, n
    j, n = head(b, 0)
    out, i = [], j
    while i < j + n:
        cj, cn = head(b, i)
        out.append((b[i], b[i:cj + cn]))
        i = cj + cn
    return out


# ----------------------------------------------------------------------------- certificates
def key():
    return ec.generate_private_key(ec.SECP256R1())


def name(cn, mail=None, org=None):
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if mail:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, mail))
    return x509.Name(attrs)


def make(subject, issuer, pub, signer, *, ca=False, bc=True, ku="auto", eku=None, san=None, raw=()):
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(NB).not_valid_after(NA))
    if bc:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if ku == "auto":
        ku = "ca" if ca else "leaf"
    if ku == "ca":
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    elif ku == "leaf":
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if san is not None:
        b = b.add_extension(san, critical=False)
    for oid, value, crit in raw:
        b = b.add_extension(x509.UnrecognizedExtension(oid, value), critical=crit)
    return b.sign(signer, hashes.SHA256())


def der(c):
    return c if isinstance(c, bytes) else c.public_bytes(serialization.Encoding.DER)


def put(label, c):
    assert label not in OUT, label
    OUT[label] = der(c)


SERVER = [ExtendedKeyUsageOID.SERVER_AUTH]
EMAIL = [ExtendedKeyUsageOID.EMAIL_PROTECTION]
HOST = x509.SubjectAlternativeName([x509.DNSName("host.test")])


def root(label, cn):
    k, n = key(), name(cn)
    put(label, make(n, n, k.public_key(), k, ca=True))
    return k, n


def inter(label, pk, pn, cn, raw=(), mail=None):
    k, n = key(), name(cn, mail)
    put(label, make(n, pn, k.public_key(), pk, ca=True, raw=raw))
    return k, n


def leaf(label, pk, pn, cn="leaf", san=HOST, eku=SERVER, raw=(), mail=None, org=None):
    k, n = key(), name(cn, mail, org)
    put(label, make(n, pn, k.public_key(), pk, eku=eku, san=san, raw=raw))


# ----------------------------------------------------------------------------- 1. the path search
def ladder(levels=8, variants=4):
    """A leaf and, at each of 8 levels, 4 different certificates with the same subject, each of which
    verifies against the one above. No anchor is reachable: the search tries every path."""
    keys = [key() for _ in range(levels + 1)]
    names = [name(f"Ladder S{i}") for i in range(levels + 2)]
    put("ladder_leaf", make(name("leaf"), names[1], key().public_key(), keys[0], eku=SERVER, san=HOST))
    for lvl in range(1, levels + 1):
        for v in range(variants):
            put(f"ladder_L{lvl}_{v}", make(names[lvl], names[lvl + 1], keys[lvl - 1].public_key(), keys[lvl], ca=True))
    root("ladder_unrelated_root", "Ladder Unrelated Root")


def decoys(n=10):
    """A good chain, with `n` certificates in front of the real intermediate that have its name but
    not its key: each costs one failed signature check and nothing more."""
    rk, rn = root("decoy_root", "Decoy Root")
    ik, inn = inter("decoy_inter", rk, rn, "Decoy Inter")
    leaf("decoy_leaf", ik, inn)
    for i in range(n):
        other = key()
        put(f"decoy_x{i}", make(inn, rn, other.public_key(), rk, ca=True))


# ----------------------------------------------------------------------------- 2. anchors
def v1_self_signed(label, cn):
    """An X.509 version 1 certificate (no version field, no extensions): the old roots that have no
    basicConstraints. Returns its key and name."""
    k, n = key(), name(cn)
    sigalg = seq(tlv(0x06, bytes.fromhex("2a8648ce3d040302")))  # ecdsa-with-SHA256
    validity = seq(tlv(0x17, b"200101000000Z"), tlv(0x18, b"21200101000000Z"))
    spki = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    tbs = seq(tlv(0x02, b"\x01"), sigalg, n.public_bytes(), validity, n.public_bytes(), spki)
    sig = k.sign(tbs, ec.ECDSA(hashes.SHA256()))
    put(label, seq(tbs, sigalg, tlv(0x03, b"\x00" + sig)))
    return k, n


def anchors():
    # a version 3 certificate with no basicConstraints and no keyUsage: not a CA
    k, n = key(), name("Anchor V3 No BC")
    put("anchor_v3_nobc", make(n, n, k.public_key(), k, bc=False, ku=None))
    leaf("anchor_v3_nobc_leaf", k, n)
    # the same, with keyUsage keyCertSign but still no basicConstraints
    k, n = key(), name("Anchor V3 No BC With KU")
    put("anchor_v3_nobc_ku", make(n, n, k.public_key(), k, bc=False, ku="ca"))
    leaf("anchor_v3_nobc_ku_leaf", k, n)
    # a version 1 root: no basicConstraints is all it can have
    k, n = v1_self_signed("anchor_v1", "Anchor V1")
    leaf("anchor_v1_leaf", k, n)


# ----------------------------------------------------------------------------- 4. dropped names, 7, 3
def names():
    rk, rn = root("nm_root", "Names Root")
    x400 = tlv(0xA3, b"")
    dir_ok = tlv(0xA4, seq())
    dir_bad = tlv(0xA4, tlv(0x04, b"A"))

    def under(label, permitted=(), excluded=()):
        return inter(label, rk, rn, label, raw=[(OID_NC, nc_value(permitted, excluded), True)])

    def with_san(label, k, n, *entries):
        leaf(label, k, n, san=None, raw=[(OID_SAN, san_value(*entries), False)])

    # 4: names the SAN reader leaves out, under a constraint of their kind
    k, n = under("nm_inter_x400", permitted=[x400])
    with_san("nm_leaf_x400", k, n, x400, dns("host.test"))
    k, n = under("nm_inter_dir", permitted=[dir_ok])
    with_san("nm_leaf_dir_ok", k, n, dir_ok, dns("host.test"))
    with_san("nm_leaf_dir_malformed", k, n, dir_bad, dns("host.test"))
    k, n = under("nm_inter_email", permitted=[email(".corp.example")])
    with_san("nm_leaf_email_nonascii", k, n, email(b"mallory@\xc3\xa9vil.test"), dns("host.test"))
    # control: the same odd name, but the CA's constraints are about DNS names only
    k, n = under("nm_inter_dns_only", permitted=[dns("test")])
    with_san("nm_leaf_x400_dns_only", k, n, x400, dns("host.test"))

    # 7: constraint syntax
    k, n = under("nm_inter_trailing_dot", excluded=[dns("bad.example.com.")])
    with_san("nm_leaf_bad_host", k, n, dns("bad.example.com"))
    k, n = under("nm_inter_empty_label", excluded=[dns("bad..example.com")])
    with_san("nm_leaf_bad_host2", k, n, dns("bad.example.com"))
    k, n = under("nm_inter_empty_email", excluded=[email("")])
    leaf("nm_leaf_email", k, n, san=None, eku=EMAIL, raw=[(OID_SAN, san_value(email("mallory@evil.test")), False)])
    k, n = under("nm_inter_excl_plain", excluded=[dns("bad.example.com")])  # control: refused before and after
    with_san("nm_leaf_bad_host3", k, n, dns("bad.example.com"))

    # 3: the e-mail address in the subject name, checked against e-mail constraints
    k, n = under("nm_inter_corp_email", permitted=[email("corp.example")])
    leaf("nm_leaf_subject_email_out", k, n, san=None, eku=EMAIL, mail="mallory@evil.test")
    leaf("nm_leaf_subject_email_in", k, n, san=None, eku=EMAIL, mail="alice@corp.example")
    leaf("nm_leaf_san_in_subject_out", k, n, san=x509.SubjectAlternativeName([x509.RFC822Name("alice@corp.example")]),
         eku=EMAIL, mail="mallory@evil.test")

    # directoryName constraints: this code does not compare Names, so a CA that carries one is refused
    corp = tlv(0xA4, seq(tlv(0x31, seq(tlv(0x06, bytes.fromhex("55040a")), tlv(0x0C, b"Corp")))))
    k, n = under("nm_inter_dir_perm", permitted=[corp])
    leaf("nm_leaf_o_other", k, n, org="Other")
    k, n = under("nm_inter_dir_excl", excluded=[corp])
    leaf("nm_leaf_o_corp", k, n, org="Corp")

    # the names of an intermediate are held to the constraints of the CAs above it
    ak, an = under("nm_inter_good", permitted=[dns("good.example")])
    www = x509.SubjectAlternativeName([x509.DNSName("www.good.example")])
    for label, host in [("nm_sub_san_out", "evil.test"), ("nm_sub_san_in", "ca.good.example")]:
        bk, bn = inter(label, ak, an, "Sub B", raw=[(OID_SAN, san_value(dns(host)), False)])
        leaf(label.replace("nm_sub", "nm_leaf_under_sub"), bk, bn, san=www)
    ek, en = under("nm_inter_corp_email2", permitted=[email("corp.example")])
    alice = x509.SubjectAlternativeName([x509.RFC822Name("alice@corp.example")])
    for label, mail in [("nm_sub_mail_out", "mallory@evil.test"), ("nm_sub_mail_in", "bob@corp.example")]:
        bk, bn = inter(label, ek, en, "Sub B", mail=mail)
        leaf(label.replace("nm_sub", "nm_leaf_under_sub"), bk, bn, san=alice, eku=EMAIL)

    # 8: a dNSName with a line feed in it
    leaf("nm_leaf_ctl_dns", rk, rn, san=None, raw=[(OID_SAN, san_value(dns("evil\nINJECTED log line.test")), False)])


# ----------------------------------------------------------------------------- 6. BOOLEAN
def booleans():
    rk, rn = root("bool_root", "Bool Root")
    unknown = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1")
    oid_der = tlv(0x06, bytes.fromhex("2b06010401868d1f01"))
    for label, byte in [("bool_leaf_ff", None), ("bool_leaf_01", b"\x01")]:
        c = make(name("leaf"), rn, key().public_key(), rk, eku=SERVER, san=HOST, raw=[(unknown, b"\x05\x00", True)])
        raw = der(c)
        if byte is not None:
            tbs, sigalg = children(raw)[0][1], children(raw)[1][1]
            at = tbs.find(oid_der + b"\x01\x01\xff")
            assert at >= 0
            at += len(oid_der) + 2
            tbs = tbs[:at] + byte + tbs[at + 1:]
            raw = seq(tbs, sigalg, tlv(0x03, b"\x00" + rk.sign(tbs, ec.ECDSA(hashes.SHA256()))))
        put(label, raw)


if __name__ == "__main__":
    ladder()
    decoys()
    anchors()
    names()
    booleans()
    with open("tests/data/rv_fixtures.txt", "w") as f:
        f.write("# Certificates for the review regression tests (src/x509.rs, `mod tests`).\n")
        f.write("# Made by tools/gen_review_fixtures.py: `name base64(DER)`, one per line.\n")
        for label, raw in OUT.items():
            f.write(f"{label} {base64.b64encode(raw).decode()}\n")
    print(len(OUT), "certificates written to tests/data/rv_fixtures.txt")
