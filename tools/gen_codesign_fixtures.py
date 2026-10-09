#!/usr/bin/env python3
"""Regenerates the non-TLS chain fixtures in tests/data/cs_*.pem, as_*.pem, ts_*.pem and em_*.pem
with Python `cryptography` (BACKLOG B-69: chains verified for code signing, time stamping and e-mail).

Run from the repository root: python3 tools/gen_codesign_fixtures.py
Keys are random; the files hold public certificates only (no private keys are written).

These are generated, not captured. They copy the *profile* of the real thing:

  cs_*  Sigstore's Fulcio: a P-384 root and intermediate (pathLen 0, EKU codeSigning), and short-lived
        P-256 leaves (10 minutes) with an empty subject, a critical subjectAltName that holds a URI,
        an e-mail address or an otherName, keyUsage digitalSignature, EKU codeSigning and the
        OIDC claims in non-critical extensions under 1.3.6.1.4.1.57264.1 (the encodings were
        taken from a real Fulcio leaf: .1.1 is raw text, .1.8 and later are DER UTF8Strings).
  as_*  Authenticode: an RSA root, a code-signing intermediate and an RSA leaf that has expired by
        now but was valid when it signed; EKU codeSigning plus Microsoft's lifetime signing.
  ts_*  A time-stamp authority: EKU timeStamping, critical, as RFC 3161 asks.
  em_*  S/MIME: EKU emailProtection, keyUsage with and without digitalSignature.

The real Fulcio root and intermediate (tests/data/fulcio_real_*.pem) are NOT generated here: they
were copied from github.com/sigstore/root-signing and their signatures checked.
Nothing here uses a real organisation's name.
"""
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID as EKU
from cryptography.x509.oid import NameOID, ObjectIdentifier

D = "tests/data/"
LONG_FROM = datetime.datetime(2020, 1, 1)
LONG_TO = datetime.datetime(2120, 1, 1)
# the moment the short-lived leaves were "issued": 2025-03-01 12:00:00 UTC, for ten minutes
SIGNED_AT = datetime.datetime(2025, 3, 1, 12, 0, 0)

FULCIO = ObjectIdentifier("1.3.6.1.4.1.57264.1")
LIFETIME_SIGNING = ObjectIdentifier("1.3.6.1.4.1.311.10.3.13")


def fulcio(n):
    return ObjectIdentifier("1.3.6.1.4.1.57264.1.%d" % n)


def utf8(s):
    b = s.encode()
    assert len(b) < 128
    return bytes([0x0C, len(b)]) + b


def raw(oid, value, critical=False):
    return x509.UnrecognizedExtension(oid, value), critical


def save(name, cert):
    open(D + name + ".pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))


def p256():
    return ec.generate_private_key(ec.SECP256R1())


def p384():
    return ec.generate_private_key(ec.SECP384R1())


def rsa2048():
    return rsa.generate_private_key(65537, 2048)


def dn(cn=None, o=None, c=None, email=None):
    attrs = []
    if c:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    if o:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if cn:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    if email:
        attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    return x509.Name(attrs)


def ku(**kw):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False)
    base.update(kw)
    return x509.KeyUsage(**base)


def issue(subject, key, issuer, issuer_key, h, extensions, nb=LONG_FROM, na=LONG_TO):
    """extensions: list of (extension, critical)."""
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na))
    for ext, critical in extensions:
        b = b.add_extension(ext, critical=critical)
    return b.sign(issuer_key, h)


def ca_exts(key, pathlen=None, eku=None, nc=None):
    out = [(x509.BasicConstraints(ca=True, path_length=pathlen), True),
           (ku(key_cert_sign=True, crl_sign=True), True)]
    if eku:
        out.append((x509.ExtendedKeyUsage(eku), False))
    if nc:
        out.append((nc, True))
    out.append((x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))
    return out


# ------------------------------------------------------------------ Fulcio profile
ORG = "Test PKI (Fulcio profile)"
root_k, inter_k = p384(), p384()
root_n, inter_n = dn("Fulcio-profile Test Root", ORG), dn("Fulcio-profile Test Intermediate", ORG)
save("cs_root", issue(root_n, root_k, root_n, root_k, hashes.SHA384(), ca_exts(root_k)))
save("cs_inter", issue(inter_n, inter_k, root_n, root_k, hashes.SHA384(),
                       ca_exts(inter_k, pathlen=0, eku=[EKU.CODE_SIGNING])))

WORKFLOW = "https://github.com/example-org/example-repo/.github/workflows/release.yml@refs/tags/v1.2.3"
GH_ISSUER = "https://token.actions.githubusercontent.com"


def fulcio_leaf(name, san, extra=(), eku=(EKU.CODE_SIGNING,), key_usage=None, issuer=(inter_n, inter_k),
                nb=SIGNED_AT, na=SIGNED_AT + datetime.timedelta(minutes=10), san_critical=True):
    k = p256()
    exts = [(key_usage or ku(digital_signature=True), True)]
    if eku is not None:
        exts.append((x509.ExtendedKeyUsage(list(eku)), False))
    exts.append((x509.SubjectKeyIdentifier.from_public_key(k.public_key()), False))
    exts.append((x509.SubjectAlternativeName(san), san_critical))
    exts += list(extra)
    save(name, issue(x509.Name([]), k, issuer[0], issuer[1], hashes.SHA384(), exts, nb, na))


fulcio_leaf("cs_leaf_workflow", [x509.UniformResourceIdentifier(WORKFLOW)], [
    raw(fulcio(1), GH_ISSUER.encode()),                       # Issuer (v1): raw text
    raw(fulcio(8), utf8(GH_ISSUER)),                          # Issuer (v2): DER UTF8String
    raw(fulcio(9), utf8(WORKFLOW)),                           # Build Signer URI
    raw(fulcio(12), utf8("https://github.com/example-org/example-repo")),   # Source Repository URI
    raw(fulcio(13), utf8("0123456789abcdef0123456789abcdef01234567")),     # Source Repository Digest
    raw(fulcio(14), utf8("refs/tags/v1.2.3")),                # Source Repository Ref
])
fulcio_leaf("cs_leaf_email", [x509.RFC822Name("dev@example.test")], [raw(fulcio(8), utf8("https://accounts.example.test"))])
# otherName with the Fulcio "username" type, 1.3.6.1.4.1.57264.1.7, whose value is a UTF8String
fulcio_leaf("cs_leaf_other", [x509.OtherName(fulcio(7), utf8("alice"))], [raw(fulcio(8), utf8("https://accounts.example.test"))])
fulcio_leaf("cs_leaf_noeku", [x509.RFC822Name("dev@example.test")], eku=None)
fulcio_leaf("cs_leaf_tls", [x509.DNSName("tls-only.example.test")], eku=(EKU.SERVER_AUTH,))
fulcio_leaf("cs_leaf_anyeku", [x509.RFC822Name("dev@example.test")], eku=(x509.ObjectIdentifier("2.5.29.37.0"),))
fulcio_leaf("cs_leaf_noku", [x509.RFC822Name("dev@example.test")], key_usage=ku(key_encipherment=True))
# a critical extension of a kind nobody here knows (1.3.6.1.4.1.99999.1, a made-up private arc)
fulcio_leaf("cs_leaf_critical", [x509.RFC822Name("dev@example.test")],
            [raw(ObjectIdentifier("1.3.6.1.4.1.99999.1"), utf8("private"), critical=True)])
# several names of several kinds, to read back in order
fulcio_leaf("cs_leaf_names", [
    x509.DNSName("Host.Example.Test"), x509.IPAddress(ipaddress.ip_address("192.0.2.7")),
    x509.IPAddress(ipaddress.ip_address("2001:db8::1")), x509.RFC822Name("Dev@Example.test"),
    x509.UniformResourceIdentifier("https://example.test/a?b#c"),
    x509.DirectoryName(dn("Some Person", "Some Org")), x509.OtherName(fulcio(7), utf8("alice")),
    x509.RegisteredID(ObjectIdentifier("1.2.3.4.5")),
])

# name constraints on e-mail, URI and IP names (and an excluded mailbox)
nc_k = p384()
nc_n = dn("Fulcio-profile Constrained Intermediate", ORG)
nc = x509.NameConstraints(
    permitted_subtrees=[x509.RFC822Name("example.test"), x509.UniformResourceIdentifier("github.com"),
                        x509.UniformResourceIdentifier(".corp.example.test"),
                        x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))],
    excluded_subtrees=[x509.RFC822Name("banned@example.test"), x509.DNSName("bad.example.test")])
save("cs_inter_nc", issue(nc_n, nc_k, root_n, root_k, hashes.SHA384(),
                          ca_exts(nc_k, pathlen=0, eku=[EKU.CODE_SIGNING], nc=nc)))
nc_issuer = (nc_n, nc_k)
LONG = dict(nb=LONG_FROM, na=LONG_TO)
fulcio_leaf("cs_nc_ok", [x509.RFC822Name("dev@example.test"), x509.UniformResourceIdentifier("https://github.com/org/repo/x@refs"),
                         x509.UniformResourceIdentifier("https://ci.corp.example.test/job/1"),
                         x509.IPAddress(ipaddress.ip_address("192.0.2.7"))], issuer=nc_issuer, **LONG)
fulcio_leaf("cs_nc_bad_email", [x509.RFC822Name("dev@evil.test")], issuer=nc_issuer, **LONG)
fulcio_leaf("cs_nc_bad_email_sub", [x509.RFC822Name("dev@sub.example.test")], issuer=nc_issuer, **LONG)  # host constraint, not subdomains
fulcio_leaf("cs_nc_excluded_email", [x509.RFC822Name("banned@example.test")], issuer=nc_issuer, **LONG)
fulcio_leaf("cs_nc_bad_uri", [x509.UniformResourceIdentifier("https://evil.test/x")], issuer=nc_issuer, **LONG)
fulcio_leaf("cs_nc_bad_uri_sub", [x509.UniformResourceIdentifier("https://api.github.com/x")], issuer=nc_issuer, **LONG)  # exact host
fulcio_leaf("cs_nc_bad_ip", [x509.IPAddress(ipaddress.ip_address("198.51.100.1"))], issuer=nc_issuer, **LONG)
fulcio_leaf("cs_nc_excluded_dns", [x509.DNSName("bad.example.test")], issuer=nc_issuer, **LONG)
# a name of a kind with no constraint under this CA is not affected
fulcio_leaf("cs_nc_other_kind", [x509.OtherName(fulcio(7), utf8("alice"))], issuer=nc_issuer, **LONG)

# a constraint of a kind this code does not evaluate (here an otherName)
nco_k = p384()
nco_n = dn("Fulcio-profile OtherName-constrained Intermediate", ORG)
nco = x509.NameConstraints(permitted_subtrees=[x509.OtherName(fulcio(7), utf8("alice"))], excluded_subtrees=None)
try:
    save("cs_inter_nc_other", issue(nco_n, nco_k, root_n, root_k, hashes.SHA384(),
                                    ca_exts(nco_k, pathlen=0, eku=[EKU.CODE_SIGNING], nc=nco)))
    fulcio_leaf("cs_nco_other", [x509.OtherName(fulcio(7), utf8("alice"))], issuer=(nco_n, nco_k), **LONG)
    fulcio_leaf("cs_nco_email", [x509.RFC822Name("dev@example.test")], issuer=(nco_n, nco_k), **LONG)
except Exception as e:  # pragma: no cover - depends on the library version
    print("skipping otherName constraints:", e)

# ------------------------------------------------------------------ Authenticode profile
AORG = "Test PKI (code signing profile)"
as_root_k, as_inter_k = rsa2048(), rsa2048()
as_root_n, as_inter_n = dn("Test Code Signing Root", AORG, "US"), dn("Test Code Signing CA 01", AORG, "US")
save("as_root", issue(as_root_n, as_root_k, as_root_n, as_root_k, hashes.SHA256(), ca_exts(as_root_k)))
save("as_inter", issue(as_inter_n, as_inter_k, as_root_n, as_root_k, hashes.SHA256(),
                       ca_exts(as_inter_k, pathlen=0, eku=[EKU.CODE_SIGNING])))
leaf_k = rsa2048()
save("as_leaf", issue(dn("Example Software Inc", "Example Software Inc", "US"), leaf_k, as_inter_n, as_inter_k, hashes.SHA256(), [
    (x509.BasicConstraints(ca=False, path_length=None), True),
    (ku(digital_signature=True), True),
    (x509.ExtendedKeyUsage([EKU.CODE_SIGNING, LIFETIME_SIGNING]), False),
    (x509.SubjectKeyIdentifier.from_public_key(leaf_k.public_key()), False),
], nb=datetime.datetime(2023, 1, 1), na=datetime.datetime(2024, 1, 1)))
# a TLS certificate from the same CA hierarchy cannot sign code
tls_k = rsa2048()
save("as_leaf_tls", issue(dn("tls.example.test"), tls_k, as_inter_n, as_inter_k, hashes.SHA256(), [
    (x509.BasicConstraints(ca=False, path_length=None), True), (ku(digital_signature=True), True),
    (x509.ExtendedKeyUsage([EKU.SERVER_AUTH]), False),
    (x509.SubjectAlternativeName([x509.DNSName("tls.example.test")]), False)]))

# ------------------------------------------------------------------ time stamping authority
ts_root_k = p256()
ts_root_n = dn("Test Time Stamping Root", "Test PKI (timestamp profile)")
save("ts_root", issue(ts_root_n, ts_root_k, ts_root_n, ts_root_k, hashes.SHA256(), ca_exts(ts_root_k)))
ts_k = p256()
save("ts_leaf", issue(dn("Test Time Stamping Authority", "Test PKI (timestamp profile)"), ts_k, ts_root_n, ts_root_k, hashes.SHA256(), [
    (ku(digital_signature=True), True),
    (x509.ExtendedKeyUsage([EKU.TIME_STAMPING]), True),     # RFC 3161: critical, and the only purpose
    (x509.SubjectKeyIdentifier.from_public_key(ts_k.public_key()), False)],
    nb=datetime.datetime(2022, 1, 1), na=datetime.datetime(2032, 1, 1)))

# ------------------------------------------------------------------ S/MIME
em_root_k = rsa2048()
em_root_n = dn("Test E-mail Root", "Test PKI (S/MIME profile)")
save("em_root", issue(em_root_n, em_root_k, em_root_n, em_root_k, hashes.SHA256(), ca_exts(em_root_k)))


def em_leaf(name, key_usage):
    k = p256()
    save(name, issue(dn("Alice Example", email="alice@example.test"), k, em_root_n, em_root_k, hashes.SHA256(), [
        (x509.BasicConstraints(ca=False, path_length=None), True), (key_usage, True),
        (x509.ExtendedKeyUsage([EKU.EMAIL_PROTECTION, EKU.CLIENT_AUTH]), False),
        (x509.SubjectAlternativeName([x509.RFC822Name("alice@example.test")]), False)]))


em_leaf("em_leaf", ku(digital_signature=True, content_commitment=True))
em_leaf("em_leaf_nr", ku(content_commitment=True, key_encipherment=True))   # no digitalSignature
print("fixtures written")
