#!/usr/bin/env python3
"""Generates the Ed25519 certificate, CRL and OCSP fixtures in tests/data/ed_* with Python `cryptography`.

Run from the repository root: python3 tools/gen_ed25519_fixtures.py
Keys are random and are not written (the files hold public data only), so running it again produces
different, equally valid files; the tests do not depend on the particular bytes. Windows are built
around NOW = 2026-09-15 00:00:00 UTC (1789430400), the clock the unit tests use.

  ed_root, ed_inter, ed_leaf     an all-Ed25519 chain (leaf: serverAuth, DNS ed.example.test, a CRL
                                 distribution point)
  ed_leaf_p256                   a P-256 leaf issued by the Ed25519 intermediate
  ed_ec_root, ed_leaf_by_ec      a P-256 root issuing an Ed25519 leaf
  ed_crl_*.der                   CRLs of ed_inter (signed with Ed25519): one that revokes ed_leaf, one that does not
  ed_ocsp_*.der                  OCSP responses about ed_leaf from ed_inter (signed with Ed25519)
  ed_leaf_certverify.txt         a signature by ed_leaf's key over TLS 1.3 CertificateVerify content, to test scheme 0x0807
"""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

D = "tests/data/"
DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM
nb = dt.datetime(2020, 1, 1)
na = dt.datetime(2120, 1, 1)
NOW = dt.datetime(2026, 9, 15)
day = dt.timedelta(days=1)
CRL_URL = "http://crl.example.test/ed-inter.crl"


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def save_pem(n, c):
    open(D + n + ".pem", "wb").write(c.public_bytes(PEM))


def save_der(n, o):
    open(D + n + ".der", "wb").write(o.public_bytes(DER) if hasattr(o, "public_bytes") else o)


def cert(subject, key, issuer_name, issuer_key, ca=False, pathlen=None, eku=None, sans=None, crl_url=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if crl_url:
        b = b.add_extension(
            x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)]),
            critical=False,
        )
    # an Ed25519 signature has no separate hash; a P-256 or RSA issuer would be given SHA-256
    h = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return b.sign(issuer_key, h)


root_k = ed25519.Ed25519PrivateKey.generate()
root = cert("Ed25519 Test Root", root_k, name("Ed25519 Test Root"), root_k, ca=True)
inter_k = ed25519.Ed25519PrivateKey.generate()
inter = cert("Ed25519 Test Intermediate", inter_k, root.subject, root_k, ca=True, pathlen=0)
srv = [ExtendedKeyUsageOID.SERVER_AUTH]
sans = [x509.DNSName("ed.example.test")]
leaf_k = ed25519.Ed25519PrivateKey.generate()
leaf = cert("ed-leaf", leaf_k, inter.subject, inter_k, eku=srv, sans=sans, crl_url=CRL_URL)
p256_k = ec.generate_private_key(ec.SECP256R1())
leaf_p256 = cert("ed-leaf-p256", p256_k, inter.subject, inter_k, eku=srv, sans=sans)
ec_root_k = ec.generate_private_key(ec.SECP256R1())
ec_root = cert("EC Root For Ed25519 Leaf", ec_root_k, name("EC Root For Ed25519 Leaf"), ec_root_k, ca=True)
leaf_by_ec_k = ed25519.Ed25519PrivateKey.generate()
leaf_by_ec = cert("ed-leaf-by-ec", leaf_by_ec_k, ec_root.subject, ec_root_k, eku=srv, sans=sans)
for n, c in [("root", root), ("inter", inter), ("leaf", leaf), ("leaf_p256", leaf_p256), ("ec_root", ec_root), ("leaf_by_ec", leaf_by_ec)]:
    save_pem("ed_" + n, c)


def crl(entries):
    b = x509.CertificateRevocationListBuilder().issuer_name(inter.subject).last_update(NOW - 2 * day).next_update(NOW + 5 * day)
    for serial, reason in entries:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(NOW - 4 * day)
            .add_extension(x509.CRLReason(reason), critical=False)
            .build()
        )
    b = b.add_extension(x509.CRLNumber(3), critical=False)
    return b.sign(inter_k, None)


save_der("ed_crl_empty", crl([(x509.random_serial_number(), x509.ReasonFlags.key_compromise)]))
save_der("ed_crl_revoked", crl([(leaf.serial_number, x509.ReasonFlags.key_compromise)]))


def ocsp_resp(status=ocsp.OCSPCertStatus.GOOD, reason=None, revoked_at=None):
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf, issuer=inter, algorithm=hashes.SHA1(), cert_status=status, this_update=NOW - 2 * day, next_update=NOW + 5 * day,
            revocation_time=revoked_at, revocation_reason=reason,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, inter)
        .sign(inter_k, None)
    )


save_der("ed_ocsp_good", ocsp_resp())
save_der("ed_ocsp_revoked", ocsp_resp(ocsp.OCSPCertStatus.REVOKED, x509.ReasonFlags.key_compromise, NOW - 3 * day))
forged = bytearray(ocsp_resp().public_bytes(DER))
forged[-1] ^= 1  # the last byte of the DER is the last byte of the signature
save_der("ed_ocsp_forged", bytes(forged))

# a signature over the content a TLS 1.3 server signs (RFC 8446 section 4.4.3): 64 spaces, the context
# string, a zero byte and the transcript hash (here: SHA-256("transcript"), as if the suite hashed with SHA-256)
import hashlib

content = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00" + hashlib.sha256(b"transcript").digest()
open(D + "ed_leaf_certverify.txt", "w").write(
    "# signed content, then signature, by the key of ed_leaf.pem (hex). See tools/gen_ed25519_fixtures.py.\n"
    + content.hex() + "\n" + leaf_k.sign(content).hex() + "\n"
)
print("wrote ed_* fixtures")
