#!/usr/bin/env python3
"""Generates the fixtures of BACKLOG B-34 for name comparison in chain building, tests/data/nm_*, with Python
`cryptography`: certificates whose issuer name is written differently from their issuer's subject name.

Run from the repository root: python3 tools/gen_name_fixtures.py
Keys are random and are not written. Validity: 2020 to 2120.

  nm_root              CN=Name Test Root, O=Example Org, C=US (all PrintableString), self-signed
  nm_inter             issued by nm_root, but its issuer is written " name test root ", "EXAMPLE   ORG" (UTF8String),
                       C=US: the same name under RFC 5280 section 7.1 (and OpenSSL), not the same bytes
  nm_leaf              issued by nm_inter (subject CN=Name Test Intermediate, UTF8String), its issuer written as
                       CN=NAME TEST INTERMEDIATE in a BMPString; DNS name.example.test
  nm_inter_u           issued by nm_root (issuer byte for byte), subject CN=Über Intermediate (UTF8String)
  nm_leaf_u_ascii      issued by nm_inter_u, issuer CN=Über INTERMEDIATE: only ASCII letters differ, the same name
  nm_leaf_u_lower      issued by nm_inter_u, issuer CN=über intermediate: Ü and ü differ, and only ASCII is folded,
                       so not the same name (OpenSSL refuses it too)
  nm_root_twin         a root with nm_root's subject (the same bytes) and another key
"""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

D = "tests/data/"
PEM = serialization.Encoding.PEM
nb = dt.datetime(2020, 1, 1)
na = dt.datetime(2120, 1, 1)


def attr(oid, value, t):
    return x509.NameAttribute(oid, value, _type=t)


P, U, B = _ASN1Type.PrintableString, _ASN1Type.UTF8String, _ASN1Type.BMPString


def cert(subject, key, issuer, issuer_key, ca, dns=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def save(n, c):
    open(D + n + ".pem", "wb").write(c.public_bytes(PEM))


root_k, inter_k, leaf_k, inter_u_k, twin_k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(5))
root_name = x509.Name([attr(NameOID.COUNTRY_NAME, "US", P), attr(NameOID.ORGANIZATION_NAME, "Example Org", P), attr(NameOID.COMMON_NAME, "Name Test Root", P)])
root_as_written = x509.Name([attr(NameOID.COUNTRY_NAME, "US", P), attr(NameOID.ORGANIZATION_NAME, "EXAMPLE   ORG", U), attr(NameOID.COMMON_NAME, " name test root ", U)])
inter_name = x509.Name([attr(NameOID.COMMON_NAME, "Name Test Intermediate", U)])
inter_as_written = x509.Name([attr(NameOID.COMMON_NAME, "NAME TEST INTERMEDIATE", B)])
leaf_name = x509.Name([attr(NameOID.COMMON_NAME, "name.example.test", U)])
inter_u_name = x509.Name([attr(NameOID.COMMON_NAME, "Über Intermediate", U)])

save("nm_root", cert(root_name, root_k, root_name, root_k, True))
save("nm_inter", cert(inter_name, inter_k, root_as_written, root_k, True))
save("nm_leaf", cert(leaf_name, leaf_k, inter_as_written, inter_k, False, "name.example.test"))
save("nm_inter_u", cert(inter_u_name, inter_u_k, root_name, root_k, True))
save("nm_leaf_u_ascii", cert(leaf_name, leaf_k, x509.Name([attr(NameOID.COMMON_NAME, "Über INTERMEDIATE", U)]), inter_u_k, False, "name.example.test"))
save("nm_leaf_u_lower", cert(leaf_name, leaf_k, x509.Name([attr(NameOID.COMMON_NAME, "über intermediate", U)]), inter_u_k, False, "name.example.test"))
save("nm_root_twin", cert(root_name, twin_k, root_name, twin_k, True))
print("wrote tests/data/nm_*")
