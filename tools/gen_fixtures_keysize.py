#!/usr/bin/env python3
"""Generates the RSA key-size policy fixtures (tests/data/ks_*.pem) with Python `cryptography`.

Run from the repository root: python3 tools/gen_fixtures_keysize.py
Only public certificates are written; the private keys are discarded.

  ks_root_p256         P-256 root
  ks_leaf_rsa1024      RSA-1024 leaf under ks_root_p256        (must be rejected: leaf key too small)
  ks_leaf_rsa2048      RSA-2048 leaf under ks_root_p256        (control: accepted)
  ks_inter_rsa1024     RSA-1024 intermediate under ks_root_p256
  ks_leaf_by_small_inter  P-256 leaf signed by that intermediate (must be rejected: intermediate key too small)
  ks_root_rsa1024      self-signed RSA-1024 root               (old roots stay usable as trust anchors)
  ks_leaf_old_root     P-256 leaf signed by ks_root_rsa1024    (accepted)
"""
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

D = "tests/data/"
NB = datetime.datetime(2020, 1, 1)
NA = datetime.datetime(2120, 1, 1)

def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def save(n, cert): open(D + n + ".pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))

def build(subject_cn, key, issuer_cn, issuer_key, ca=False, san=None):
    b = (x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NB).not_valid_after(NA))
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    return b.sign(issuer_key, hashes.SHA256())

p256 = lambda: ec.generate_private_key(ec.SECP256R1())
rsa_k = lambda bits: rsa.generate_private_key(65537, bits)

root_k = p256()
save("ks_root_p256", build("KS Root P256", root_k, "KS Root P256", root_k, ca=True))
save("ks_leaf_rsa1024", build("small-rsa-leaf", rsa_k(1024), "KS Root P256", root_k, san="small.test"))
save("ks_leaf_rsa2048", build("big-rsa-leaf", rsa_k(2048), "KS Root P256", root_k, san="big.test"))

inter_k = rsa_k(1024)
save("ks_inter_rsa1024", build("KS Small Intermediate", inter_k, "KS Root P256", root_k, ca=True))
save("ks_leaf_by_small_inter", build("via-small-inter", p256(), "KS Small Intermediate", inter_k, san="via.test"))

old_k = rsa_k(1024)
save("ks_root_rsa1024", build("KS Old Root 1024", old_k, "KS Old Root 1024", old_k, ca=True))
save("ks_leaf_old_root", build("old-root-leaf", p256(), "KS Old Root 1024", old_k, san="old.test"))
print("key-size fixtures written")
