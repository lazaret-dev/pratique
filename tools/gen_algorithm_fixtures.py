#!/usr/bin/env python3
"""Generates the certificate fixtures of BACKLOG B-33 (ECDSA P-521 and RSASSA-PSS certificate signatures) in
tests/data/alg_* with Python `cryptography`.

Run from the repository root: python3 tools/gen_algorithm_fixtures.py
Keys are random and are not written (the files hold public data only), so running it again produces different,
equally valid files; the tests do not depend on the particular bytes. Validity: 2020 to 2120.

  alg_p521_root                  a P-521 root, self-signed with ECDSA and SHA-512
  alg_p521_inter                 a P-384 intermediate the root signed (ECDSA, SHA-512)
  alg_p521_leaf                  a P-521 leaf the intermediate signed (ECDSA, SHA-384), DNS p521.example.test
  alg_p521_leaf_certverify.txt   the leaf's key over TLS 1.3 CertificateVerify content (scheme 0x0603), and a P-256 key's
  alg_pss_root                   an RSA root, self-signed with PKCS#1 v1.5 and SHA-256
  alg_pss_inter                  an RSA intermediate the root signed with RSASSA-PSS, SHA-256, MGF1-SHA-256, salt 32
  alg_pss_leaf                   a leaf the intermediate signed with RSASSA-PSS, SHA-512, MGF1-SHA-512, salt 64,
                                 DNS pss.example.test
  alg_pss_leaf_sha384            the same with SHA-384 and salt 48
  alg_pss_leaf_salt20            signed with SHA-256 and a salt of 20 bytes: a real signature with parameters the Web PKI
                                 does not allow (Mozilla Root Store Policy 5.1.1), which the library does not read
  alg_pss_leaf_mgf_sha512        SHA-256 with MGF1-SHA-512 (a mask hash unlike the message hash), the same
  alg_pss_crl.der                a CRL of alg_pss_inter, signed with RSASSA-PSS (SHA-256), revoking alg_pss_leaf_sha384
"""
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

D = "tests/data/"
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
nb = dt.datetime(2020, 1, 1)
na = dt.datetime(2120, 1, 1)
NOW = dt.datetime(2026, 9, 15)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pss(h, salt=None, mgf=None):
    return padding.PSS(mgf=padding.MGF1(mgf or h), salt_length=h.digest_size if salt is None else salt)


def cert(subject, key, issuer, issuer_key, alg, ca=False, dns=None, padding_=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
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
    if padding_ is None:
        return b.sign(issuer_key, alg)
    return b.sign(issuer_key, alg, rsa_padding=padding_)


def save(n, c):
    open(D + n + ".pem", "wb").write(c.public_bytes(PEM))


# --- P-521
root_k = ec.generate_private_key(ec.SECP521R1())
inter_k = ec.generate_private_key(ec.SECP384R1())
leaf_k = ec.generate_private_key(ec.SECP521R1())
save("alg_p521_root", cert("P-521 Test Root", root_k, "P-521 Test Root", root_k, hashes.SHA512(), ca=True))
save("alg_p521_inter", cert("P-384 Test Intermediate", inter_k, "P-521 Test Root", root_k, hashes.SHA512(), ca=True))
save("alg_p521_leaf", cert("p521.example.test", leaf_k, "P-384 Test Intermediate", inter_k, hashes.SHA384(), dns="p521.example.test"))
content = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + bytes(range(48))
sig = leaf_k.sign(content, ec.ECDSA(hashes.SHA512()))
p256_k = ec.generate_private_key(ec.SECP256R1())
p256_pub = p256_k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
p256_sig = p256_k.sign(content, ec.ECDSA(hashes.SHA512()))
with open(D + "alg_p521_leaf_certverify.txt", "w") as f:
    f.write("# content, the P-521 leaf's signature (SHA-512), a P-256 public key and its signature of the same (SHA-512)\n")
    f.write(content.hex() + "\n" + sig.hex() + "\n" + p256_pub.hex() + "\n" + p256_sig.hex() + "\n")

# --- RSASSA-PSS
proot_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pinter_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pleaf_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save("alg_pss_root", cert("PSS Test Root", proot_k, "PSS Test Root", proot_k, hashes.SHA256(), ca=True))
save("alg_pss_inter", cert("PSS Test Intermediate", pinter_k, "PSS Test Root", proot_k, hashes.SHA256(), ca=True, padding_=pss(hashes.SHA256())))
I = "PSS Test Intermediate"
save("alg_pss_leaf", cert("pss.example.test", pleaf_k, I, pinter_k, hashes.SHA512(), dns="pss.example.test", padding_=pss(hashes.SHA512())))
leaf384 = cert("pss.example.test", pleaf_k, I, pinter_k, hashes.SHA384(), dns="pss.example.test", padding_=pss(hashes.SHA384()))
save("alg_pss_leaf_sha384", leaf384)
save("alg_pss_leaf_salt20", cert("pss.example.test", pleaf_k, I, pinter_k, hashes.SHA256(), dns="pss.example.test", padding_=pss(hashes.SHA256(), salt=20)))
save("alg_pss_leaf_mgf_sha512", cert("pss.example.test", pleaf_k, I, pinter_k, hashes.SHA256(), dns="pss.example.test", padding_=pss(hashes.SHA256(), mgf=hashes.SHA512())))
crl = (
    x509.CertificateRevocationListBuilder()
    .issuer_name(name(I))
    .last_update(NOW - dt.timedelta(days=2))
    .next_update(NOW + dt.timedelta(days=5))
    .add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(leaf384.serial_number).revocation_date(NOW - dt.timedelta(days=3)).build())
    .sign(pinter_k, hashes.SHA256(), rsa_padding=pss(hashes.SHA256()))
)
open(D + "alg_pss_crl.der", "wb").write(crl.public_bytes(DER))
print("wrote tests/data/alg_*")
