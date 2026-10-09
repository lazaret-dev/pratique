#!/usr/bin/env python3
"""Regenerates the X.509 fixtures in tests/data/*.pem with Python `cryptography`.

Run from the repository root: python3 tools/gen_fixtures.py
Keys are random; the files hold public certificates only (no private keys are written).
"""
import datetime, ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

D="tests/data/"
nb=datetime.datetime(2020,1,1)
na=datetime.datetime(2120,1,1)
def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def save(n,cert): open(D+n+".pem","wb").write(cert.public_bytes(serialization.Encoding.PEM))
def build(subject_cn, key, issuer_cn, issuer_key, h, ca=False, pathlen=None, sans=None, nb_=nb, na_=na, nc=None, eku=True):
    b=(x509.CertificateBuilder().subject_name(name(subject_cn)).issuer_name(name(issuer_cn))
       .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(nb_).not_valid_after(na_))
    b=b.add_extension(x509.BasicConstraints(ca=ca,path_length=pathlen),critical=True)
    if ca:
        b=b.add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
    else:
        b=b.add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),critical=True)
        if eku: b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
    if sans: b=b.add_extension(x509.SubjectAlternativeName(sans),critical=False)
    if nc: b=b.add_extension(nc,critical=True)
    b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
    return b.sign(issuer_key,h)
rsa_key=lambda: rsa.generate_private_key(65537,2048)
p256=lambda: ec.generate_private_key(ec.SECP256R1())
p384=lambda: ec.generate_private_key(ec.SECP384R1())
dns=x509.DNSName

root_rsa_k=rsa_key(); root_rsa=build("Test Root RSA",root_rsa_k,"Test Root RSA",root_rsa_k,hashes.SHA256(),ca=True); save("root_rsa",root_rsa)
inter_k=p256(); inter=build("Test Intermediate P256",inter_k,"Test Root RSA",root_rsa_k,hashes.SHA256(),ca=True,pathlen=0); save("inter_p256",inter)
leaf_k=p384()
leaf=build("leaf",leaf_k,"Test Intermediate P256",inter_k,hashes.SHA256(),sans=[dns("example.test"),dns("*.wild.test"),x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]); save("leaf_p384",leaf)
# expired leaf
exp=build("expired",p384(),"Test Intermediate P256",inter_k,hashes.SHA256(),sans=[dns("expired.test")],nb_=datetime.datetime(2020,1,1),na_=datetime.datetime(2021,1,1)); save("leaf_expired",exp)
# p384 root -> rsa leaf
root384_k=p384(); root384=build("Test Root P384",root384_k,"Test Root P384",root384_k,hashes.SHA384(),ca=True); save("root_p384",root384)
save("leaf_rsa",build("rsaleaf",rsa_key(),"Test Root P384",root384_k,hashes.SHA384(),sans=[dns("rsa.test")]))
# leaf issued by a non-CA leaf
save("leaf_by_leaf",build("byleaf",p256(),"leaf",leaf_k,hashes.SHA384(),sans=[dns("byleaf.test")]))
# path length: inter(pathlen 0) -> inter2 -> leaf
inter2_k=p256(); save("inter2_p256",build("Test Intermediate 2",inter2_k,"Test Intermediate P256",inter_k,hashes.SHA256(),ca=True))
save("leaf_deep",build("deep",p256(),"Test Intermediate 2",inter2_k,hashes.SHA256(),sans=[dns("deep.test")]))
# name constraints
nc=x509.NameConstraints(permitted_subtrees=[dns("constrained.test")],excluded_subtrees=None)
ink=p256(); save("inter_nc",build("Test Constrained",ink,"Test Root RSA",root_rsa_k,hashes.SHA256(),ca=True,nc=nc))
save("leaf_nc_ok",build("ncok",p256(),"Test Constrained",ink,hashes.SHA256(),sans=[dns("a.constrained.test")]))
save("leaf_nc_bad",build("ncbad",p256(),"Test Constrained",ink,hashes.SHA256(),sans=[dns("outside.test")]))
print("fixtures written")
