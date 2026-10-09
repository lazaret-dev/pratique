#!/usr/bin/env python3
"""Regenerates src/crypto/test_vectors.rs (RSA / ECDSA signature vectors) with Python `cryptography`.

Run from the repository root: python3 tools/gen_vectors.py
Keys are random, so every run produces a fresh (equally valid) set; commit the output together.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
RSA_MSG=b"tiny_https RSA test message"
EC_MSG=b"tiny_https ECDSA test message"
key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
pub=key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
out=["//! Test vectors generated with an independent implementation (Python `cryptography` / OpenSSL).","#![allow(dead_code)]",""]
def c(name,val): out.append(f'pub const {name}: &str = "{val}";')
out.append(f'pub const RSA_MSG: &[u8] = b"{RSA_MSG.decode()}";')
out.append(f'pub const EC_MSG: &[u8] = b"{EC_MSG.decode()}";')
c("RSA_PUBKEY_DER",pub.hex())
for name,h in (("SHA256",hashes.SHA256()),("SHA384",hashes.SHA384()),("SHA512",hashes.SHA512())):
    c(f"RSA_PKCS1_{name}_SIG", key.sign(RSA_MSG,padding.PKCS1v15(),h).hex())
for name,h in (("SHA256",hashes.SHA256()),("SHA384",hashes.SHA384())):
    c(f"RSA_PSS_{name}_SIG", key.sign(RSA_MSG,padding.PSS(mgf=padding.MGF1(h),salt_length=h.digest_size),h).hex())
for cname,curve in (("P256",ec.SECP256R1()),("P384",ec.SECP384R1())):
    k=ec.generate_private_key(curve)
    pk=k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    c(f"{cname}_PUBKEY",pk.hex())
    for hname,h in (("SHA256",hashes.SHA256()),("SHA384",hashes.SHA384())):
        c(f"{cname}_{hname}_SIG", k.sign(EC_MSG, ec.ECDSA(h)).hex())
open("src/crypto/test_vectors.rs","w").write("\n".join(out)+"\n")
print("wrote", sum(len(l) for l in out), "bytes")
