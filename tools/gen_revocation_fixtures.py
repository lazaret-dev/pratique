#!/usr/bin/env python3
"""Regenerates the revocation fixtures in tests/data/rev_* (certificates as PEM, OCSP responses and CRLs
as DER) with Python `cryptography`.

Run from the repository root: python3 tools/gen_revocation_fixtures.py
Keys are random and are not written; the files hold public data only. Every window is built around
NOW = 2026-09-15 00:00:00 UTC (1789430400), the clock the unit tests use.
"""
import datetime as dt
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

D = "tests/data/"
DER = serialization.Encoding.DER
PEM = serialization.Encoding.PEM
nb = dt.datetime(2020, 1, 1)
na = dt.datetime(2120, 1, 1)
NOW = dt.datetime(2026, 9, 15)
day = dt.timedelta(days=1)
CRL_URL = "http://crl.example.test/inter.crl"

def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def save_pem(n, c): open(D + n + ".pem", "wb").write(c.public_bytes(PEM))
def save_der(n, o): open(D + n + ".der", "wb").write(o.public_bytes(DER) if hasattr(o, "public_bytes") else o)
p256 = lambda: ec.generate_private_key(ec.SECP256R1())

def cert(subject, key, issuer_name, issuer_key, ca=False, pathlen=None, eku=None, sans=None, crl_url=None, must_staple=False, h=hashes.SHA256()):
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na))
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
    if eku: b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if sans: b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if crl_url:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)]), critical=False)
    if must_staple:
        b = b.add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
    return b.sign(issuer_key, h)

# ---- the PKI: RSA root -> P-256 intermediate -> P-256 leaves; a delegated responder; an unrelated CA
root_k = rsa.generate_private_key(65537, 2048)
root = cert("Rev Test Root", root_k, name("Rev Test Root"), root_k, ca=True)
inter_k = p256()
inter = cert("Rev Test Intermediate", inter_k, root.subject, root_k, ca=True, pathlen=0)
dns = x509.DNSName
srv = [ExtendedKeyUsageOID.SERVER_AUTH]
leaf_k = p256()
leaf = cert("revleaf", leaf_k, inter.subject, inter_k, eku=srv, sans=[dns("example.test")], crl_url=CRL_URL)
ms_k = p256()
leaf_ms = cert("revleaf-ms", ms_k, inter.subject, inter_k, eku=srv, sans=[dns("example.test")], crl_url=CRL_URL, must_staple=True)
resp_k = p256()
responder = cert("Rev Test Responder", resp_k, inter.subject, inter_k, eku=[ExtendedKeyUsageOID.OCSP_SIGNING])
resp_noeku_k = p256()
responder_noeku = cert("Rev Test Responder no EKU", resp_noeku_k, inter.subject, inter_k, eku=srv)
other_k = p256()
other = cert("Other CA", other_k, name("Other CA"), other_k, ca=True)

for n, c in [("root", root), ("inter", inter), ("leaf", leaf), ("leaf_ms", leaf_ms), ("responder", responder), ("responder_noeku", responder_noeku), ("other", other)]:
    save_pem("rev_" + n, c)

# ---- OCSP responses about `leaf` (issuer = inter), unless a name says otherwise
def ocsp_resp(subject, issuer, signer_key, signer_cert=None, certs=(), status=ocsp.OCSPCertStatus.GOOD, this=NOW - 2 * day, nxt=NOW + 5 * day,
              algo=hashes.SHA1(), reason=None, revoked_at=None, by_hash=False, sign_hash=hashes.SHA256()):
    b = ocsp.OCSPResponseBuilder().add_response(cert=subject, issuer=issuer, algorithm=algo, cert_status=status, this_update=this, next_update=nxt,
                                                revocation_time=revoked_at, revocation_reason=reason)
    rid = signer_cert if signer_cert is not None else issuer
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH if by_hash else ocsp.OCSPResponderEncoding.NAME, rid)
    if certs: b = b.certificates(list(certs))
    return b.sign(signer_key, sign_hash)

save_der("rev_ocsp_good", ocsp_resp(leaf, inter, inter_k))
save_der("rev_ocsp_good_sha256", ocsp_resp(leaf, inter, inter_k, algo=hashes.SHA256()))
save_der("rev_ocsp_good_byhash", ocsp_resp(leaf, inter, inter_k, by_hash=True))
save_der("rev_ocsp_good_nonext", ocsp_resp(leaf, inter, inter_k, nxt=None))
save_der("rev_ocsp_nonext_old", ocsp_resp(leaf, inter, inter_k, nxt=None, this=NOW - 30 * day))
save_der("rev_ocsp_revoked", ocsp_resp(leaf, inter, inter_k, status=ocsp.OCSPCertStatus.REVOKED, reason=x509.ReasonFlags.key_compromise, revoked_at=NOW - 3 * day))
save_der("rev_ocsp_unknown", ocsp_resp(leaf, inter, inter_k, status=ocsp.OCSPCertStatus.UNKNOWN))
save_der("rev_ocsp_good_delegated", ocsp_resp(leaf, inter, resp_k, signer_cert=responder, certs=[responder]))
save_der("rev_ocsp_good_delegated_byhash", ocsp_resp(leaf, inter, resp_k, signer_cert=responder, certs=[responder], by_hash=True))
save_der("rev_ocsp_delegated_nocert", ocsp_resp(leaf, inter, resp_k, signer_cert=responder))
save_der("rev_ocsp_delegated_noeku", ocsp_resp(leaf, inter, resp_noeku_k, signer_cert=responder_noeku, certs=[responder_noeku]))
save_der("rev_ocsp_expired", ocsp_resp(leaf, inter, inter_k, this=NOW - 10 * day, nxt=NOW - 3 * day))
save_der("rev_ocsp_future", ocsp_resp(leaf, inter, inter_k, this=NOW + 60 * day, nxt=NOW + 67 * day))
save_der("rev_ocsp_other_cert", ocsp_resp(leaf_ms, inter, inter_k))
save_der("rev_ocsp_ms_good", ocsp_resp(leaf_ms, inter, inter_k))
# a good response whose signature has been damaged (the last byte of the DER is the signature's)
forged = bytearray(ocsp_resp(leaf, inter, inter_k).public_bytes(DER)); forged[-1] ^= 0x01
save_der("rev_ocsp_forged", bytes(forged))
# a response from another CA about a certificate with the same serial number would not match its issuer hashes
save_der("rev_ocsp_wrong_issuer", ocsp_resp(leaf, other, other_k))
save_der("rev_ocsp_unauthorized", ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED))
# stapled for the intermediate (per-entry staple), issuer = root
save_der("rev_ocsp_inter_revoked", ocsp_resp(inter, root, root_k, status=ocsp.OCSPCertStatus.REVOKED, reason=x509.ReasonFlags.ca_compromise, revoked_at=NOW - day))
save_der("rev_ocsp_inter_good", ocsp_resp(inter, root, root_k))

# ---- CRLs for `inter` (issuer = inter)
def crl(issuer_cert, key, entries=(), this=NOW - 2 * day, nxt=NOW + 5 * day, idp=None, extra=(), issuer_name=None):
    b = x509.CertificateRevocationListBuilder().issuer_name(issuer_name or issuer_cert.subject).last_update(this)
    if nxt is not None:
        b = b.next_update(nxt)
    for serial, reason in entries:
        eb = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW - 4 * day)
        if reason is not None: eb = eb.add_extension(x509.CRLReason(reason), critical=False)
        b = b.add_revoked_certificate(eb.build())
    b = b.add_extension(x509.CRLNumber(7), critical=False)
    if idp is not None: b = b.add_extension(idp, critical=True)
    for ext, crit in extra: b = b.add_extension(ext, critical=crit)
    return b.sign(key, hashes.SHA256())

def idp(full_name=None, only_user=False, only_ca=False, only_some=None, indirect=False, only_attr=False):
    fn = [x509.UniformResourceIdentifier(full_name)] if full_name else None
    return x509.IssuingDistributionPoint(full_name=fn, relative_name=None, only_contains_user_certs=only_user, only_contains_ca_certs=only_ca,
                                         only_some_reasons=only_some, indirect_crl=indirect, only_contains_attribute_certs=only_attr)

other_serial = x509.random_serial_number()
save_der("rev_crl_empty", crl(inter, inter_k, entries=[(other_serial, None)]))
save_der("rev_crl_revoked", crl(inter, inter_k, entries=[(other_serial, None), (leaf.serial_number, x509.ReasonFlags.key_compromise)]))
save_der("rev_crl_revoked_hold", crl(inter, inter_k, entries=[(leaf.serial_number, x509.ReasonFlags.certificate_hold)]))
save_der("rev_crl_revoked_removefromcrl", crl(inter, inter_k, entries=[(leaf.serial_number, x509.ReasonFlags.remove_from_crl)]))
save_der("rev_crl_stale", crl(inter, inter_k, this=NOW - 20 * day, nxt=NOW - 10 * day))
save_der("rev_crl_future", crl(inter, inter_k, this=NOW + 30 * day, nxt=NOW + 37 * day))
save_der("rev_crl_idp_dp", crl(inter, inter_k, idp=idp(full_name=CRL_URL)))
save_der("rev_crl_idp_dp_revoked", crl(inter, inter_k, entries=[(leaf.serial_number, None)], idp=idp(full_name=CRL_URL)))
save_der("rev_crl_idp_other_dp", crl(inter, inter_k, entries=[(leaf.serial_number, None)], idp=idp(full_name="http://crl.example.test/other.crl")))
save_der("rev_crl_idp_ca_only", crl(inter, inter_k, entries=[(leaf.serial_number, None)], idp=idp(only_ca=True)))
save_der("rev_crl_idp_user_only", crl(inter, inter_k, entries=[(leaf.serial_number, None)], idp=idp(only_user=True)))
save_der("rev_crl_idp_some_reasons", crl(inter, inter_k, entries=[(leaf.serial_number, None)], idp=idp(only_some=frozenset([x509.ReasonFlags.key_compromise]))))
save_der("rev_crl_other_issuer", crl(other, other_k))
save_der("rev_crl_forged", crl(inter, other_k, entries=[(leaf.serial_number, None)]))  # inter's name, another key
save_der("rev_crl_delta", crl(inter, inter_k, extra=[(x509.DeltaCRLIndicator(6), True)]))
save_der("rev_crl_unknown_critical", crl(inter, inter_k, extra=[(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), True)]))
# a CRL signed by the root listing the intermediate
save_der("rev_crl_root_revokes_inter", crl(root, root_k, entries=[(inter.serial_number, x509.ReasonFlags.ca_compromise)]))
save_der("rev_crl_root_empty", crl(root, root_k))
print("revocation fixtures written")
