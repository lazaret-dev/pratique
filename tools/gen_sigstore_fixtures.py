#!/usr/bin/env python3
"""Generates tests/data/sigstore/synthetic.json: Sigstore bundles from a throwaway Sigstore of our own, for the
paths the real attestations in tests/data/sigstore do not reach (RFC 3161 time stamps, a log that signs with
Ed25519 and gives proofs only, certificates of every key type, identities from e-mail and username) and for
the failures a real signer never produces (an entry body that binds another signature, a checkpoint from
another key, a time stamp from a rogue authority, ...). Everything that has to be signed is signed here, so
that the tests can check what is rejected and why; the Rust verifier is not told anything but the bytes.

Needs Python `cryptography` and `openssl` 3.x (for RFC 3161 tokens, which are made with `openssl cms` so that
the time is the one this script chooses). Run from the repository root:

    python3 tools/gen_sigstore_fixtures.py

The keys are made on every run, so rerunning changes the file; only public data is written. The file is one
JSON object:

  artifact      Base64 of the bytes the statements are about
  roots         trusted roots by name (`base` is the one most cases use)
  cases         [{name, why, root, algorithm?, bundle, expect, facts?}]

`expect` is `ok` or the name of the variant of pratique::sigstore::Error the bundle must be refused with;
`facts` for an `ok` says what must come out. tests/sigstore_synthetic.rs reads it.
"""
import base64
import copy
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

OUT = "tests/data/sigstore/synthetic.json"
UTC = datetime.timezone.utc
W = tempfile.mkdtemp(prefix="sigstorefix")


def ts(y, mo, d, h=0, mi=0, s=0):
    return int(datetime.datetime(y, mo, d, h, mi, s, tzinfo=UTC).timestamp())


def rfc3339(t):
    return datetime.datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


T0 = ts(2026, 3, 10, 12, 0, 0)  # when the artifact is signed
PAYLOAD_TYPE = "application/vnd.in-toto+json"

b64 = lambda b: base64.b64encode(b).decode()
sha256 = lambda b: hashlib.sha256(b).digest()
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
spki_of = lambda pub: pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
pem_of_cert = lambda c: c.public_bytes(serialization.Encoding.PEM)
der_of_cert = lambda c: c.public_bytes(serialization.Encoding.DER)

# ------------------------------------------------------------------------------------------ DER helpers


def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + length(len(content)) + content


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * a[0] + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))


def gentime(t):
    return tlv(0x18, datetime.datetime.fromtimestamp(t, UTC).strftime("%Y%m%d%H%M%SZ").encode())


def utf8(text):
    return tlv(0x0C, text.encode())


# ------------------------------------------------------------------------------------------ keys and signing


def new_key(kind):
    return {
        "p256": lambda: ec.generate_private_key(ec.SECP256R1()),
        "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
        "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ed": lambda: ed25519.Ed25519PrivateKey.generate(),
    }[kind]()


def sign(key, message):
    """The signature a Sigstore client makes: ECDSA with the curve's hash, PKCS#1 v1.5 over SHA-256 for RSA."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(message, ec.ECDSA(hashes.SHA384() if key.curve.name == "secp384r1" else hashes.SHA256()))
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return key.sign(message)


def run(*args):
    p = subprocess.run([str(a) for a in args], cwd=W, capture_output=True)
    if p.returncode:
        sys.exit(f"{' '.join(map(str, args))}\n{p.stderr.decode()}")


# ------------------------------------------------------------------------------------------ certificates

FULCIO_ARC = "1.3.6.1.4.1.57264.1."


class CA:
    def __init__(self, cn, key=None, issuer=None, nb=ts(2026, 1, 1), na=ts(2036, 1, 1), eku=None, eku_critical=False):
        self.key = key or new_key("p256")
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        self.issuer = issuer
        ikey = issuer.key if issuer else self.key
        b = (
            x509.CertificateBuilder()
            .subject_name(self.name)
            .issuer_name(issuer.name if issuer else self.name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.fromtimestamp(nb, UTC))
            .not_valid_after(datetime.datetime.fromtimestamp(na, UTC))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None if not issuer else 0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
        )
        if issuer:
            b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False)
        self.cert = b.sign(ikey, hashes.SHA256())

    def chain(self):
        """This CA's certificate and those above it, as a Sigstore trusted root lists them: nearest first."""
        return [self.cert] + (self.issuer.chain() if self.issuer else [])


SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"


def issue(ca, key, *, san, exts=(), eku=ExtendedKeyUsageOID.CODE_SIGNING, nb=T0 - 30, na=T0 + 570, subject=None, san_critical=True, eku_critical=False, scts="default", sct_value=None):
    """A Fulcio-style leaf: short-lived, no subject, the identity in the subjectAltName, and (as Fulcio does) the
    signed certificate timestamps of CT logs embedded, by default one from `ct_log` signed a quarter second after
    the notBefore. `scts` is None for none, or a list of options for `CtLog.sct` (see there); `sct_value` replaces
    the extension's value outright."""
    serial = x509.random_serial_number()
    pre = leaf_builder(ca, key, serial, san=san, exts=exts, eku=eku, nb=nb, na=na, subject=subject, san_critical=san_critical, eku_critical=eku_critical).sign(ca.key, hashes.SHA256())
    if scts is None and sct_value is None:
        return pre
    tbs = pre.tbs_certificate_bytes  # the precertificate's TBSCertificate: the leaf without the SCT list
    if sct_value is None:
        made = [(o.pop("log", None) or ct_log).sct(ca, tbs, nb * 1000 + 250, **o) for o in [dict(x) for x in (scts if scts != "default" else [{}])]]
        inner = b"".join(len(m).to_bytes(2, "big") + m for m in made)
        sct_value = tlv(0x04, len(inner).to_bytes(2, "big") + inner)
    b = leaf_builder(ca, key, serial, san=san, exts=exts, eku=eku, nb=nb, na=na, subject=subject, san_critical=san_critical, eku_critical=eku_critical)
    leaf = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(SCT_LIST), sct_value), critical=False).sign(ca.key, hashes.SHA256())
    assert leaf.tbs_precertificate_bytes == tbs, "the precertificate is the leaf without its SCT list"
    return leaf


def leaf_builder(ca, key, serial, *, san, exts, eku, nb, na, subject, san_critical, eku_critical):
    b = (
        x509.CertificateBuilder()
        .subject_name(subject or x509.Name([]))
        .issuer_name(ca.name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime.fromtimestamp(nb, UTC))
        .not_valid_after(datetime.datetime.fromtimestamp(na, UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=san_critical)
    )
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=eku_critical)
    for o, value in exts:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(o), value), critical=False)
    return b


def fulcio_exts(**v):
    """The Fulcio extensions: .1 to .6 hold raw text, the later ones a DER UTF8String."""
    out = []
    for n, text in sorted(v.items(), key=lambda kv: int(kv[0][1:])):
        n = int(n[1:])
        out.append((FULCIO_ARC + str(n), text.encode() if n <= 6 else utf8(text)))
    return out


GITHUB = "https://token.actions.githubusercontent.com"
WORKFLOW = "https://github.com/example/widget/.github/workflows/release.yml@refs/tags/v1.2.3"
GH_EXTS = dict(
    x1=GITHUB, x8=GITHUB,
    x9=WORKFLOW, x10="1111111111111111111111111111111111111111",
    x11="github-hosted",
    x12="https://github.com/example/widget", x13="2222222222222222222222222222222222222222", x14="refs/tags/v1.2.3",
    x15="424242", x16="https://github.com/example", x17="777",
    x18=WORKFLOW, x19="3333333333333333333333333333333333333333",
    x20="push", x21="https://github.com/example/widget/actions/runs/99/attempts/1", x22="public",
)

# ------------------------------------------------------------------------------------------ the world

fulcio_root = CA("synthetic Sigstore root")
fulcio_int = CA("synthetic Sigstore intermediate", issuer=fulcio_root)
rogue_root = CA("rogue root")
rogue_int = CA("rogue intermediate", issuer=rogue_root)
tsa_root = CA("synthetic TSA root")
tsa_int = CA("synthetic TSA intermediate", issuer=tsa_root)
rogue_tsa_root = CA("rogue TSA root")

TSA_NAME = "synthetic-tsa"


def tsa_cert(issuer, cn=TSA_NAME, eku=ExtendedKeyUsageOID.TIME_STAMPING, nb=ts(2026, 1, 1), na=ts(2036, 1, 1)):
    key = new_key("p256")
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer.name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.fromtimestamp(nb, UTC))
        .not_valid_after(datetime.datetime.fromtimestamp(na, UTC))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
    )
    return key, b.sign(issuer.key, hashes.SHA256())


tsa_key, tsa_leaf = tsa_cert(tsa_int)
rogue_tsa_key, rogue_tsa_leaf = tsa_cert(rogue_tsa_root, cn="rogue-tsa")
codesign_key = new_key("p256")  # for the case of a Fulcio leaf pretending to be a time-stamp authority


class Log:
    """A transparency log: a key, a name, and trees it can give checkpoints for."""

    def __init__(self, kind, base_url, tree_id):
        self.kind = kind
        self.key = new_key("p256" if kind == "ecdsa" else "ed")
        self.base_url = base_url
        self.host = base_url.split("://")[1]
        self.origin = f"{self.host} - {tree_id}"
        self.spki = spki_of(self.key.public_key())
        if kind == "ecdsa":
            self.log_id = sha256(self.spki)  # Rekor v1: the SHA-256 of the key
            self.hint = sha256(self.spki)[:4]  # and the checkpoint signature's key hash
        else:
            raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.log_id = sha256(self.spki)
            self.hint = sha256(self.host.encode() + b"\n" + b"\x01" + raw)[:4]  # c2sp.org/signed-note

    def sign(self, data):
        return sign(self.key, data)

    def checkpoint(self, size, root, origin=None, signer=None):
        text = f"{origin or self.origin}\n{size}\n{b64(root)}\n".encode()
        sig = (signer or self).sign(text)
        return text + b"\n" + f"— {self.host} ".encode() + b64(self.hint + sig).encode() + b"\n"

    def set(self, body, integrated_time, log_index, signer=None):
        payload = canon({"body": b64(body), "integratedTime": integrated_time, "logID": self.log_id.hex(), "logIndex": log_index})
        return (signer or self).sign(payload)

    def root_entry(self, start=ts(2026, 1, 1), end=None):
        vf = {"start": rfc3339(start)}
        if end:
            vf["end"] = rfc3339(end)
        return {
            "baseUrl": self.base_url,
            "hashAlgorithm": "SHA2_256",
            "publicKey": {"rawBytes": b64(self.spki), "keyDetails": "PKIX_ECDSA_P256_SHA_256" if self.kind == "ecdsa" else "PKIX_ED25519", "validFor": vf},
            "logId": {"keyId": b64(self.log_id)},
        }


class CtLog:
    """A Certificate Transparency log (RFC 6962): a key, and the SCTs it signs for precertificates."""

    DETAILS = {"p256": ("PKIX_ECDSA_P256_SHA_256", (4, 3)), "p384": ("PKIX_ECDSA_P384_SHA_384", (5, 3)), "rsa": ("PKIX_RSA_PKCS1V15_2048_SHA256", (4, 1))}

    def __init__(self, base_url, kind="p256"):
        self.kind, self.base_url = kind, base_url
        self.key = new_key(kind)
        self.spki = spki_of(self.key.public_key())
        self.log_id = sha256(self.spki)

    def sct(self, ca, tbs, at_ms, *, version=0, log_id=None, signer=None, algs=None, written_ms=None, signed_tbs=None, issuer_key=None, ext=b""):
        """An SCT for the precertificate `tbs` that `ca` issues, signed at `at_ms`; the options make it wrong: another
        version byte, log id, signing key or algorithms, a time other than the signed one, signed over another TBS
        or another issuer's key."""
        ikh = sha256(spki_of((issuer_key or ca.key).public_key()))
        t = signed_tbs if signed_tbs is not None else tbs
        data = b"\x00\x00" + at_ms.to_bytes(8, "big") + b"\x00\x01" + ikh + len(t).to_bytes(3, "big") + t + len(ext).to_bytes(2, "big") + ext
        sig = sign(signer or self.key, data)
        algs = algs or self.DETAILS[self.kind][1]
        return (
            bytes([version]) + (log_id or self.log_id) + (written_ms if written_ms is not None else at_ms).to_bytes(8, "big")
            + len(ext).to_bytes(2, "big") + ext + bytes(algs) + len(sig).to_bytes(2, "big") + sig
        )

    def root_entry(self, start=ts(2026, 1, 1), end=None):
        vf = {"start": rfc3339(start)}
        if end:
            vf["end"] = rfc3339(end)
        return {
            "baseUrl": self.base_url,
            "hashAlgorithm": "SHA2_256",
            "publicKey": {"rawBytes": b64(self.spki), "keyDetails": self.DETAILS[self.kind][0], "validFor": vf},
            "logId": {"keyId": b64(self.log_id)},
        }


ct_log = CtLog("https://ctfe.synthetic.test/2026")
ct_log_rsa = CtLog("https://ct2.synthetic.test", "rsa")
unlisted_ct_log = CtLog("https://ct.elsewhere.test")

log_a = Log("ecdsa", "https://rekor.synthetic.test", 1234567890123456789)
log_b = Log("ed25519", "https://log2.synthetic.test", 42)
rogue_log = Log("ecdsa", "https://rekor.synthetic.test", 1234567890123456789)  # same name, another key

# ------------------------------------------------------------------------------------------ Merkle trees


def leaf_hash(rec):
    return sha256(b"\x00" + rec)


def node_hash(l, r):
    return sha256(b"\x01" + l + r)


def lpt(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = lpt(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def path(m, leaves):
    if len(leaves) == 1:
        return []
    k = lpt(len(leaves))
    if m < k:
        return path(m, leaves[:k]) + [mth(leaves[k:])]
    return path(m - k, leaves[k:]) + [mth(leaves[:k])]


def tree_with(body, size, index, seed):
    """The leaf hashes of a tree of `size` leaves with `body` at `index` (the others are made up)."""
    leaves = [leaf_hash(b"synthetic filler %s %d" % (seed.encode(), i)) for i in range(size)]
    leaves[index] = leaf_hash(body)
    return leaves


# ------------------------------------------------------------------------------------------ statements, envelopes, bodies

ARTIFACT = b"tiny_https synthetic sigstore artifact\n"
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


def statement(subjects=None, ptype="https://slsa.dev/provenance/v1", stype="https://in-toto.io/Statement/v1", predicate=None, raw=None):
    if raw is not None:
        return raw
    s = {
        "_type": stype,
        "subject": subjects if subjects is not None else [{"name": "widget-1.2.3.tgz", "digest": {"sha256": DIGEST}}],
        "predicateType": ptype,
        "predicate": predicate if predicate is not None else {"buildDefinition": {"buildType": "https://example.test/build/v1"}},
    }
    return canon(s)


def pae(ptype, payload):
    return b"DSSEv1 %d %s %d " % (len(ptype), ptype.encode(), len(payload)) + payload


def body_dsse(payload_type, payload, sig, verifier_pem, hash_override=None):
    ph = hash_override or hashlib.sha256(payload).hexdigest()
    env = canon({"payloadType": payload_type, "payload": b64(payload), "signatures": [{"sig": b64(sig)}]})
    return canon({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "envelopeHash": {"algorithm": "sha256", "value": hashlib.sha256(env).hexdigest()},
            "payloadHash": {"algorithm": "sha256", "value": ph},
            "signatures": [{"signature": b64(sig), "verifier": b64(verifier_pem)}],
        },
    })


def body_intoto(payload_type, payload, sig, verifier_pem, hash_override=None):
    ph = hash_override or hashlib.sha256(payload).hexdigest()
    return canon({
        "apiVersion": "0.0.2",
        "kind": "intoto",
        "spec": {
            "content": {
                "envelope": {"payloadType": payload_type, "signatures": [{"keyid": "", "publicKey": b64(verifier_pem), "sig": b64(b64(sig).encode())}]},
                "hash": {"algorithm": "sha256", "value": "0" * 64},
                "payloadHash": {"algorithm": "sha256", "value": ph},
            }
        },
    })


# ------------------------------------------------------------------------------------------ time stamps


def tst_info(digest, gen_time):
    imprint = tlv(0x30, tlv(0x30, oid("2.16.840.1.101.3.4.2.1") + tlv(0x05, b"")) + tlv(0x04, digest))
    return tlv(0x30, integer(1) + oid("1.2.3.4.1") + imprint + integer(0x0A0B0C) + gentime(gen_time))


_tsn = [0]


def stamp(message, gen_time, key=None, leaf=None, extra=(), response=True, status=0, imprint_of=None):
    """A time-stamp response (or the bare token) over SHA-256 of `message`, with the time this script says.
    `extra` are the certificates that go in the token besides the signer's."""
    key, leaf = key or tsa_key, leaf or tsa_leaf
    _tsn[0] += 1
    n = _tsn[0]
    with open(os.path.join(W, f"tst{n}.der"), "wb") as f:
        f.write(tst_info(sha256(imprint_of if imprint_of is not None else message), gen_time))
    for name, obj in ((f"s{n}.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())), (f"s{n}.crt", pem_of_cert(leaf)), (f"x{n}.pem", b"".join(pem_of_cert(c) for c in extra))):
        with open(os.path.join(W, name), "wb") as f:
            f.write(obj)
    args = ["openssl", "cms", "-sign", "-binary", "-nodetach", "-in", f"tst{n}.der", "-outform", "DER", "-signer", f"s{n}.crt", "-inkey", f"s{n}.key", "-md", "sha256", "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-out", f"tok{n}.der"]
    if extra:
        args += ["-certfile", f"x{n}.pem"]
    run(*args)
    token = open(os.path.join(W, f"tok{n}.der"), "rb").read()
    if not response:
        return token
    return tlv(0x30, tlv(0x30, integer(status)) + (token if status in (0, 1) else b""))


# ------------------------------------------------------------------------------------------ bundles

MEDIA = {
    "0.1": "application/vnd.dev.sigstore.bundle+json;version=0.1",
    "0.2": "application/vnd.dev.sigstore.bundle+json;version=0.2",
    "0.3": "application/vnd.dev.sigstore.bundle.v0.3+json",
}


class Entry:
    """A log entry to put in a bundle. `set` and `proof` say what authenticates it."""

    def __init__(self, log=None, *, set=True, proof=True, it=T0 + 20, kind="dsse", index=None, tree_size=11, position=6, **kw):
        self.log, self.set, self.proof, self.it, self.kind = log or log_a, set, proof, it, kind
        self.index, self.tree_size, self.position = index, tree_size, position
        self.kw = kw


_next_index = [100000]


def make_entry(e, env, verifier_pem):
    """The JSON of a tlogEntries element for the envelope `env` (payload type, payload, signature)."""
    ptype, payload, sig = env
    kw = dict(e.kw)
    body = kw.pop("body", None)
    if body is None:
        mk = body_dsse if e.kind == "dsse" else body_intoto
        body = mk(kw.pop("body_type", ptype), kw.pop("body_payload", payload), kw.pop("body_sig", sig), kw.pop("body_pem", verifier_pem), kw.pop("hash_override", None))
    version = {"dsse": "0.0.1", "intoto": "0.0.2"}.get(e.kind, "0.0.1")
    index = e.index if e.index is not None else _next_index[0]
    _next_index[0] += 1
    out = {
        "logIndex": str(index),
        "logId": {"keyId": b64(kw.pop("log_id", e.log.log_id))},
        "kindVersion": {"kind": e.kind, "version": version},
        "integratedTime": str(e.it),
        "canonicalizedBody": b64(body),
    }
    if e.set:
        out["inclusionPromise"] = {"signedEntryTimestamp": b64(e.log.set(body, kw.pop("set_time", e.it), index, kw.pop("set_signer", None)))}
    if e.proof:
        proved = kw.pop("proved_body", body)
        leaves = tree_with(proved, e.tree_size, e.position, str(index))
        root = mth(leaves)
        hashes_ = path(e.position, leaves)
        checkpoint = e.log.checkpoint(e.tree_size, root, kw.pop("origin", None), kw.pop("checkpoint_signer", None))
        out["inclusionProof"] = {
            "logIndex": str(e.position),
            "rootHash": b64(kw.pop("proof_root", root)),
            "treeSize": str(kw.pop("proof_size", e.tree_size)),
            "hashes": [b64(h) for h in hashes_],
            "checkpoint": {"envelope": checkpoint.decode()},
        }
    assert not kw, f"options that did not apply: {kw}"
    return out


def bundle(
    fmt="0.3",
    *,
    leaf=None,
    leaf_key=None,
    chain=None,
    entries=None,
    stamps=(),
    stmt=None,
    ptype=PAYLOAD_TYPE,
    signer_key=None,
    two_signatures=False,
):
    """A bundle that verifies unless an option says otherwise."""
    leaf_key = leaf_key or DEFAULT_KEY
    leaf = leaf or DEFAULT_LEAF
    payload = stmt if stmt is not None else statement()
    sig = sign(signer_key or leaf_key, pae(ptype, payload))
    entries = [Entry()] if entries is None else entries
    em = [make_entry(e, (ptype, payload, sig), pem_of_cert(leaf)) for e in entries]
    vm = {}
    if fmt == "0.3":
        vm["certificate"] = {"rawBytes": b64(der_of_cert(leaf))}
    else:
        vm["x509CertificateChain"] = {"certificates": [{"rawBytes": b64(der_of_cert(c))} for c in (chain if chain is not None else [leaf, fulcio_int.cert])]}
    vm["tlogEntries"] = em
    vm["timestampVerificationData"] = {"rfc3161Timestamps": [{"signedTimestamp": b64(s(sig) if callable(s) else s)} for s in stamps]}
    sigs = [{"sig": b64(sig), "keyid": ""}]
    if two_signatures:
        sigs.append({"sig": b64(sign(codesign_key, pae(ptype, payload))), "keyid": ""})
    return {"mediaType": MEDIA[fmt], "verificationMaterial": vm, "dsseEnvelope": {"payload": b64(payload), "payloadType": ptype, "signatures": sigs}}


DEFAULT_KEY = new_key("p256")
SAN_URI = [x509.UniformResourceIdentifier(WORKFLOW)]
DEFAULT_LEAF = issue(fulcio_int, DEFAULT_KEY, san=SAN_URI, exts=fulcio_exts(**GH_EXTS))

# ------------------------------------------------------------------------------------------ trusted roots


def cert_entry(c):
    return {"rawBytes": b64(der_of_cert(c))}


def trusted_root(*, fulcio=None, tsas=None, logs=None, log_valid_from=ts(2026, 1, 1), log_valid_until=None, ctlogs=None):
    fulcio = fulcio if fulcio is not None else [
        {"subject": {"organization": "synthetic", "commonName": "fulcio"}, "uri": "https://fulcio.synthetic.test", "certChain": {"certificates": [cert_entry(c) for c in fulcio_int.chain()]}, "validFor": {"start": rfc3339(ts(2026, 1, 1))}}
    ]
    tsas = tsas if tsas is not None else [
        {"subject": {"organization": "synthetic", "commonName": TSA_NAME}, "uri": "https://tsa.synthetic.test/api/v1/timestamp", "certChain": {"certificates": [cert_entry(c) for c in [tsa_leaf, tsa_int.cert, tsa_root.cert]]}, "validFor": {"start": rfc3339(ts(2026, 1, 1))}}
    ]
    logs = logs if logs is not None else [log_a.root_entry(log_valid_from, log_valid_until), log_b.root_entry(log_valid_from, log_valid_until)]
    ctlogs = ctlogs if ctlogs is not None else [ct_log.root_entry(), ct_log_rsa.root_entry()]
    return {"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": logs, "certificateAuthorities": fulcio, "ctlogs": ctlogs, "timestampAuthorities": tsas}


roots = {"base": trusted_root()}

# ------------------------------------------------------------------------------------------ cases

cases = []

# What the message of each refusal must contain: the refusal is for the reason the case was made for.
REASONS = {
    "no time at all": "nothing in the bundle establishes when",
    "time stamp after the certificate expired": "certificate has expired",
    "time stamp before the certificate was valid": "certificate is not yet valid",
    "SET after the certificate expired": "certificate has expired",
    "SET one second late": "certificate has expired",
    "certificate for TLS servers": "not valid for code signing",
    "certificate with no purpose": "has no extendedKeyUsage",
    "certificate of another CA": "unable to build a chain to a trusted root",
    "a Fulcio extension that is not text": "is not text",
    "the CA ended before": "no certificate authority of the trusted root counts",
    "the CA starts after the SET": "no certificate authority of the trusted root counts",
    "a trusted root with no CA": "the trusted root has no certificate authority",
    "another payload type": "is not an in-toto statement",
    "two signatures": "exactly one signature",
    "signed by another key": "not by the signer's key",
    "the artifact is not a subject": "no subject of the statement has",
    "the subject has another digest algorithm": "no subject of the statement has",
    "unknown statement type": "is not known",
    "no subjects": "subject list is empty",
    "a subject with no digest": "has no digest",
    "a statement that is not JSON": "not strict JSON",
    "a statement with a repeated name": "names a member twice",
    "a statement whose digest is not text": "digest is not a string",
    "the entry names another signature": "body's signature is not the envelope's",
    "the entry names another payload hash": "payload hash is not the SHA-256",
    "the entry names another payload": "payload hash is not the SHA-256",
    "the entry names another payload type": "payload type is not the envelope's",
    "the entry names another certificate": "certificate or key is not the signer's",
    "the entry names a key, not the certificate": "certificate or key is not the signer's",
    "an entry of another kind": "hashedrekord 0.0.1 are not handled",
    "an entry body that is not JSON": "entry body is not strict JSON",
    "an entry of an unknown log": "no log with id",
    "no entries": "no transparency log entry",
    "the same entry twice": "in the bundle twice",
    "SET by another key": "signed entry timestamp is not by a trusted key",
    "SET for another time": "signed entry timestamp is not by a trusted key",
    "the log's key is not valid yet": "signed entry timestamp is not by a trusted key",
    "the log's key had ended": "signed entry timestamp is not by a trusted key",
    "the log's key is not valid at any verified time": "no key of the log was valid",
    "an inclusion proof for another entry": "invalid proof",
    "a checkpoint by another key": "the checkpoint: invalid signature",
    "a checkpoint of another log": "origin",
    "an inclusion proof with another tree size": "tree other than the checkpoint's",
    "an inclusion proof with another root hash": "tree other than the checkpoint's",
    "Ed25519 checkpoint by another key": "the checkpoint: invalid signature",
    "v01 entry without a SET": "needs a signed entry timestamp",
    "v02 entry without a proof": "needs an inclusion proof",
    "v03 entry without a proof": "needs an inclusion proof",
    "v03 with a chain": "signer's material",
    "v01 with a single certificate": "signer's material",
    "a bundle of another version": "bundle media type",
    "a message signature bundle": "messageSignature",
    "neither an envelope nor a message signature": "not exactly one of dsseEnvelope and messageSignature",
    "time stamp over other bytes": "not for this message",
    "time stamp by an authority the root does not have": "unable to build a chain to a trusted root",
    "time stamp by a signing certificate": "unable to build a chain to a trusted root",
    "a refused time stamp": "not a grant",
    "a time stamp that is not DER": "unsupported CMS version",
    "time stamp after its authority's validity": "outside its validity",
    "a trusted root with no time-stamp authority": "has no time-stamp authority",
    "a time-stamp authority's chain that is the leaf alone": "unable to build a chain to a trusted root",
    "a time-stamp authority's root, the token carries nothing": "unable to build a chain to a trusted root",
}


def case(name, why, b, expect="ok", root="base", algorithm=None, facts=None, reason=None, sct_threshold=None):
    c = {"name": name, "why": why, "root": root, "bundle": b, "expect": expect}
    if sct_threshold is not None:
        c["sct_threshold"] = sct_threshold
    reason = reason or REASONS.pop(name, None)
    assert (expect == "ok") == (reason is None), f"{name}: a refusal needs a reason, and a success has none"
    if reason:
        c["reason"] = reason
    if algorithm:
        c["algorithm"] = algorithm
    if facts is not None:
        c["facts"] = facts
    cases.append(c)


def sig_of(b):
    return base64.b64decode(b["dsseEnvelope"]["signatures"][0]["sig"])


def stamped(t, **kw):
    """A time-stamp maker for `bundle(stamps=...)`: it is given the signature."""
    return lambda sig: stamp(sig, t, **kw)


def facts(time, sources, *, entries=None, **more):
    return {"verified_time": time, "sources": sources, "entries": entries or [], **more}


# --- what verifies

case("v03 certificate, SET and inclusion proof", "the default shape", bundle(), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}], uri=WORKFLOW, issuer=GITHUB, repository="https://github.com/example/widget", ref="refs/tags/v1.2.3", scts=[[ct_log.base_url, (T0 - 30) * 1000 + 250]]))
case("v01 chain, SET only", "version 0.1 has no proofs", bundle("0.1", entries=[Entry(proof=False)]), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": None, "integrated_time": T0 + 20}]))
case("v02 chain, SET and proof", "version 0.2", bundle("0.2"), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}]))
case("v01 chain with the root too", "the extra certificates are candidates only", bundle("0.1", chain=[DEFAULT_LEAF, fulcio_int.cert, fulcio_root.cert], entries=[Entry(proof=False)]), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": None, "integrated_time": T0 + 20}]))
case("v01 chain with the leaf alone", "the intermediate comes from the trusted root", bundle("0.1", chain=[DEFAULT_LEAF], entries=[Entry(proof=False)]), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": None, "integrated_time": T0 + 20}]))
case("v03 proof only, time stamp", "the entry's integratedTime is not signed: the time stamp is the time", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10)]), facts=facts(T0 + 10, ["tsa"], entries=[{"set": False, "inclusion": 11, "integrated_time": None}]))
case("v03 proof only, time stamp as a bare token", "a token without the response around it", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10, response=False)]), facts=facts(T0 + 10, ["tsa"], entries=[{"set": False, "inclusion": 11, "integrated_time": None}]))
case("v03 proof only, time stamp with the whole chain in the token", "certificates in the token are candidates", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10, extra=[tsa_int.cert, tsa_root.cert])]), facts=facts(T0 + 10, ["tsa"], entries=[{"set": False, "inclusion": 11, "integrated_time": None}]))
case("ed25519 log, proof only, time stamp", "a log that signs with Ed25519 (Rekor v2's way) and gives no promise", bundle(entries=[Entry(log_b, set=False, tree_size=1, position=0)], stamps=[stamped(T0 + 10)]), facts=facts(T0 + 10, ["tsa"], entries=[{"set": False, "inclusion": 1, "integrated_time": None}]))
case("two logs and a time stamp", "all entries must be good; the times are all there is", bundle(entries=[Entry(log_a, it=T0 + 25), Entry(log_b, set=False, tree_size=9, position=8)], stamps=[stamped(T0 + 15)]), facts=facts(T0 + 15, ["tsa", "entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 25}, {"set": False, "inclusion": 9, "integrated_time": None}]))
case("two time stamps", "the earliest time the certificate was valid at", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 9000), stamped(T0 + 10)]), facts=facts(T0 + 10, ["tsa", "tsa"], entries=[{"set": False, "inclusion": 11, "integrated_time": None}]))
case("late SET, early time stamp", "one time inside the certificate's validity is enough", bundle(entries=[Entry(it=T0 + 9000)], stamps=[stamped(T0 + 10)]), facts=facts(T0 + 10, ["tsa", "entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 9000}]))
case("v03 intoto entry", "an entry of kind intoto 0.0.2 for a certificate-signed bundle", bundle(entries=[Entry(kind="intoto")]), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}]))
case("subjects, the second one matches", "any subject may have the digest", bundle(stmt=statement(subjects=[{"name": "a", "digest": {"sha256": "00" * 32}}, {"name": "b", "digest": {"sha512": "11" * 64, "sha256": DIGEST.upper()}}])), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}], matched_subject=1))
case("in-toto v0.1 statement", "the older statement type", bundle(stmt=statement(stype="https://in-toto.io/Statement/v0.1")), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}]))
case("subject digest in sha512", "the caller's algorithm is the subject's", bundle(stmt=statement(subjects=[{"name": "a", "digest": {"sha512": hashlib.sha512(ARTIFACT).hexdigest()}}])), algorithm="sha512", facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}]))

# --- other identities and key types

mail_key = new_key("p256")
mail_leaf = issue(fulcio_int, mail_key, san=[x509.RFC822Name("dev@example.test")], exts=fulcio_exts(x8="https://accounts.example.test", x1="https://accounts.example.test"))
case("identity by e-mail", "an e-mail address, issuer from the OIDC issuer extension", bundle(leaf=mail_leaf, leaf_key=mail_key), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}], email="dev@example.test", issuer="https://accounts.example.test"))
user_key = new_key("p256")
user_leaf = issue(fulcio_int, user_key, san=[x509.OtherName(ObjectIdentifier(FULCIO_ARC + "7"), utf8("alice"))], exts=fulcio_exts(x8="https://oidc.example.test"))
case("identity by username", "an otherName of Sigstore's username type", bundle(leaf=user_leaf, leaf_key=user_key), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}], username="alice", issuer="https://oidc.example.test"))
for kind in ("p384", "ed", "rsa"):
    k = new_key(kind)
    lf = issue(fulcio_int, k, san=SAN_URI, exts=fulcio_exts(**GH_EXTS))
    case(f"signing key {kind}", "the signature is checked with the certificate's key, whatever its type", bundle(leaf=lf, leaf_key=k), facts=facts(T0 + 20, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}], uri=WORKFLOW))

# --- the time and the certificate

case("no time at all", "a proof is not a time", bundle(entries=[Entry(set=False)]), "NoVerifiedTime")
case("time stamp after the certificate expired", "the certificate must be valid at a time the bundle establishes", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 9000)]), "Certificate")
case("time stamp before the certificate was valid", "likewise", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 - 600)]), "Certificate")
case("SET after the certificate expired", "a log time is a time", bundle(entries=[Entry(it=T0 + 9000)]), "Certificate")
case("SET at the last second", "the end of a validity is inside it", bundle(entries=[Entry(it=T0 + 570)]), facts=facts(T0 + 570, ["entry"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 570}]))
case("SET one second late", "and the next second is not", bundle(entries=[Entry(it=T0 + 571)]), "Certificate")
case("certificate for TLS servers", "Fulcio certificates are for code signing", bundle(leaf=issue(fulcio_int, DEFAULT_KEY, san=SAN_URI, exts=fulcio_exts(**GH_EXTS), eku=ExtendedKeyUsageOID.SERVER_AUTH)), "Certificate")
case("certificate with no purpose", "an absent extended key usage is not code signing", bundle(leaf=issue(fulcio_int, DEFAULT_KEY, san=SAN_URI, exts=fulcio_exts(**GH_EXTS), eku=None)), "Certificate")
rogue_leaf = issue(rogue_int, DEFAULT_KEY, san=SAN_URI, exts=fulcio_exts(**GH_EXTS))
case("certificate of another CA", "under a root the trusted root does not have", bundle("0.1", leaf=rogue_leaf, chain=[rogue_leaf, rogue_int.cert, rogue_root.cert], entries=[Entry(proof=False)]), "Certificate")
case("a Fulcio extension that is not text", "an issuer extension of the wrong type", bundle(leaf=issue(fulcio_int, DEFAULT_KEY, san=SAN_URI, exts=[(FULCIO_ARC + "8", tlv(0x04, b"x"))])), "Certificate")
def fulcio_ca(start, end=None):
    vf = {"start": rfc3339(start)}
    if end:
        vf["end"] = rfc3339(end)
    return {"subject": {"organization": "synthetic", "commonName": "fulcio"}, "uri": "https://fulcio.synthetic.test", "certChain": {"certificates": [cert_entry(c) for c in fulcio_int.chain()]}, "validFor": vf}


roots["ca ended"] = trusted_root(fulcio=[fulcio_ca(ts(2026, 1, 1), T0 - 1000)])
case("the CA ended before", "a CA counts only while it is valid", bundle(), "Certificate", root="ca ended")
roots["ca starts later"] = trusted_root(fulcio=[fulcio_ca(T0 + 21)])
case("the CA starts after the SET", "and not before it starts", bundle(), "Certificate", root="ca starts later")
case("the CA starts after the SET, before the time stamp", "the time stamp is a time too", bundle(stamps=[stamped(T0 + 22)]), facts=facts(T0 + 22, ["entry", "tsa"], entries=[{"set": True, "inclusion": 11, "integrated_time": T0 + 20}]), root="ca starts later")
roots["no fulcio"] = trusted_root(fulcio=[])
case("a trusted root with no CA", "nothing to verify a certificate with", bundle(), "Certificate", root="no fulcio")

# --- certificate transparency (BACKLOG B-81)

E = [{"set": True, "inclusion": 11, "integrated_time": T0 + 20}]
SCT_AT = (T0 - 30) * 1000 + 250


def ct_leaf(**kw):
    return issue(fulcio_int, DEFAULT_KEY, san=SAN_URI, exts=fulcio_exts(**GH_EXTS), **kw)


case("SCTs from two logs and one the root does not list", "each listed log's SCT is checked; an unlisted one is passed over", bundle(leaf=ct_leaf(scts=[{}, {"log": ct_log_rsa}, {"log": unlisted_ct_log}])), facts=facts(T0 + 20, ["entry"], entries=E, scts=[[ct_log.base_url, SCT_AT], [ct_log_rsa.base_url, SCT_AT]]))
case("two logs required, SCTs from two", "", bundle(leaf=ct_leaf(scts=[{"log": ct_log_rsa}, {}])), facts=facts(T0 + 20, ["entry"], entries=E, scts=[[ct_log_rsa.base_url, SCT_AT], [ct_log.base_url, SCT_AT]]), sct_threshold=2)
case("an SCT of another version next to one", "a version this does not know is passed over (RFC 6962 section 5.2)", bundle(leaf=ct_leaf(scts=[{"version": 1}, {}])), facts=facts(T0 + 20, ["entry"], entries=E, scts=[[ct_log.base_url, SCT_AT]]))
case("an SCT with extensions", "they are signed as they are", bundle(leaf=ct_leaf(scts=[{"ext": b"\x00\x01\x02"}])), facts=facts(T0 + 20, ["entry"], entries=E, scts=[[ct_log.base_url, SCT_AT]]))
case("no SCT, none required", "a Sigstore without CT", bundle(leaf=ct_leaf(scts=None)), facts=facts(T0 + 20, ["entry"], entries=E, scts=[]), sct_threshold=0)
case("a certificate without SCTs", "one is required by default", bundle(leaf=ct_leaf(scts=None)), "CertificateTransparency", reason="from 0 of the trusted root's CT logs verified and 1 are required (the certificate has 0, 0 from logs")
case("an SCT from a log the root does not list", "it does not count", bundle(leaf=ct_leaf(scts=[{"log": unlisted_ct_log}])), "CertificateTransparency", reason="from 0 of the trusted root's CT logs verified and 1 are required (the certificate has 1, 1 from logs the root does not list)")
case("only an SCT of another version", "it is not checked, so it does not count", bundle(leaf=ct_leaf(scts=[{"version": 1}])), "CertificateTransparency", reason="the certificate has 1, 0 from logs")
case("two logs required, one SCT", "", bundle(), "CertificateTransparency", reason="from 1 of the trusted root's CT logs verified and 2 are required", sct_threshold=2)
case("two logs required, two SCTs from one log", "a log counts once", bundle(leaf=ct_leaf(scts=[{}, {"ext": b"x"}])), "CertificateTransparency", reason="from 1 of the trusted root's CT logs verified and 2 are required", sct_threshold=2)
case("an SCT by another key", "the log's id, another key", bundle(leaf=ct_leaf(scts=[{"signer": unlisted_ct_log.key, "log_id": ct_log.log_id}])), "CertificateTransparency", reason="the signature is not the log's")
case("an SCT over another certificate", "what the log signed is not this precertificate", bundle(leaf=ct_leaf(scts=[{"signed_tbs": mail_leaf.tbs_precertificate_bytes}])), "CertificateTransparency", reason="the signature is not the log's")
case("an SCT for another issuer", "the issuer's key is part of what is signed", bundle(leaf=ct_leaf(scts=[{"issuer_key": rogue_int.key}])), "CertificateTransparency", reason="the signature is not the log's")
case("an SCT whose time was changed", "the time is signed", bundle(leaf=ct_leaf(scts=[{"written_ms": SCT_AT + 1}])), "CertificateTransparency", reason="the signature is not the log's")
case("an SCT with the algorithms of RSA from an ECDSA log", "the algorithms must be the log key's", bundle(leaf=ct_leaf(scts=[{"algs": (4, 1)}])), "CertificateTransparency", reason="signed with algorithms (4, 1), and the log's key goes with (4, 3)")
case("a bad SCT next to a good one", "an SCT that is there and wrong is an error, as with the log's other promises", bundle(leaf=ct_leaf(scts=[{}, {"log": ct_log_rsa, "written_ms": SCT_AT + 1000}])), "CertificateTransparency", reason="the signature is not the log's")
case("an SCT list that is empty", "RFC 6962: at least one", bundle(leaf=ct_leaf(scts=None, sct_value=tlv(0x04, b"\x00\x00"))), "CertificateTransparency", reason="the SCT list is empty")
case("an SCT list that is not an OCTET STRING", "", bundle(leaf=ct_leaf(scts=None, sct_value=tlv(0x30, b""))), "CertificateTransparency", reason="not an OCTET STRING")
roots["ct key later"] = trusted_root(ctlogs=[ct_log.root_entry(start=T0)])
case("an SCT from before the CT log's key", "the key counts from its start", bundle(), "CertificateTransparency", root="ct key later", reason="no key of the log was valid at")
roots["ct key ended"] = trusted_root(ctlogs=[ct_log.root_entry(end=T0 - 31)])
case("an SCT from after the CT log's key ended", "", bundle(), "CertificateTransparency", root="ct key ended", reason="no key of the log was valid at")
roots["ct key last second"] = trusted_root(ctlogs=[ct_log.root_entry(end=T0 - 30)])
case("an SCT in the last second of the CT log's key", "the end of a validity is inside it", bundle(), root="ct key last second", facts=facts(T0 + 20, ["entry"], entries=E, scts=[[ct_log.base_url, SCT_AT]]))
roots["no ct logs"] = trusted_root(ctlogs=[])
case("a trusted root with no CT log", "nothing counts", bundle(), "CertificateTransparency", root="no ct logs", reason="from 0 of the trusted root's CT logs verified and 1 are required (the certificate has 1, 1 from logs the root does not list)")

# --- the envelope and the statement

case("another payload type", "only in-toto statements", bundle(ptype="text/plain"), "PayloadType")
case("two signatures", "exactly one", bundle(two_signatures=True), "Malformed")
case("signed by another key", "the signature must be the certificate's", bundle(signer_key=new_key("p256")), "Signature")
case("the artifact is not a subject", "the statement is about something else", bundle(stmt=statement(subjects=[{"name": "other", "digest": {"sha256": "ab" * 32}}])), "SubjectMismatch")
case("the subject has another digest algorithm", "the caller's algorithm must be there", bundle(), "SubjectMismatch", algorithm="sha384")
case("unknown statement type", "", bundle(stmt=statement(stype="https://in-toto.io/Statement/v2")), "Statement")
case("no subjects", "", bundle(stmt=statement(subjects=[])), "Statement")
case("a subject with no digest", "", bundle(stmt=statement(subjects=[{"name": "x"}])), "Statement")
case("a statement that is not JSON", "", bundle(stmt=b"hello"), "Statement")
case("a statement with a repeated name", "I-JSON: duplicate names are an error", bundle(stmt=b'{"_type":"https://in-toto.io/Statement/v1","_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x"}'), "Statement")
case("a statement whose digest is not text", "", bundle(stmt=statement(subjects=[{"name": "x", "digest": {"sha256": 7}}])), "Statement")

# --- the entries

case("the entry names another signature", "the body of the entry is signed by the log, but it is about another envelope", bundle(entries=[Entry(body_sig=sign(DEFAULT_KEY, b"something else"))]), "Entry")
case("the entry names another payload hash", "", bundle(entries=[Entry(hash_override="ab" * 32)]), "Entry")
case("the entry names another payload", "", bundle(entries=[Entry(body_payload=statement(ptype="https://example.test/other"))]), "Entry")
case("the entry names another payload type", "an intoto entry carries the payload type", bundle(entries=[Entry(kind="intoto", body_type="text/plain")]), "Entry")
case("the entry names another certificate", "", bundle(entries=[Entry(body_pem=pem_of_cert(mail_leaf))]), "Entry")
case("the entry names a key, not the certificate", "the body's verifier must be the signer's own certificate", bundle(entries=[Entry(body_pem=DEFAULT_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))]), "Entry")
case("an entry of another kind", "hashedrekord is for artifacts", bundle(entries=[Entry(body=canon({"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {}}), kind="hashedrekord")]), "Entry")
case("an entry body that is not JSON", "", bundle(entries=[Entry(body=b"not json")]), "Entry")
case("an entry of an unknown log", "no log with this id in the trusted root", bundle(entries=[Entry(log_id=sha256(b"unknown log"))]), "Entry")
case("no entries", "a bundle without a log entry", bundle(entries=[], stamps=[stamped(T0 + 10)]), "Entry")
case("the same entry twice", "", bundle(entries=[Entry(index=777), Entry(index=777)]), "Entry")
case("SET by another key", "the log's name and id, another key", bundle(entries=[Entry(set_signer=rogue_log)]), "Entry")
case("SET for another time", "the time in the entry is what the SET covers", bundle(entries=[Entry(set_time=T0 + 21)]), "Entry")
roots["log key later"] = trusted_root(log_valid_from=T0 + 100)
case("the log's key is not valid yet", "at the time of the SET", bundle(), "Entry", root="log key later")
roots["log key ended"] = trusted_root(log_valid_until=T0 + 19)
case("the log's key had ended", "", bundle(), "Entry", root="log key ended")
case("the log's key is not valid at any verified time", "for a proof: some verified time must be in the key's validity", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10)]), "Entry", root="log key later")
case("an inclusion proof for another entry", "the leaf is not this body", bundle(entries=[Entry(proved_body=b"another body")]), "Entry")
case("a checkpoint by another key", "same name, other key", bundle(entries=[Entry(checkpoint_signer=rogue_log)]), "Entry")
case("a checkpoint of another log", "the origin line is not the log's", bundle(entries=[Entry(origin="other.example - 1")]), "Entry")
case("an inclusion proof with another tree size", "the proof must be to the checkpoint's tree", bundle(entries=[Entry(proof_size=12)]), "Entry")
case("an inclusion proof with another root hash", "", bundle(entries=[Entry(proof_root=sha256(b"x"))]), "Entry")
case("Ed25519 checkpoint by another key", "", bundle(entries=[Entry(log_b, set=False, tree_size=1, position=0, checkpoint_signer=Log("ed25519", "https://log2.synthetic.test", 42))], stamps=[stamped(T0 + 10)]), "Entry")

# --- what the format version needs

b = bundle("0.1", entries=[Entry(proof=False)])
b["verificationMaterial"]["tlogEntries"][0].pop("inclusionPromise")
case("v01 entry without a SET", "version 0.1 needs the promise", b, "Malformed")
case("v02 entry without a proof", "version 0.2 needs the proof", bundle("0.2", entries=[Entry(proof=False)]), "Malformed")
case("v03 entry without a proof", "", bundle("0.3", entries=[Entry(proof=False)]), "Malformed")
b = bundle("0.3")
b["verificationMaterial"] = {**b["verificationMaterial"], "x509CertificateChain": {"certificates": [{"rawBytes": b64(der_of_cert(DEFAULT_LEAF))}]}}
b["verificationMaterial"].pop("certificate")
case("v03 with a chain", "version 0.3 has a single certificate", b, "Malformed")
b = bundle("0.1", entries=[Entry(proof=False)])
b["verificationMaterial"]["certificate"] = b["verificationMaterial"].pop("x509CertificateChain")["certificates"][0]
case("v01 with a single certificate", "that is version 0.3's", b, "Malformed")
b = bundle()
b["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.4+json"
case("a bundle of another version", "", b, "Unsupported")
b = bundle()
b["dsseEnvelope"] = None
b["messageSignature"] = {"messageDigest": {"algorithm": "SHA2_256", "digest": b64(sha256(ARTIFACT))}, "signature": b64(b"x")}
case("a message signature bundle", "not handled", b, "Unsupported")
b = bundle()
b["dsseEnvelope"] = None
case("neither an envelope nor a message signature", "", b, "Malformed")

# --- time stamps

case("time stamp over other bytes", "the imprint is not the signature's", bundle(entries=[Entry(set=False)], stamps=[lambda sig: stamp(sig, T0 + 10, imprint_of=b"another message")]), "Timestamp")
case("time stamp by an authority the root does not have", "", bundle(entries=[Entry(set=False)], stamps=[lambda sig: stamp(sig, T0 + 10, key=rogue_tsa_key, leaf=rogue_tsa_leaf, extra=[rogue_tsa_root.cert])]), "Timestamp")
case("time stamp by a signing certificate", "a Fulcio-style leaf has the wrong purpose for a time-stamp authority", bundle(entries=[Entry(set=False)], stamps=[lambda sig: stamp(sig, T0 + 10, key=DEFAULT_KEY, leaf=DEFAULT_LEAF, extra=[fulcio_int.cert])]), "Timestamp")
case("a refused time stamp", "the response says the request was rejected", bundle(entries=[Entry(set=False)], stamps=[lambda sig: stamp(sig, T0 + 10, status=2)]), "Timestamp")
case("a time stamp that is not DER", "", bundle(entries=[Entry(set=False)], stamps=[b"\x30\x03\x02\x01\x00"]), "Timestamp")
roots["tsa ended"] = trusted_root(tsas=[{"subject": {"commonName": TSA_NAME}, "uri": "https://tsa.synthetic.test", "certChain": {"certificates": [cert_entry(c) for c in [tsa_leaf, tsa_int.cert, tsa_root.cert]]}, "validFor": {"start": rfc3339(ts(2026, 1, 1)), "end": rfc3339(T0 + 5)}}])
case("time stamp after its authority's validity", "the authority counts only for the time it is valid", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10)]), "Timestamp", root="tsa ended")
roots["no tsa"] = trusted_root(tsas=[])
case("a trusted root with no time-stamp authority", "", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10)]), "Timestamp", root="no tsa")
roots["tsa leaf only"] = trusted_root(tsas=[{"subject": {"commonName": TSA_NAME}, "uri": "https://tsa.synthetic.test", "certChain": {"certificates": [cert_entry(tsa_leaf)]}, "validFor": {"start": rfc3339(ts(2026, 1, 1))}}])
case("a time-stamp authority's chain that is the leaf alone", "a leaf is no one's root: nothing anchors the token", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10)]), "Timestamp", root="tsa leaf only")
roots["tsa root only"] = trusted_root(tsas=[{"subject": {"commonName": TSA_NAME}, "uri": "https://tsa.synthetic.test", "certChain": {"certificates": [cert_entry(tsa_root.cert)]}, "validFor": {"start": rfc3339(ts(2026, 1, 1))}}])
case("a time-stamp authority's root, the token carries the rest", "", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10, extra=[tsa_int.cert])]), facts=facts(T0 + 10, ["tsa"], entries=[{"set": False, "inclusion": 11, "integrated_time": None}]), root="tsa root only")
case("a time-stamp authority's root, the token carries nothing", "the intermediate is nowhere", bundle(entries=[Entry(set=False)], stamps=[stamped(T0 + 10)]), "Timestamp", root="tsa root only")

# ------------------------------------------------------------------------------------------ write

assert not REASONS, f"reasons for cases that do not exist: {list(REASONS)}"

doc = {"artifact": b64(ARTIFACT), "generated_by": "tools/gen_sigstore_fixtures.py", "roots": roots, "cases": cases}
dump = lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False)
with open(OUT, "w", encoding="utf-8") as f:
    # one case to a line, so that a change shows as the cases it changes
    f.write('{"generated_by":' + dump(doc["generated_by"]) + ',\n"artifact":' + dump(doc["artifact"]) + ',\n"roots":' + dump(roots) + ',\n"cases":[\n')
    f.write(",\n".join(dump(c) for c in cases))
    f.write("\n]}\n")
print(f"wrote {OUT}: {len(cases)} cases, {len(roots)} trusted roots")
