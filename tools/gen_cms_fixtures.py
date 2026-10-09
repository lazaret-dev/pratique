#!/usr/bin/env python3
"""Generates tests/data/cms_fixtures.txt: CMS / PKCS#7 SignedData messages made by other
implementations (OpenSSL's `cms`, `smime` and `ts`, and the JDK's `jarsigner`), signed by keys of a
throwaway PKI that is made on every run (so rerunning changes the file; only public data is written).
Needs Python `cryptography`, `openssl` 3.x, and for the JAR blocks `keytool`/`jarsigner` (skipped,
with a note, if there is no JDK). Run from the repository root:

    python3 tools/gen_cms_fixtures.py

The file has one record per line:

  cert NAME HEX       a certificate (DER): root, inter, rogue (a CA nobody trusts), and the leaves
  content NAME HEX    detached content (what a signature that does not carry its message covers)
  blob NAME HEX       a SignedData or a time-stamp token (DER or BER, as the tool wrote it)

and tests/cms_vectors.rs says what each blob is expected to do (so the expectations are not in the
data). The PKI: root and inter are P-256 CAs; the leaves under inter are RSA-2048 (`rsa`), P-256
(`p256`), P-384 (`p384`), Ed25519 (`ed`), a code-signing leaf that expired in June 2026 (`short`),
one for TLS only (`tls`), a time-stamp authority (`tsa`); `rogue` signs under a root of its own.
"""
import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = "tests/data/cms_fixtures.txt"
W = tempfile.mkdtemp(prefix="cmsfix")
UTC = datetime.timezone.utc


def when(y, m, d):
    return datetime.datetime(y, m, d, tzinfo=UTC)


def run(*args, stdin=None, check=True):
    p = subprocess.run([str(a) for a in args], cwd=W, input=stdin, capture_output=True)
    if check and p.returncode:
        sys.exit(f"{' '.join(map(str, args))}\n{p.stderr.decode()}")
    return p


def path(name):
    return os.path.join(W, name)


def write(name, data):
    with open(path(name), "wb") as f:
        f.write(data)


def read(name):
    with open(path(name), "rb") as f:
        return f.read()


# ------------------------------------------------------------------------------------------ the PKI

keys = {}
certs = {}


def make_key(kind):
    return {
        "p256": lambda: ec.generate_private_key(ec.SECP256R1()),
        "p384": lambda: ec.generate_private_key(ec.SECP384R1()),
        "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ed": lambda: ed25519.Ed25519PrivateKey.generate(),
    }[kind]()


def make_cert(name, kind, issuer, cn, *, ca=False, eku=None, eku_critical=False, nb=when(2026, 1, 1), na=when(2036, 1, 1)):
    key = make_key(kind)
    ikey = keys[issuer] if issuer else key
    icert = certs[issuer] if issuer else None
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(icert.subject if icert else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca and issuer else None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca:
        b = b.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        b = b.add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
    if icert:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False
        )
    algo = None if isinstance(ikey, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = b.sign(ikey, algo)
    keys[name], certs[name] = key, cert
    write(name + ".key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write(name + ".crt", cert.public_bytes(serialization.Encoding.PEM))
    return cert


CS = [ExtendedKeyUsageOID.CODE_SIGNING]
make_cert("root", "p256", None, "tiny_https CMS test root", ca=True, na=when(2046, 1, 1))
make_cert("inter", "p256", "root", "tiny_https CMS test intermediate", ca=True, na=when(2041, 1, 1))
make_cert("rsa", "rsa", "inter", "cms rsa signer", eku=CS)
make_cert("p256", "p256", "inter", "cms p256 signer", eku=CS)
make_cert("p384", "p384", "inter", "cms p384 signer", eku=CS)
make_cert("ed", "ed", "inter", "cms ed25519 signer", eku=CS)
make_cert("short", "rsa", "inter", "cms short-lived signer", eku=CS, nb=when(2026, 3, 1), na=when(2026, 6, 1))
make_cert("tls", "p256", "inter", "cms tls-only leaf", eku=[ExtendedKeyUsageOID.SERVER_AUTH])
make_cert("tsa", "p256", "inter", "cms time-stamp authority", eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True)
make_cert("rogue_root", "p256", None, "tiny_https CMS rogue root", ca=True)
make_cert("rogue", "p256", "rogue_root", "cms rogue signer", eku=CS)
make_cert("rogue_tsa", "p256", "rogue_root", "cms rogue time-stamp authority", eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=True)

pem = lambda n: read(n + ".crt")
write("inter_chain.pem", pem("inter"))
write("tsa_chain.pem", pem("inter") + pem("root"))
write("rogue_tsa_chain.pem", pem("rogue_root"))

# ------------------------------------------------------------------------------------------ messages

HELLO = b"tiny_https cms fixture: the message that is signed\n"
write("hello.txt", HELLO)
blobs = {}
contents = {"hello": HELLO}


def cms_sign(name, signers, *, detached=False, md="sha256", extra=(), certfile="inter_chain.pem", infile="hello.txt", stream=False):
    args = ["openssl", "cms", "-sign", "-binary", "-in", infile, "-outform", "DER", "-md", md, "-out", name + ".der"]
    if not detached:
        args.append("-nodetach")
    if certfile:
        args += ["-certfile", certfile]
    if stream:
        args.append("-stream")
    for s in signers:
        args += ["-signer", s + ".crt", "-inkey", s + ".key"]
    args += list(extra)
    run(*args)
    blobs[name] = read(name + ".der")


for sig, md in [("rsa", "sha256"), ("rsa", "sha384"), ("rsa", "sha512"), ("rsa", "sha1")]:
    cms_sign(f"{sig}_{md}", [sig], md=md)
cms_sign("rsa_sha256_detached", ["rsa"], detached=True)
cms_sign("rsa_noattr", ["rsa"], extra=["-noattr"])
cms_sign("rsa_noattr_detached", ["rsa"], detached=True, extra=["-noattr"])
cms_sign("rsa_keyid", ["rsa"], extra=["-keyid"])
cms_sign("rsa_nocerts", ["rsa"], certfile=None, extra=["-nocerts"])
cms_sign("rsa_econtent_type", ["rsa"], extra=["-econtent_type", "1.2.3.4.5"])
cms_sign("rsa_stream", ["rsa"], stream=True)
# (a detached signature cannot be streamed to DER: OpenSSL then writes the content into the message)
cms_sign("rsa_pss_sha256", ["rsa"], extra=["-keyopt", "rsa_padding_mode:pss"])
cms_sign("rsa_pss_sha384", ["rsa"], md="sha384", extra=["-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:20", "-keyopt", "rsa_mgf1_md:sha256"])
cms_sign("p256_sha256", ["p256"])
cms_sign("p256_sha1", ["p256"], md="sha1")
cms_sign("p384_sha384", ["p384"], md="sha384")
cms_sign("p256_noattr", ["p256"], extra=["-noattr"])
# (OpenSSL 3.0 cannot sign CMS with Ed25519; the JDK can, see the JAR blocks below)
cms_sign("two_signers", ["rsa", "p256"])
cms_sign("short_signed", ["short"])
cms_sign("tls_signed", ["tls"])
cms_sign("rogue_signed", ["rogue"], certfile=None)
cms_sign("rsa_nosmimecap", ["rsa"], extra=["-nosmimecap"])
# PKCS#7 as OpenSSL's PKCS7 code (smime) writes it: version 1, issuerAndSerialNumber
for name, detach in [("pkcs7_attached", False), ("pkcs7_detached", True)]:
    args = ["openssl", "smime", "-sign", "-binary", "-in", "hello.txt", "-outform", "DER", "-signer", "rsa.crt", "-inkey", "rsa.key", "-certfile", "inter_chain.pem", "-md", "sha256", "-out", name + ".der"]
    if not detach:
        args.append("-nodetach")
    run(*args)
    blobs[name] = read(name + ".der")

# ------------------------------------------------------------------------- a small DER editor (to add unsigned attributes)


def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + length(len(content)) + content


class Node:
    def __init__(self, tag, content=None, kids=None):
        self.tag, self.content, self.kids = tag, content, kids

    def encode(self):
        if self.kids is not None:
            return tlv(self.tag, b"".join(k.encode() for k in self.kids))
        return tlv(self.tag, self.content)


def parse_all(buf):
    out, pos = [], 0
    while pos < len(buf):
        tag = buf[pos]
        n = buf[pos + 1]
        pos += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[pos : pos + k], "big")
            pos += k
        body = buf[pos : pos + n]
        pos += n
        out.append(Node(tag, kids=parse_all(body)) if tag & 0x20 else Node(tag, content=body))
    return out


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
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return tlv(0x02, b)


def gentime(dt):
    return tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode())


def with_unsigned_attr(cms_der, attr_oid, value_der, signer=0):
    root = parse_all(cms_der)[0]
    signed_data = root.kids[1].kids[0]
    signer_infos = signed_data.kids[-1]
    si = signer_infos.kids[signer]
    attr = Node(0x30, kids=[Node(0x06, content=oid(attr_oid)[2:]), Node(0x31, kids=parse_all(value_der))])
    if si.kids[-1].tag == 0xA1:
        si.kids[-1].kids.append(attr)
    else:
        si.kids.append(Node(0xA1, kids=[attr]))
    return root.encode()


def signature_value(cms_der, signer=0):
    root = parse_all(cms_der)[0]
    si = root.kids[1].kids[0].kids[-1].kids[signer]
    return [k for k in si.kids if k.tag == 0x04][-1].content


ID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14"
MS_RFC3161_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1"



def edit(cms_der, fn):
    """Applies fn(signed_data_node) to a message and writes it again."""
    root = parse_all(cms_der)[0]
    fn(root.kids[1].kids[0])
    return root.encode()


def signer_info(sd, n=0):
    return sd.kids[-1].kids[n]


# structural damage that keeps the signature bytes as they were
blobs["rsa_attrs_stripped"] = edit(blobs["rsa_sha256"], lambda sd: signer_info(sd).kids.__setitem__(slice(None), [k for k in signer_info(sd).kids if k.tag != 0xA0]))


def swap_econtent_type(sd):
    sd.kids[2].kids[0].content = sd.kids[2].kids[0].content[:-1] + b"\x06"


blobs["rsa_econtent_type_swapped"] = edit(blobs["rsa_econtent_type"], swap_econtent_type)


def swap_digest_alg(sd):
    oid_node = signer_info(sd).kids[2].kids[0]
    assert oid_node.content[-1] == 0x01, "a SHA-256 signer info"
    oid_node.content = oid_node.content[:-1] + b"\x02"


# ------------------------------------------------------------------------------------------ RFC 3161

write(
    "tsa.cnf",
    b"""[tsa]
default_tsa = tsa_config
[tsa_config]
serial = tsa.serial
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha1, sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
""",
)
write("tsa.serial", b"0A0B\n")


def tsa_token(digest_hex, hash_name="sha256", signer="tsa", chain="tsa_chain.pem"):
    """A real RFC 3161 reply from `openssl ts` for a message imprint, as a bare TimeStampToken."""
    run("openssl", "ts", "-query", "-digest", digest_hex, f"-{hash_name}", "-cert", "-out", "q.tsq")
    run("openssl", "ts", "-reply", "-queryfile", "q.tsq", "-signer", signer + ".crt", "-inkey", signer + ".key", "-chain", chain, "-config", "tsa.cnf", "-token_out", "-out", "r.tk")
    return read("r.tk")


def tst_info(imprint_hash_oid, digest, gen_time):
    """A TSTInfo (RFC 3161 section 2.4.2) for a time the generator chooses."""
    imprint = tlv(0x30, tlv(0x30, oid(imprint_hash_oid) + tlv(0x05, b"")) + tlv(0x04, digest))
    return tlv(0x30, integer(1) + oid("1.2.3.4.1") + imprint + integer(0x0A0B0C) + gentime(gen_time))


SHA256_OID = "2.16.840.1.101.3.4.2.1"


def custom_token(digest, gen_time, signer="tsa", chain="tsa_chain.pem", md="sha256"):
    """A time-stamp token for any genTime: TSTInfo signed with `openssl cms` (what a TSA's clock
    says cannot be bent in `openssl ts`)."""
    write("tst.der", tst_info(SHA256_OID, digest, gen_time))
    run("openssl", "cms", "-sign", "-binary", "-nodetach", "-in", "tst.der", "-outform", "DER", "-signer", signer + ".crt", "-inkey", signer + ".key", "-certfile", chain, "-md", md, "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-out", "tok.der")
    return read("tok.der")


# a token over a message, and one over each hash
contents["stamped"] = b"tiny_https cms fixture: data that gets time-stamped\n"
for h in ("sha1", "sha256", "sha384", "sha512"):
    blobs[f"token_{h}"] = tsa_token(getattr(hashlib, h)(contents["stamped"]).hexdigest(), h)
blobs["token_rogue_tsa"] = tsa_token(hashlib.sha256(contents["stamped"]).hexdigest(), "sha256", "rogue_tsa", "rogue_tsa_chain.pem")
# a token signed by a certificate that is for code signing and not for time stamping
blobs["token_wrong_eku"] = custom_token(hashlib.sha256(contents["stamped"]).digest(), when(2026, 4, 1) + datetime.timedelta(hours=1), signer="rsa", chain="inter_chain.pem")
blobs["token_custom"] = custom_token(hashlib.sha256(contents["stamped"]).digest(), when(2026, 4, 1) + datetime.timedelta(hours=12, minutes=34, seconds=56))

# signatures carrying a time stamp over their signature value
rsa_der = blobs["rsa_sha256"]
sig = signature_value(rsa_der)
sig_digest = hashlib.sha256(sig).digest()
blobs["rsa_ts"] = with_unsigned_attr(rsa_der, ID_TIMESTAMP_TOKEN, tsa_token(sig_digest.hex()))
blobs["rsa_ts_ms"] = with_unsigned_attr(rsa_der, MS_RFC3161_TIMESTAMP, tsa_token(sig_digest.hex()))
blobs["rsa_ts_wrong_imprint"] = with_unsigned_attr(rsa_der, ID_TIMESTAMP_TOKEN, tsa_token(hashlib.sha256(b"not the signature").hexdigest()))
blobs["rsa_ts_wrong_eku"] = with_unsigned_attr(rsa_der, ID_TIMESTAMP_TOKEN, custom_token(sig_digest, when(2026, 4, 1) + datetime.timedelta(hours=1), signer="rsa", chain="inter_chain.pem"))
blobs["rsa_ts_rogue_tsa"] = with_unsigned_attr(rsa_der, ID_TIMESTAMP_TOKEN, tsa_token(sig_digest.hex(), "sha256", "rogue_tsa", "rogue_tsa_chain.pem"))
# the short-lived signer's key signed on 2026-04-01 (inside its validity) and was time-stamped then
short_der = blobs["short_signed"]
short_digest = hashlib.sha256(signature_value(short_der)).digest()
blobs["short_ts"] = with_unsigned_attr(short_der, ID_TIMESTAMP_TOKEN, custom_token(short_digest, when(2026, 4, 1) + datetime.timedelta(hours=9)))
blobs["short_ts_late"] = with_unsigned_attr(short_der, ID_TIMESTAMP_TOKEN, custom_token(short_digest, when(2026, 7, 1)))
blobs["short_ts_early"] = with_unsigned_attr(short_der, ID_TIMESTAMP_TOKEN, custom_token(short_digest, when(2026, 2, 1)))

# ------------------------------------------------------------------------------------------ JAR blocks

if shutil.which("jarsigner") and shutil.which("keytool"):
    for kind, ext, alg in [("rsa", "RSA", "SHA256withRSA"), ("p256", "EC", "SHA256withECDSA"), ("ed", "EC", "Ed25519")]:
        run("openssl", "pkcs12", "-export", "-inkey", kind + ".key", "-in", kind + ".crt", "-certfile", "tsa_chain.pem", "-name", "signer", "-passout", "pass:changeit", "-out", kind + ".p12")
        jar = f"{kind}.jar"
        with zipfile.ZipFile(path(jar), "w") as z:
            z.writestr("hello.txt", HELLO)
        run("jarsigner", "-keystore", kind + ".p12", "-storetype", "PKCS12", "-storepass", "changeit", "-sigfile", "SIG", "-digestalg", "SHA-256", "-sigalg", alg, jar, "signer")
        with zipfile.ZipFile(path(jar)) as z:
            blobs[f"jar_{kind}"] = z.read(f"META-INF/SIG.{ext}")
            contents[f"jar_{kind}"] = z.read("META-INF/SIG.SF")
else:
    print("no JDK: the JAR fixtures are left out", file=sys.stderr)

if "jar_rsa" in blobs:
    blobs["jar_rsa_alg_swapped"] = edit(blobs["jar_rsa"], swap_digest_alg)
    contents["jar_rsa_alg_swapped"] = contents["jar_rsa"]

# ------------------------------------------------------------------------------------------ output

lines = ["# generated by tools/gen_cms_fixtures.py: signatures made by OpenSSL and the JDK, public data only"]
for name in ("root", "inter", "rsa", "p256", "p384", "ed", "short", "tls", "tsa", "rogue_root", "rogue", "rogue_tsa"):
    lines.append(f"cert {name} {certs[name].public_bytes(serialization.Encoding.DER).hex()}")
for name, data in contents.items():
    lines.append(f"content {name} {data.hex()}")
for name, data in blobs.items():
    lines.append(f"blob {name} {data.hex()}")
with open(OUT, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {OUT}: {len(blobs)} blobs, {os.path.getsize(OUT)} bytes")
shutil.rmtree(W)
