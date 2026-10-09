#!/usr/bin/env python3
"""Writes roots/mozilla.pem, the embedded root store of the `mozilla-roots` feature (BACKLOG B-31), from NSS's certdata.txt.

    curl -sS -o certdata.txt https://raw.githubusercontent.com/nss-dev/nss/master/lib/ckfw/builtins/certdata.txt
    curl -sS -o nssckbi.h https://raw.githubusercontent.com/nss-dev/nss/master/lib/ckfw/builtins/nssckbi.h
    curl -sS -o genname.c https://raw.githubusercontent.com/nss-dev/nss/master/lib/certdb/genname.c
    python3 tools/gen_mozilla_roots.py certdata.txt nssckbi.h genname.c

(github.com/nss-dev/nss is the NSS project's own mirror; certdata.txt is where Firefox's root store comes from.) A root
is kept when its trust object says CKA_TRUST_SERVER_AUTH CKT_NSS_TRUSTED_DELEGATOR: a CA trusted to issue TLS server
certificates. Roots NSS lists as distrusted, or trusted only for e-mail, are left out. Where the certificate object
carries CKA_NSS_SERVER_DISTRUST_AFTER, the date goes into a "# distrust-tls-after:" line above the certificate:
certificates issued (by their notBefore) after it are not trusted under that root, which is how Mozilla winds down a CA
(Entrust, for one). NSS also imposes name constraints on a few roots in its code rather than in certdata.txt
(genname.c, `builtInNameConstraints`: a government root limited to its country's domains); those go into a
"# name-constraints:" line (the extension value, hex), which the library applies as if the root carried it, as NSS does
when the root has none of its own. Uses only the standard library and `openssl` is not needed; the result is checked by
`cargo test --features mozilla-roots --test mozilla_roots`.
"""
import base64
import datetime as dt
import hashlib
import re
import sys


def octal(lines):
    out = bytearray()
    for line in lines:
        for m in re.finditer(r"\\([0-7]{3})", line):
            out.append(int(m.group(1), 8))
    return bytes(out)


def objects(text):
    """Each object of certdata.txt as a dict: attribute -> (type, value); MULTILINE_OCTAL values are bytes."""
    obj, lines, i = None, text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith("BEGINDATA"):
            continue
        parts = line.split(None, 2)
        if parts[0] == "CKA_CLASS":
            if obj is not None:
                yield obj
            obj = {}
        if obj is None:
            continue
        if len(parts) >= 2 and parts[1] == "MULTILINE_OCTAL":
            body = []
            while lines[i] != "END":
                body.append(lines[i])
                i += 1
            i += 1
            obj[parts[0]] = ("MULTILINE_OCTAL", octal(body))
        elif len(parts) == 3:
            obj[parts[0]] = (parts[1], parts[2])
    if obj is not None:
        yield obj


def c_bytes(macro_body):
    """The bytes of the C string literals in a macro body (with \\x escapes), comments and line continuations aside."""
    body = re.sub(r"/\*.*?\*/", "", macro_body, flags=re.S)
    out = bytearray()
    for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', body):
        i = 0
        while i < len(lit):
            if lit[i] == "\\" and lit[i + 1] == "x":
                j = i + 2
                while j < len(lit) and j < i + 4 and lit[j] in "0123456789abcdefABCDEF":
                    j += 1
                out.append(int(lit[i + 2:j], 16))
                i = j
            else:
                out.append(ord(lit[i]))
                i += 1
    return bytes(out)


def imposed_constraints(genname):
    """(subject DN, name constraints value) for each entry of NSS's builtInNameConstraints."""
    text = open(genname).read()
    entries = re.findall(r"NAME_CONSTRAINTS_ENTRY\((\w+)\)", text.split("builtInNameConstraints", 1)[1].split("};", 1)[0])
    out = []
    for ca in entries:
        macro = lambda name: re.search(r"#define %s_%s\s+((?:.*\\\n)*.*)" % (ca, name), text).group(1)
        out.append((ca, c_bytes(macro("SUBJECT_DN")), c_bytes(macro("NAME_CONSTRAINTS"))))
    return out


def subject_der(cert):
    """The subject Name of a DER certificate, as written."""
    def tlv(b, i):
        tag, n = b[i], b[i + 1]
        i += 2
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[i:i + k], "big")
            i += k
        return tag, i, i + n
    _, s, _ = tlv(cert, 0)
    _, i, tbs_end = tlv(cert, s)
    if cert[i] == 0xA0:
        i = tlv(cert, i)[2]
    for _ in range(3):  # serial, signature algorithm, issuer
        i = tlv(cert, i)[2]
    i = tlv(cert, i)[2]  # validity
    start = i
    return cert[start:tlv(cert, i)[2]]


def main():
    certdata, header, genname = sys.argv[1], sys.argv[2], sys.argv[3]
    raw = open(certdata, "rb").read()
    version = re.search(r'NSS_BUILTINS_LIBRARY_VERSION "([^"]+)"', open(header).read()).group(1)
    certs, trust = {}, {}
    for o in objects(raw.decode("utf-8")):
        cls = o["CKA_CLASS"][1]
        if cls == "CKO_CERTIFICATE":
            der = o["CKA_VALUE"][1]
            certs[(o["CKA_ISSUER"][1], o["CKA_SERIAL_NUMBER"][1])] = (o["CKA_LABEL"][1].strip('"'), der, o.get("CKA_NSS_SERVER_DISTRUST_AFTER"))
        elif cls == "CKO_NSS_TRUST":
            trust[(o["CKA_ISSUER"][1], o["CKA_SERIAL_NUMBER"][1])] = (o["CKA_TRUST_SERVER_AUTH"][1], o.get("CKA_CERT_SHA1_HASH"))
    kept, distrusted = [], 0
    for key, (label, der, distrust) in certs.items():
        server, sha1 = trust.get(key, (None, None))
        if server != "CKT_NSS_TRUSTED_DELEGATOR":
            continue
        assert sha1 is None or sha1[1] == hashlib.sha1(der).digest(), label
        after = None
        if distrust and distrust[0] == "MULTILINE_OCTAL":
            text = distrust[1].decode()
            after = dt.datetime.strptime(text, "%y%m%d%H%M%SZ").replace(tzinfo=dt.timezone.utc)
            distrusted += 1
        kept.append((label, der, after))
    kept.sort(key=lambda k: k[0].lower())
    imposed = {}
    for ca, dn, nc in imposed_constraints(genname):
        match = [label for label, der, _ in kept if subject_der(der) == dn]
        print("NSS imposes name constraints on %s: %s" % (ca, ", ".join(match) or "not in the store"))
        for label in match:
            imposed[label] = nc
    out = [
        "# Mozilla's root store for TLS server authentication: the certificates NSS trusts as CAs for it",
        "# (CKA_TRUST_SERVER_AUTH CKT_NSS_TRUSTED_DELEGATOR), from NSS's certdata.txt, builtins version %s" % version,
        "# (SHA-256 %s), taken from https://raw.githubusercontent.com/nss-dev/nss/master/lib/ckfw/builtins/certdata.txt" % hashlib.sha256(raw).hexdigest(),
        "# by tools/gen_mozilla_roots.py. NSS is under the Mozilla Public License 2.0; certificates are public data.",
        "# A \"distrust-tls-after\" line: certificates issued (by their notBefore) after that time are not trusted under the root.",
        "# builtins-version: %s" % version,
        "# roots: %d" % len(kept),
        "",
    ]
    for label, der, after in kept:
        out.append("# " + label)
        out.append("# sha256: " + hashlib.sha256(der).hexdigest())
        if after is not None:
            out.append("# distrust-tls-after: %d (%s)" % (int(after.timestamp()), after.strftime("%Y-%m-%dT%H:%M:%SZ")))
        if label in imposed:
            out.append("# name-constraints: " + imposed[label].hex())
        b64 = base64.b64encode(der).decode()
        out.append("-----BEGIN CERTIFICATE-----")
        out.extend(b64[i:i + 64] for i in range(0, len(b64), 64))
        out.append("-----END CERTIFICATE-----")
        out.append("")
    open("roots/mozilla.pem", "w").write("\n".join(out))
    print("wrote roots/mozilla.pem: %d roots (NSS builtins %s), %d with a TLS distrust date" % (len(kept), version, distrusted))


main()
