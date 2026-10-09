#!/bin/sh
# rekor_capture.sh - captures Sigstore's Rekor transparency-log public key and its current checkpoint
# (signed tree head), checks them, and packs everything up as fixtures for pratique (backlog B-71).
#
#   sh rekor_capture.sh              # writes ./rekor-capture/ and ./rekor-capture.tgz
#   sh rekor_capture.sh OUTDIR       # somewhere else
#   sh rekor_capture.sh --selftest   # only the offline self-checks (no network)
#
# It needs curl and python3 (the standard library only), both of which a Mac with the Xcode command line
# tools has. openssl is used as a second opinion on the signature when it is there. It sends nothing
# anywhere but plain GET requests to rekor.sigstore.dev (and log2025-1.rekor.sigstore.dev), and it
# reads and writes nothing outside the output directory. Everything it saves is public data.
#
# What it does:
#   1. GET /api/v1/log/publicKey and /api/v1/log (the checkpoint is the "signedTreeHead" field);
#   2. checks the checkpoint's ECDSA P-256 signature with the key it just downloaded, with pure Python
#      and (if openssl is present) with openssl, and that the key is the one in Sigstore's trusted root;
#   3. asks Rekor for a consistency proof between an older checkpoint (the one in the Lazaret npm
#      provenance bundle, tree size 2953640305) and the current one, and checks that proof itself
#      (RFC 9162 section 2.1.4.2), so the log is shown to have only grown;
#   4. tries the newer Rekor v2 log's checkpoint (Ed25519) and saves whatever it answers;
#   5. writes summary.txt and packs the directory into OUTDIR.tgz.
# Send OUTDIR.tgz (or just summary.txt) back.

set -u

if [ "${1:-}" = "--selftest" ]; then
    MODE=selftest
    OUT=.
else
    MODE=capture
    OUT=${1:-rekor-capture}
fi
BASE=${REKOR_URL:-https://rekor.sigstore.dev}
V2=${REKOR_V2_URL:-https://log2025-1.rekor.sigstore.dev}

command -v python3 >/dev/null 2>&1 || { echo "python3 is needed (on a Mac: xcode-select --install)" >&2; exit 2; }

if [ "$MODE" = capture ]; then
    command -v curl >/dev/null 2>&1 || { echo "curl is needed" >&2; exit 2; }
    mkdir -p "$OUT" || exit 2
    echo "== fetching from $BASE"
    curl -fsS --max-time 30 -H 'Accept: application/x-pem-file' -o "$OUT/publickey.pem" "$BASE/api/v1/log/publicKey" || echo "  (public key: download failed)"
    curl -fsS --max-time 30 -H 'Accept: application/json' -o "$OUT/log.json" "$BASE/api/v1/log" || echo "  (log info: download failed)"
    # the consistency proof needs the current size, which only the python part knows: it asks for it itself
    curl -sS --max-time 30 -o "$OUT/v2_checkpoint.txt" -w '  v2 checkpoint: HTTP %{http_code}\n' "$V2/checkpoint" || echo "  (v2 checkpoint: no answer)"
fi

REKOR_BASE="$BASE" REKOR_OUT="$OUT" REKOR_MODE="$MODE" python3 - <<'PYEOF'
import base64, hashlib, json, os, re, shutil, subprocess, sys, tempfile

BASE = os.environ["REKOR_BASE"]
OUT = os.environ["REKOR_OUT"]
MODE = os.environ["REKOR_MODE"]

# ------------------------------------------------------------------------- things pinned in this script
# The key from Sigstore's production trusted root (sigstore-python's copy of the TUF metadata), and a
# checkpoint made with it that sits in the real Lazaret 0.1.8 npm provenance bundle: the self-test and the
# "older checkpoint" of the consistency proof.
PINNED_SPKI_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
OLD_CHECKPOINT = (
    "rekor.sigstore.dev - 1193050959916656506\n2953640305\nWUnuMvULV/uEfj+CnxWtVytWRpDCsoSYmUypvVwKV9w=\n\n"
    "— rekor.sigstore.dev wNI9ajBEAiBUbiamcWJlKdwxHGirS8kcVNWoQVHi7j0pCks429vchwIgB2eVETid+Uqbl7LO/UN7lEmlMZGR9FnjqfEP8ctywDY=\n"
)
SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

report = []
problems = []


def say(line=""):
    print(line)
    report.append(line)


def fail(what):
    problems.append(what)
    say("  FAIL: " + what)


# ------------------------------------------------------------------------------------ ECDSA P-256 (pure)
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def ec_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = ec_add(r, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return r


def on_curve(pt):
    return (pt[1] * pt[1] - (pt[0] ** 3 + A * pt[0] + B)) % P == 0


def der_len(b, i):
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return n, i


def parse_der_sig(sig):
    if sig[0] != 0x30:
        raise ValueError("not a SEQUENCE")
    n, i = der_len(sig, 1)
    if i + n != len(sig):
        raise ValueError("length")
    out = []
    for _ in range(2):
        if sig[i] != 0x02:
            raise ValueError("not an INTEGER")
        n, i = der_len(sig, i + 1)
        out.append(int.from_bytes(sig[i:i + n], "big"))
        i += n
    if i != len(sig):
        raise ValueError("trailing bytes")
    return out


def p256_key(spki):
    if len(spki) != 91 or not spki.startswith(SPKI_P256_PREFIX) or spki[26] != 4:
        raise ValueError("not an uncompressed P-256 SubjectPublicKeyInfo")
    q = (int.from_bytes(spki[27:59], "big"), int.from_bytes(spki[59:91], "big"))
    if not on_curve(q):
        raise ValueError("point is not on the curve")
    return q


def ecdsa_verify(q, msg, der_sig):
    if isinstance(msg, str):
        msg = msg.encode()
    try:
        r, s = parse_der_sig(der_sig)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, N)
    x = ec_add(ec_mul(e * w % N, G), ec_mul(r * w % N, q))
    return x is not None and x[0] % N == r


# -------------------------------------------------------------------------------------- signed notes
def split_note(text):
    """The signed text, and the (name, hint, signature) of each signature line."""
    if "\n\n" not in text:
        raise ValueError("no blank line between the text and the signatures")
    body, sigs = text.split("\n\n", 1)
    body += "\n"
    out = []
    for line in sigs.split("\n"):
        if not line:
            continue
        if not line.startswith("— "):
            raise ValueError("a signature line must start with an em dash")
        name, b64 = line[2:].split(" ", 1)
        raw = base64.b64decode(b64, validate=True)
        out.append((name, raw[:4], raw[4:]))
    return body, out


def checkpoint_fields(body):
    lines = body.split("\n")
    origin, size, root = lines[0], int(lines[1]), base64.b64decode(lines[2], validate=True)
    if str(size) != lines[1] or len(root) != 32:
        raise ValueError("size or root hash malformed")
    return origin, size, root


def openssl_verify(pem_path, body, der_sig):
    exe = shutil.which("openssl")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "m"), "wb").write(body)
        open(os.path.join(d, "s"), "wb").write(der_sig)
        r = subprocess.run([exe, "dgst", "-sha256", "-verify", pem_path, "-signature", os.path.join(d, "s"), os.path.join(d, "m")],
                           capture_output=True, text=True)
        return r.returncode == 0 and "Verified OK" in (r.stdout + r.stderr)


# ------------------------------------------------------------------------------------ Merkle trees
def h_leaf(d):
    return hashlib.sha256(b"\x00" + d).digest()


def h_node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def verify_consistency(first, second, root1, root2, proof):
    """RFC 9162 section 2.1.4.2: is the tree of `second` leaves with root `root2` an extension of the tree
    of `first` leaves with root `root1`, given `proof`?"""
    if first < 1 or second < first:
        return False
    if first == second:
        return not proof and root1 == root2
    if not proof:
        return False
    proof = list(proof)
    if first & (first - 1) == 0:
        proof.insert(0, root1)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = h_node(c, fr)
            sr = h_node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = h_node(sr, c)
        fn >>= 1
        sn >>= 1
    return fn == 0 and fr == root1 and sr == root2


def mth(leaves):
    if len(leaves) == 1:
        return h_leaf(leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return h_node(mth(leaves[:k]), mth(leaves[k:]))


def consistency_proof(m, leaves):
    """RFC 6962 section 2.1.2, the recursive definition: an independent way to make proofs for the self-test."""
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    return sub(m, leaves, True)


def hash_value(s):
    """Rekor's REST API writes hashes in hex; a protobuf JSON bundle writes them in Base64."""
    if re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return bytes.fromhex(s)
    return base64.b64decode(s, validate=True)


# ----------------------------------------------------------------------------------------- self-test
def selftest():
    say("== self-test (offline)")
    q = p256_key(base64.b64decode(PINNED_SPKI_B64))
    body, sigs = split_note(OLD_CHECKPOINT)
    name, hint, sig = sigs[0]
    ok = ecdsa_verify(q, body, sig)
    say("  the real checkpoint from the Lazaret bundle verifies with the pinned key: %s" % ("yes" if ok else "NO"))
    if not ok:
        problems.append("self-test: known checkpoint does not verify")
    bad = bytearray(body.encode())
    bad[30] ^= 1
    if ecdsa_verify(q, bytes(bad), sig):
        problems.append("self-test: a damaged checkpoint verified")
    say("  a damaged copy is refused: %s" % ("yes" if not ecdsa_verify(q, bytes(bad), sig) else "NO"))
    spki = base64.b64decode(PINNED_SPKI_B64)
    say("  key hint %s = first 4 bytes of the key's SHA-256: %s" % (hint.hex(), "yes" if hashlib.sha256(spki).digest()[:4] == hint else "NO"))
    if hashlib.sha256(spki).digest()[:4] != hint:
        problems.append("self-test: key hint")
    bad_proofs = 0
    checked = 0
    for second in range(1, 41):
        leaves = [b"leaf %d" % i for i in range(second)]
        r2 = mth(leaves)
        for first in range(1, second + 1):
            proof = consistency_proof(first, leaves) if first < second else []
            r1 = mth(leaves[:first])
            checked += 1
            if not verify_consistency(first, second, r1, r2, proof):
                bad_proofs += 1
            if proof:
                broken = proof[:-1] + [bytes([proof[-1][0] ^ 1]) + proof[-1][1:]]
                if verify_consistency(first, second, r1, r2, broken):
                    bad_proofs += 1
                if verify_consistency(first, second, r1, mth(leaves[:-1] + [b"other"]), proof):
                    bad_proofs += 1
    say("  consistency proofs for every pair of sizes up to 40 (%d), and damaged ones refused: %s" % (checked, "yes" if bad_proofs == 0 else "NO (%d wrong)" % bad_proofs))
    if bad_proofs:
        problems.append("self-test: consistency proofs")


# -------------------------------------------------------------------------------------------- capture
def get(url):
    # through curl, like the other downloads, so that it uses the system's certificate store
    r = subprocess.run(["curl", "-fsS", "--max-time", "30", "-H", "Accept: application/json", url], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode("utf-8", "replace").strip() or "curl failed")
    return r.stdout


def capture():
    say("== the key")
    pem_path = os.path.join(OUT, "publickey.pem")
    try:
        pem = open(pem_path).read()
        der = base64.b64decode("".join(l for l in pem.splitlines() if "-----" not in l))
        q = p256_key(der)
    except Exception as e:  # noqa
        fail("public key missing or not an uncompressed P-256 key (%s)" % e)
        return
    say("  ECDSA P-256 key, SHA-256 of its SubjectPublicKeyInfo: %s" % base64.b64encode(hashlib.sha256(der).digest()).decode())
    if der == base64.b64decode(PINNED_SPKI_B64):
        say("  identical to the key in Sigstore's production trusted root")
    else:
        fail("the server's key is NOT the one in Sigstore's trusted root (the log may have rotated its key: send this back)")

    say("== the checkpoint")
    try:
        info = json.load(open(os.path.join(OUT, "log.json")))
        text = info["signedTreeHead"]
        body, sigs = split_note(text)
        origin, size, root = checkpoint_fields(body)
    except Exception as e:  # noqa
        fail("log info missing or malformed (%s)" % e)
        return
    open(os.path.join(OUT, "checkpoint.txt"), "w", newline="\n").write(text)
    say("  origin %s, tree size %d, root %s" % (origin, size, base64.b64encode(root).decode()))
    if int(info.get("treeSize", -1)) != size or hash_value(info["rootHash"]) != root:
        fail("the log info's treeSize and rootHash disagree with the checkpoint")
    mine = [s for s in sigs if s[1] == hashlib.sha256(der).digest()[:4]]
    say("  %d signature line(s), %d with this key's hint" % (len(sigs), len(mine)))
    if not mine:
        fail("no signature line carries this key's hint")
    for name, hint, sig in mine:
        ok = ecdsa_verify(q, body.encode(), sig)
        say("  signature by %s: pure-Python check %s" % (name, "VERIFIES" if ok else "does NOT verify"))
        if not ok:
            fail("the checkpoint's signature does not verify")
        o = openssl_verify(pem_path, body.encode(), sig)
        if o is None:
            say("  (openssl not found: no second opinion)")
        else:
            say("  openssl check %s" % ("VERIFIES" if o else "does NOT verify"))
            if o != ok:
                fail("openssl and the pure-Python check disagree")

    say("== consistency with an older checkpoint")
    old_body, _ = split_note(os.environ.get("REKOR_OLD_CHECKPOINT", OLD_CHECKPOINT))
    _, old_size, old_root = checkpoint_fields(old_body)
    if old_size > size:
        say("  the older checkpoint (tree size %d) is LARGER than the current one: not comparable" % old_size)
        fail("the log is smaller than it was")
    elif old_size == size:
        say("  same size as the older checkpoint")
        if old_root != root:
            fail("same tree size, different root: a fork")
    else:
        tree_id = origin.rsplit(" ", 1)[-1] if origin.rsplit(" ", 1)[-1].isdigit() else str(info.get("treeID", ""))
        url = "%s/api/v1/log/proof?firstSize=%d&lastSize=%d&treeID=%s" % (BASE, old_size, size, tree_id)
        try:
            raw = get(url)
            open(os.path.join(OUT, "consistency_proof.json"), "wb").write(raw)
            pj = json.loads(raw)
            hashes = [hash_value(x) for x in pj["hashes"]]
            ok = verify_consistency(old_size, size, old_root, root, hashes)
            say("  proof from size %d to %d (%d hashes): %s" % (old_size, size, len(hashes), "VERIFIES" if ok else "does NOT verify"))
            if not ok:
                fail("the consistency proof does not verify")
        except Exception as e:  # noqa
            say("  could not get a consistency proof (%s): not a problem for the fixtures" % e)

    say("== the v2 log")
    try:
        t = open(os.path.join(OUT, "v2_checkpoint.txt"), "rb").read().decode("utf-8", "replace")
    except OSError:
        t = ""
    if "\n\n" in t and "— " in t:
        lines = t.split("\n")
        say("  checkpoint saved: origin %s, size %s (an Ed25519 note: checked later with pratique)" % (lines[0], lines[1]))
    else:
        say("  no checkpoint there (answer: %r); that is fine" % t[:80])


if MODE == "selftest":
    selftest()
else:
    say("rekor_capture: %s" % BASE)
    selftest()
    capture()
    say("")
    say("RESULT: " + ("all checks passed" if not problems else "%d problem(s): %s" % (len(problems), "; ".join(problems))))
    open(os.path.join(OUT, "summary.txt"), "w").write("\n".join(report) + "\n")
if MODE == "selftest":
    print("RESULT: " + ("all checks passed" if not problems else "problems: " + "; ".join(problems)))
sys.exit(1 if problems else 0)
PYEOF
status=$?

if [ "$MODE" = capture ]; then
    tar -czf "$OUT.tgz" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null && echo "wrote $OUT.tgz"
fi
exit $status
