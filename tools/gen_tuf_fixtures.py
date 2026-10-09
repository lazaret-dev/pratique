#!/usr/bin/env python3
"""Generates tests/data/tuf/synthetic.json (BACKLOG B-82): TUF repositories made with python-tuf, the reference
implementation, each with a bootstrap root, the files a client would fetch, metadata a client kept from before (for the
rollback checks), a target to look up, the verdict pratique must reach, and the verdict python-tuf's own client
(`tuf.ngclient.Updater`) reached on the same bytes at the same time.

    pip install tuf==6.0.0          (securesystemslib 1.x and cryptography come with it)
    python3 tools/gen_tuf_fixtures.py

The generator stops if python-tuf does not reach the verdict a case expects (accept, refuse, or "not found"), except in
the cases marked `differs`, where pratique is stricter or more tolerant on purpose (the module documentation of
`pratique::tuf` lists those). Keys are made on every run, so the file changes when it is rerun; only public data is
written. Files are stored once by their SHA-256 (`blobs`) and named by it in each case.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric import ec
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import DelegatedRole, Delegations, Metadata, MetaFile, Root, Snapshot, TargetFile, Targets, Timestamp
from tuf.api.serialization.json import JSONSerializer
from tuf.api import exceptions
from tuf.ngclient import FetcherInterface, Updater

OUT = "tests/data/tuf/synthetic.json"
UTC = dt.timezone.utc
REF = dt.datetime(2026, 10, 8, 12, 0, 0, tzinfo=UTC)
NOW = int(REF.timestamp())
FAR = REF + dt.timedelta(days=365)
PAST = REF - dt.timedelta(days=1)
PRETTY = JSONSerializer(compact=False)


def ecdsa(scheme="ecdsa-sha2-nistp256"):
    return CryptoSigner.generate_ecdsa(scheme=scheme)


def with_identity(signer, keyid=None, keytype=None):
    """The same private key under another key id or the legacy keytype."""
    k = signer.public_key
    pub = SSlibKey(keyid or k.keyid, keytype or k.keytype, k.scheme, dict(k.keyval))
    return CryptoSigner(signer._private_key, pub)


ROOT1 = [ecdsa() for _ in range(3)]
ROOT2 = [ecdsa("ecdsa-sha2-nistp384") for _ in range(3)]
TS, TS2 = CryptoSigner.generate_ed25519(), CryptoSigner.generate_ed25519()
SNAP = ecdsa("ecdsa-sha2-nistp384")
TGT = [CryptoSigner.generate_rsa(scheme="rsassa-pss-sha256", size=2048), CryptoSigner.generate_ed25519()]
TGT_PKCS1 = CryptoSigner.generate_rsa(scheme="rsa-pkcs1v15-sha256", size=2048)
NPM = ecdsa()
OTHER = ecdsa("ecdsa-sha2-nistp521")
ROGUE = ecdsa()

TRUSTED_ROOT = b'{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": []}\n'
NPM_KEYS = b'{"keys": [{"keyId": "SHA256:example", "keyUsage": "npm:attestations"}]}\n'


def base():
    """The repository most cases change one thing of: root v1 (three P-256 root keys, threshold 2), an Ed25519 timestamp
    key, a P-384 snapshot key, two targets keys (RSA-PSS and Ed25519, threshold 1), consistent snapshots, and the
    delegated role `registry.npmjs.org` (one P-256 key, terminating, `registry.npmjs.org/*`)."""
    return {
        "consistent": True,
        "roots": [dict(version=1, root_keys=ROOT1, threshold=2, sign=ROOT1[:2], expires=FAR, ts=[TS], snap=[SNAP], tgt=TGT, tgt_threshold=1)],
        "ts": dict(version=1, expires=FAR, snap_version=None, hashes=False, length=False, sign=None, spec="1.0"),
        "snap": dict(version=1, expires=FAR, hashes=False, versions={}, drop=[], sign=None),
        "tgt": dict(version=1, expires=FAR, sign=None, targets={"trusted_root.json": TRUSTED_ROOT, "a/b.txt": b"hello\n"}, algs=["sha256", "sha512"]),
        "roles": [
            dict(name="registry.npmjs.org", by="targets", keys=[NPM], threshold=1, terminating=True, paths=["registry.npmjs.org/*"], targets={"registry.npmjs.org/keys.json": NPM_KEYS}, version=1, expires=FAR, sign=[NPM])
        ],
        "serve_roots": None,
        "post": None,
    }


def root_md(r, consistent):
    root = Root(version=r["version"], expires=r["expires"], consistent_snapshot=consistent)
    for role in ["root", "timestamp", "snapshot", "targets"]:
        root.roles[role].keyids = []
    for s in r["root_keys"]:
        root.add_key(s.public_key, "root")
    root.roles["root"].threshold = r["threshold"]
    for s in r["ts"]:
        root.add_key(s.public_key, "timestamp")
    for s in r["snap"]:
        root.add_key(s.public_key, "snapshot")
    for s in r["tgt"]:
        root.add_key(s.public_key, "targets")
    root.roles["targets"].threshold = r["tgt_threshold"]
    if "mod" in r:
        r["mod"](root)
    md = Metadata(root)
    sign(md, r["sign"])
    return md


_SIGNATURES = {}


def sign(md, signers):
    """Signs, reusing the signature of the same bytes by the same key (ECDSA signatures are random): unchanged metadata is
    the same file in every case, which keeps the fixture file small."""
    payload = md.signed_bytes
    for s in signers:
        k = (payload, s.public_key.keyid)
        if k not in _SIGNATURES:
            _SIGNATURES[k] = md.sign(s, append=True)
        md.signatures[s.public_key.keyid] = _SIGNATURES[k]


def to_bytes(md):
    return md.to_bytes(PRETTY)


def meta_name(name, version, consistent):
    return f"{version}.{quote(name, '')}.json" if consistent else f"{quote(name, '')}.json"


def render(st):
    """The files of a repository state: `metadata/...` and `targets/...`, and the bootstrap root."""
    files = {}
    roots = [to_bytes(root_md(r, st["consistent"])) for r in st["roots"]]
    for i, (r, b) in enumerate(zip(st["roots"], roots)):
        if st["serve_roots"] is None or r["version"] in st["serve_roots"]:
            files[f"metadata/{r.get('file_version', r['version'])}.root.json"] = b
    final = st["roots"][-1]
    consistent = st["consistent"]

    def serve_target(path, data, hashes_first):
        if consistent:
            d, sep, name = path.rpartition("/")
            files[f"targets/{d}{sep}{hashes_first}.{name}"] = data
        else:
            files[f"targets/{path}"] = data

    # delegated roles, innermost first so that their delegations are known
    role_bytes = {}
    for d in st["roles"]:
        t = Targets(version=d["version"], expires=d["expires"])
        for path, data in d["targets"].items():
            t.targets[path] = TargetFile.from_data(path, data, ["sha256"])
        children = [c for c in st["roles"] if c["by"] == d["name"]]
        if children:
            t.delegations = delegations(children)
        md = Metadata(t)
        sign(md, d["sign"])
        role_bytes[d["name"]] = (d["version"], to_bytes(md))
        for path, data in d["targets"].items():
            serve_target(path, d.get("serve", {}).get(path, data), hashlib.sha256(data).hexdigest())
    tg = st["tgt"]
    top = Targets(version=tg["version"], expires=tg["expires"])
    for path, data in tg["targets"].items():
        top.targets[path] = TargetFile.from_data(path, data, tg["algs"])
        if "extra_hashes" in tg:
            top.targets[path].hashes.update(tg["extra_hashes"])
    top_children = [c for c in st["roles"] if c["by"] == "targets"]
    if top_children:
        top.delegations = delegations(top_children)
    md = Metadata(top)
    sign(md, tg["sign"] or final["tgt"][: final["tgt_threshold"]])
    top_bytes = to_bytes(md)
    for path, data in tg["targets"].items():
        serve_target(path, tg.get("serve", {}).get(path, data), hashlib.sha256(data).hexdigest())
    # snapshot
    sn = st["snap"]
    snap = Snapshot(version=sn["version"], expires=sn["expires"])
    listed = {"targets": (tg["version"], top_bytes)}
    listed.update(role_bytes)
    snap.meta = {}
    for name, (v, b) in listed.items():
        if name in sn["drop"]:
            continue
        v_meta = sn["versions"].get(name, v)
        snap.meta[f"{name}.json"] = MetaFile.from_data(v_meta, b, ["sha256"]) if sn["hashes"] else MetaFile(v_meta)
        files[f"metadata/{meta_name(name, v_meta, consistent)}"] = b
    for name, mf in sn.get("extra", {}).items():
        snap.meta[name] = mf
    md = Metadata(snap)
    sign(md, sn["sign"] or final["snap"])
    snap_bytes = to_bytes(md)
    # timestamp
    t = st["ts"]
    snap_v = t["snap_version"] or sn["version"]
    files[f"metadata/{meta_name('snapshot', snap_v, consistent)}"] = snap_bytes
    ts = Timestamp(version=t["version"], expires=t["expires"], snapshot_meta=MetaFile(snap_v))
    if t["hashes"] or t["length"]:
        h = MetaFile.from_data(snap_v, t.get("hash_of", snap_bytes), ["sha256"])
        ts.snapshot_meta = MetaFile(snap_v, (len(snap_bytes) + t.get("length_delta", 0)) if t["length"] else None, h.hashes if t["hashes"] else None)
    ts.spec_version = t["spec"]
    md = Metadata(ts)
    sign(md, t["sign"] or final["ts"])
    ts_bytes = to_bytes(md)
    if t.get("duplicate_signature"):
        doc = json.loads(ts_bytes)
        doc["signatures"].append(dict(doc["signatures"][0]))
        ts_bytes = json.dumps(doc, indent=1).encode()
    files["metadata/timestamp.json"] = ts_bytes
    if st["post"]:
        st["post"](files)
    return files, roots[0], {"timestamp": ts_bytes, "snapshot": snap_bytes}


def delegations(children):
    keys, roles = {}, {}
    for c in children:
        for s in c["keys"]:
            keys[s.public_key.keyid] = s.public_key
        roles[c["name"]] = DelegatedRole(c["name"], [s.public_key.keyid for s in c["keys"]], c["threshold"], c["terminating"], paths=c.get("paths"), path_hash_prefixes=c.get("prefixes"))
    return Delegations(keys=keys, roles=roles)


# ------------------------------------------------------------------------------------------ python-tuf's verdict


class DictFetcher(FetcherInterface):
    def __init__(self, files):
        self.files = files

    def _fetch(self, url):
        path = url.split("https://repo.test/", 1)[1]
        if path not in self.files:
            raise exceptions.DownloadHTTPError("not found", 404)
        return iter([self.files[path]])


def python_verdict(files, bootstrap, local, target, content):
    d = tempfile.mkdtemp(prefix="tufcase")
    try:
        md, td = os.path.join(d, "metadata"), os.path.join(d, "targets")
        os.mkdir(md)
        os.mkdir(td)
        open(os.path.join(md, "root.json"), "wb").write(bootstrap)
        for name, b in local.items():
            open(os.path.join(md, f"{name}.json"), "wb").write(b)
        try:
            u = Updater(md, "https://repo.test/metadata/", td, "https://repo.test/targets/", fetcher=DictFetcher(files))
            u._trusted_set.reference_time = REF
            u.refresh()
            info = u.get_targetinfo(target)
            if info is None:
                return "notfound"
            got = open(u.download_target(info), "rb").read()
            assert got == content, "python-tuf took other bytes than the case's target"
            return "ok"
        except Exception as e:  # noqa: BLE001 - any refusal is a verdict
            return f"error: {type(e).__name__}: {str(e)[:160]}"
    finally:
        shutil.rmtree(d)


# ------------------------------------------------------------------------------------------ cases

blobs = {}
cases = []


def case(name, why, state, expect="ok", reason=None, target="trusted_root.json", content=TRUSTED_ROOT, local=None, differs=None):
    """A case from a repository state, or from `(files, bootstrap)` already rendered."""
    files, bootstrap = state if isinstance(state, tuple) else render(state)[:2]
    local = local or {}
    py = python_verdict(files, bootstrap, local, target, content)
    want = {"ok": "ok", "notfound": "notfound"}.get(expect, "error")
    got = py if py in ("ok", "notfound") else "error"
    if differs:
        assert got != want, f"{name}: marked as differing from python-tuf, but python-tuf agrees ({py})"
    else:
        assert got == want, f"{name}: python-tuf says {py}, the case expects {expect}"
    assert (expect in ("ok", "notfound")) == (reason is None), f"{name}: a refusal needs a reason"

    def blob(b):
        h = hashlib.sha256(b).hexdigest()
        blobs[h] = base64.b64encode(b).decode()
        return h

    c = {"name": name, "why": why, "bootstrap": blob(bootstrap), "files": {p: blob(b) for p, b in sorted(files.items())}, "local": {k: blob(v) for k, v in local.items()}, "target": target, "content": blob(content), "expect": expect, "python": py}
    if reason:
        c["reason"] = reason
    if differs:
        c["differs"] = differs
    cases.append(c)


def st(**changes):
    s = base()
    for k, v in changes.items():
        if k in ("ts", "snap", "tgt"):
            s[k].update(v)
        else:
            s[k] = v
    return s


def root(version, **kw):
    r = dict(version=version, root_keys=ROOT1, threshold=2, sign=ROOT1[:2], expires=FAR, ts=[TS], snap=[SNAP], tgt=TGT, tgt_threshold=1)
    r.update(kw)
    return r


def npm(**kw):
    r = dict(base()["roles"][0])
    r.update(kw)
    return r


def local_of(**changes):
    """The timestamp and snapshot of another state of the repository, as a client would have kept them."""
    _, _, l = render(st(**changes))
    return l


# --- what verifies
case("the trusted root", "the default repository: three rounds of metadata, a target with two hashes", st())
case("npm's keys through the delegated role", "a terminating delegation to the role that may say where registry.npmjs.org/* is", st(), target="registry.npmjs.org/keys.json", content=NPM_KEYS)
case("a file of the top-level targets", "", st(), target="a/b.txt", content=b"hello\n")
case(
    "two root rotations",
    "root keys move to P-384 (each new root signed by the old keys and the new), the timestamp key is replaced",
    st(roots=[root(1), root(2, root_keys=ROOT2, sign=ROOT1[:2] + ROOT2[:2]), root(3, root_keys=ROOT2, sign=ROOT2[:2], ts=[TS2])]),
)
case("an expired root in the middle of the chain", "only the last root must be current", st(roots=[root(1), root(2, expires=PAST), root(3)]))
case("an expired bootstrap root", "it is the start of the chain, not the end", st(roots=[root(1, expires=PAST), root(2)]))
case("the rotation stops at the first missing root", "2.root.json is not there, so 3.root.json is never asked for", st(roots=[root(1), root(2), root(3, expires=PAST)], serve_roots=[1, 3]))
case("hashes and lengths everywhere", "the timestamp gives the snapshot's length and hash, the snapshot the targets files' hashes", st(ts=dict(hashes=True, length=True), snap=dict(hashes=True)))
case("a repository without consistent snapshots", "unversioned metadata names, targets by path", st(consistent=False))
case("an RSA PKCS#1 v1.5 targets key", "rsa-pkcs1v15-sha256", st(roots=[root(1, tgt=[TGT_PKCS1])]))
case("the legacy ECDSA keytype", "keytype ecdsa-sha2-nistp256, as old Sigstore roots have", st(roles=[npm(keys=[with_identity(NPM, keytype="ecdsa-sha2-nistp256")], sign=[with_identity(NPM, keytype="ecdsa-sha2-nistp256")])]), target="registry.npmjs.org/keys.json", content=NPM_KEYS)
case("a P-521 delegation key", "ecdsa-sha2-nistp521", st(roles=[npm(keys=[OTHER], sign=[OTHER])]), target="registry.npmjs.org/keys.json", content=NPM_KEYS)
case("expires one second from now", "", st(ts=dict(expires=REF + dt.timedelta(seconds=1))))
case("older metadata kept from before", "a timestamp and snapshot of version 1, the repository at version 2", st(ts=dict(version=2), snap=dict(version=2)), local=local_of())
# the snapshot kept from before is the current one: the repository's copy is taken away to show it is not fetched
_files, _boot, _local = render(st())
_files.pop("metadata/1.snapshot.json")
case("the snapshot kept from before is the current one", "it is used as it is: the repository's copy is not even there", (_files, _boot), local=_local)
# a timestamp kept from before, signed with a key the new root replaced
case(
    "a kept timestamp under a key that was rotated away",
    "it no longer verifies, so it is dropped and does not block the newer key's lower version",
    st(roots=[root(1), root(2, ts=[TS2])], ts=dict(version=2)),
    local={"timestamp": local_of(ts=dict(version=9))["timestamp"]},
)
case("delegations in order: a non-terminating role without it, then one with it", "", st(roles=[
    dict(name="first", by="targets", keys=[NPM], threshold=1, terminating=False, paths=["x/*"], targets={}, version=1, expires=FAR, sign=[NPM]),
    dict(name="second", by="targets", keys=[OTHER], threshold=1, terminating=False, paths=["x/*"], targets={"x/f": b"second\n"}, version=1, expires=FAR, sign=[OTHER]),
]), target="x/f", content=b"second\n")
case("the first role that has it wins", "a later role's file of the same name is not looked at", st(roles=[
    dict(name="first", by="targets", keys=[NPM], threshold=1, terminating=False, paths=["x/*"], targets={"x/f": b"first\n"}, version=1, expires=FAR, sign=[NPM]),
    dict(name="second", by="targets", keys=[OTHER], threshold=1, terminating=False, paths=["x/*"], targets={"x/f": b"second\n"}, version=1, expires=FAR, sign=[OTHER]),
]), target="x/f", content=b"first\n")
case("a nested delegation", "x/* to outer, x/* again to inner, which has it", st(roles=[
    dict(name="outer", by="targets", keys=[NPM], threshold=1, terminating=False, paths=["x/*"], targets={}, version=1, expires=FAR, sign=[NPM]),
    dict(name="inner", by="outer", keys=[OTHER], threshold=1, terminating=False, paths=["x/*"], targets={"x/f": b"inner\n"}, version=1, expires=FAR, sign=[OTHER]),
]), target="x/f", content=b"inner\n")
_p = hashlib.sha256(b"p/f").hexdigest()[:2]
case("a delegation by path hash prefix", "path_hash_prefixes: the SHA-256 of the target's path", st(roles=[
    dict(name="bin", by="targets", keys=[NPM], threshold=1, terminating=False, prefixes=["zz", _p], targets={"p/f": b"bin\n"}, version=1, expires=FAR, sign=[NPM]),
]), target="p/f", content=b"bin\n")
case("a role name that has to be quoted", "its metadata is fetched as 1.a%20b%2Fc.json", st(roles=[
    dict(name="a b/c", by="targets", keys=[NPM], threshold=1, terminating=False, paths=["q/*"], targets={"q/f": b"quoted\n"}, version=1, expires=FAR, sign=[NPM]),
]), target="q/f", content=b"quoted\n")

# --- not found
case("a path the delegation does not cover", "registry.npmjs.org/* is one segment: the role has the file, but may not say where it is", st(roles=[npm(targets={"registry.npmjs.org/keys.json": NPM_KEYS, "registry.npmjs.org/sub/keys.json": b"deeper\n"})]), "notfound", target="registry.npmjs.org/sub/keys.json", content=b"deeper\n")
case("a terminating role without it ends the search", "the second role has the file and is never asked", st(roles=[
    dict(name="first", by="targets", keys=[NPM], threshold=1, terminating=True, paths=["x/*"], targets={}, version=1, expires=FAR, sign=[NPM]),
    dict(name="second", by="targets", keys=[OTHER], threshold=1, terminating=False, paths=["x/*"], targets={"x/f": b"second\n"}, version=1, expires=FAR, sign=[OTHER]),
]), "notfound", target="x/f", content=b"second\n")
case("a target in no role", "", st(), "notfound", target="nowhere.txt", content=b"")

# --- the root
case("a bootstrap root without enough signatures", "one of the two its own threshold needs", st(roots=[root(1, sign=ROOT1[:1])]), "Signature", reason="root metadata is signed by 1 of its keys and needs 2")
case("a new root signed by the new keys only", "the old root's keys must sign it too", st(roots=[root(1), root(2, root_keys=ROOT2, sign=ROOT2[:2])]), "Signature", reason="root metadata is signed by 0 of its keys and needs 2")
case("a new root signed by the old keys only", "and its own keys too", st(roots=[root(1), root(2, root_keys=ROOT2, sign=ROOT1[:2])]), "Signature", reason="root metadata is signed by 0 of its keys and needs 2")
case("2.root.json with version 3", "a root may not skip a version", st(roots=[root(1), dict(root(3), file_version=2)]), "Version", reason="root metadata has version 3, expected 2")
case("the last root has expired", "a freeze attack: no newer root to be had", st(roots=[root(1), root(2, expires=PAST)]), "Expired", reason="root metadata expired")

# --- the timestamp
case("a timestamp by another key", "", st(ts=dict(sign=[ROGUE])), "Signature", reason="timestamp metadata is signed by 0 of its keys and needs 1")
case("an expired timestamp", "", st(ts=dict(expires=PAST)), "Expired", reason="timestamp metadata expired")
case("a timestamp that expires now", "expired from that second on", st(ts=dict(expires=REF)), "Expired", reason="timestamp metadata expired")
case("a timestamp older than the one kept", "rollback", st(ts=dict(version=4)), "Rollback", reason="timestamp version 4 after 5", local=local_of(ts=dict(version=5)))
case("a timestamp naming an older snapshot than the kept one did", "rollback", st(ts=dict(version=3), snap=dict(version=2)), "Rollback", reason="names snapshot version 2 after 3", local={"timestamp": local_of(ts=dict(version=2), snap=dict(version=3))["timestamp"]})
case("the same timestamp version as an expired kept one", "the kept one stays, and it has expired", st(), "Expired", reason="timestamp metadata expired", local={"timestamp": local_of(ts=dict(expires=PAST))["timestamp"]})
case("a timestamp with two signatures by one key id", "", st(ts=dict(duplicate_signature=True)), "Malformed", reason="a second signature by key id")
case("a timestamp of specification version 2", "", st(ts=dict(spec="2.0")), "Unsupported", reason="specification version 2.0")

# --- the snapshot
case("a snapshot that is not the one the timestamp hashed", "", st(ts=dict(hashes=True, hash_of=b"other bytes")), "LengthOrHash", reason="the sha256 is not")
case("a snapshot longer than the timestamp says", "", st(ts=dict(length=True, length_delta=-1)), "LengthOrHash", reason="longer than")
case("a snapshot shorter than the timestamp says", "", st(ts=dict(length=True, length_delta=5)), "LengthOrHash", reason="not")
case("a snapshot of another version than the timestamp names", "2.snapshot.json holds version 1", st(ts=dict(snap_version=2)), "Version", reason="snapshot metadata has version 1, expected 2")
case("a snapshot by another key", "", st(snap=dict(sign=[ROGUE])), "Signature", reason="snapshot metadata is signed by 0 of its keys and needs 1")
case("an expired snapshot", "", st(snap=dict(expires=PAST)), "Expired", reason="snapshot metadata expired")
case("a snapshot with an older targets file than the kept one", "rollback", st(ts=dict(version=2), snap=dict(version=2)), "Rollback", reason="targets.json version 1 after 3", local=local_of(snap=dict(versions={"targets": 3})))
case("a snapshot that drops a role the kept one had", "rollback", st(ts=dict(version=2), snap=dict(version=2, drop=["registry.npmjs.org"])), "Rollback", reason="no longer lists registry.npmjs.org.json", local=local_of())

# --- targets
case("targets of another version than the snapshot names", "", st(snap=dict(versions={"targets": 2})), "Version", reason="targets metadata has version 1, expected 2")
case("targets by another key", "", st(tgt=dict(sign=[ROGUE])), "Signature", reason="targets metadata is signed by 0 of its keys and needs 1")
case("targets with one of the two signatures it needs", "", st(roots=[root(1, tgt_threshold=2)], tgt=dict(sign=TGT[:1])), "Signature", reason="targets metadata is signed by 1 of its keys and needs 2")
case("expired targets", "", st(tgt=dict(expires=PAST)), "Expired", reason="targets metadata expired")
case("a target with other bytes", "the same length", st(tgt=dict(serve={"trusted_root.json": TRUSTED_ROOT.replace(b"tlogs", b"tLogs")})), "LengthOrHash", reason="the sha256 is not")
case("a target longer than its metadata says", "", st(tgt=dict(serve={"trusted_root.json": TRUSTED_ROOT + b" "})), "LengthOrHash", reason="longer than")
case("a target shorter than its metadata says", "", st(tgt=dict(serve={"trusted_root.json": TRUSTED_ROOT[:-1]})), "LengthOrHash", reason="bytes, not")
case("a target hash of an unknown algorithm", "", st(tgt=dict(extra_hashes={"xyz": "00"})), "LengthOrHash", reason="unsupported hash algorithm")

# --- delegated roles
case("the delegated role signed by another key", "", st(roles=[npm(sign=[ROGUE])]), "Signature", reason="registry.npmjs.org metadata is signed by 0 of its keys and needs 1", target="registry.npmjs.org/keys.json", content=NPM_KEYS)
case("the delegated role expired", "", st(roles=[npm(expires=PAST)]), "Expired", reason="registry.npmjs.org metadata expired", target="registry.npmjs.org/keys.json", content=NPM_KEYS)
case("the delegated role missing from the snapshot", "", st(snap=dict(drop=["registry.npmjs.org"])), "Malformed", reason="the snapshot does not list registry.npmjs.org.json", target="registry.npmjs.org/keys.json", content=NPM_KEYS)
case("the delegated role of another version than the snapshot names", "", st(snap=dict(versions={"registry.npmjs.org": 2})), "Version", reason="registry.npmjs.org metadata has version 1, expected 2", target="registry.npmjs.org/keys.json", content=NPM_KEYS)
_dup = [NPM, with_identity(NPM, keyid="0" * 64)]
case(
    "one key under two key ids against a threshold of two",
    "the specification asks for unique keys",
    st(roles=[npm(keys=_dup, threshold=2, sign=_dup)]),
    "Signature",
    reason="registry.npmjs.org metadata is signed by 1 of its keys and needs 2",
    target="registry.npmjs.org/keys.json",
    content=NPM_KEYS,
    differs="python-tuf counts key ids, so it takes the same key twice",
)

# ------------------------------------------------------------------------------------------ write

os.makedirs(os.path.dirname(OUT), exist_ok=True)
doc = {"generated_by": "tools/gen_tuf_fixtures.py (python-tuf 6.0.0)", "now": NOW, "blobs": blobs, "cases": cases}
with open(OUT, "w") as f:
    f.write('{"generated_by":' + json.dumps(doc["generated_by"]) + ',\n"now":' + str(NOW) + ',\n"cases":[\n')
    f.write(",\n".join(json.dumps(c, separators=(",", ":")) for c in cases))
    f.write('\n],\n"blobs":' + json.dumps(blobs, separators=(",", ":"), sort_keys=True) + "}\n")
print(f"wrote {OUT}: {len(cases)} cases, {len(blobs)} files, {os.path.getsize(OUT)} bytes")
