#!/usr/bin/env python3
"""Turns a capture made by tools/rekor_capture.sh (the directory it writes, `rekor-capture/`) into the
fixtures of tests/data/rekor/. Run from the repository root:

    python3 tools/gen_rekor_fixtures.py PATH/TO/rekor-capture

The capture was made on 2026-10-06 00:10 UTC from the real Rekor (rekor.sigstore.dev) and its newer log
(log2025-1.rekor.sigstore.dev). Also read: the checkpoint inside the real Lazaret 0.1.8 npm provenance
bundle (tests/data/real_lazaret_0_1_8.sigstore.json), which is the older end of the consistency proof.

The Ed25519 key of the v2 log is not in the capture: it is the one in Sigstore's production trusted root
(the `tlogs` entry of log2025-1.rekor.sigstore.dev, as shipped in the sigstore-python 4.x wheel under
sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev/trusted_root.json), and it is checked by the
signature on the v2 checkpoint, which verifies under it.
"""
import base64
import json
import os
import sys

V2_NAME = "log2025-1.rekor.sigstore.dev"
V2_SPKI_B64 = "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244="
OUT = "tests/data/rekor"


def main():
    cap = sys.argv[1]
    os.makedirs(OUT, exist_ok=True)

    def w(name, text):
        with open(os.path.join(OUT, name), "w", newline="\n") as f:
            f.write(text)

    w("v1_key.pem", open(os.path.join(cap, "publickey.pem")).read())
    new = open(os.path.join(cap, "checkpoint.txt"), encoding="utf-8").read()
    w("v1_checkpoint_new.txt", new)
    bundle = json.load(open("tests/data/real_lazaret_0_1_8.sigstore.json"))
    old = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"]
    w("v1_checkpoint_old.txt", old)
    log = json.load(open(os.path.join(cap, "log.json")))
    assert log["signedTreeHead"] == new
    for shard in log["inactiveShards"]:
        w("v1_shard_%d.txt" % shard["treeSize"], shard["signedTreeHead"])
    proof = json.load(open(os.path.join(cap, "consistency_proof.json")))
    w("v1_consistency_proof.txt", "".join(h + "\n" for h in proof["hashes"]))
    w("v2_checkpoint.txt", open(os.path.join(cap, "v2_checkpoint.txt"), encoding="utf-8").read())
    w("v2_key.txt", "%s\n%s\n" % (V2_NAME, V2_SPKI_B64))
    print("wrote", sorted(os.listdir(OUT)))


if __name__ == "__main__":
    main()
