# Makes src/quic/vectors_aioquic.rs: packets protected by aioquic, to check src/quic/keys.rs against an implementation
# that this one did not come from. Run:  AIOQUIC_PATH=/dir/with/aioquic python3 tools/gen_quic_vectors.py
# (The output is checked in; this is only needed to change it.)
import binascii, random, sys
import os
sys.path.insert(0, os.environ.get("AIOQUIC_PATH", "."))  # a directory with aioquic 1.3.0 in it (pip install --target DIR aioquic==1.3.0)
from aioquic.quic.crypto import CryptoContext, next_key_phase
from aioquic.tls import CipherSuite

rng = random.Random(20261005)
SUITES = [
    (0x1301, CipherSuite.AES_128_GCM_SHA256, 32),
    (0x1302, CipherSuite.AES_256_GCM_SHA384, 48),
    (0x1303, CipherSuite.CHACHA20_POLY1305_SHA256, 32),
]
h = lambda b: binascii.hexlify(b).decode()
rows = []
for sid, cs, slen in SUITES:
    secret = bytes(rng.randrange(256) for _ in range(slen))
    for long in (False, True):
        for pn_len in (1, 2, 3, 4):
            for payload_len in (4 - pn_len, 37, 100):
                pn = rng.randrange(1 << (8 * pn_len)) | (rng.randrange(1 << 20) << (8 * pn_len))
                dcid = bytes(rng.randrange(256) for _ in range(rng.choice([0, 4, 8, 20])))
                payload = bytes(rng.randrange(256) for _ in range(payload_len))
                pnb = (pn & ((1 << (8 * pn_len)) - 1)).to_bytes(pn_len, "big")
                if long:
                    scid = bytes(rng.randrange(256) for _ in range(rng.choice([0, 5, 8])))
                    length = pn_len + payload_len + 16
                    first = 0xC0 | (2 << 4) | (pn_len - 1)  # Handshake
                    hdr = bytes([first]) + (1).to_bytes(4, "big") + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + (0x4000 | length).to_bytes(2, "big")
                    pn_offset = len(hdr)
                    hdr += pnb
                else:
                    phase = rng.randrange(2)
                    first = 0x40 | (rng.randrange(2) << 5) | (phase << 2) | (pn_len - 1)
                    hdr = bytes([first]) + dcid
                    pn_offset = len(hdr)
                    hdr += pnb
                ctx = CryptoContext()
                ctx.setup(cipher_suite=cs, secret=secret, version=1)
                sealed = ctx.encrypt_packet(hdr, payload, pn)
                nxt = next_key_phase(ctx)
                # a key update changes the AEAD key and keeps the header protection key (aioquic's `apply_key_phase` copies the AEAD of
                # `next_key_phase` over and leaves `hp`, so that is what is done here: `nxt.hp` is not the key in use)
                sealed2 = ctx.hp.apply(hdr, nxt.aead.encrypt(payload, hdr, pn))
                rows.append((sid, secret, hdr + payload, pn_offset, pn_len, pn, sealed, sealed2))

out = ["//! Packets protected by aioquic 1.3.0 (a QUIC library written independently of this one), with its keys: for each cipher suite,\n",
       "//! long and short headers, every packet number length, payloads from the shortest that can be sampled to 100 bytes, and the\n",
       "//! same packet under the keys of the next generation. Made by `tools/gen_quic_vectors.py`; see there.\n\n",
       "/// (cipher suite id, traffic secret, the packet before protection without its tag, where the packet number is, its length, the\n",
       "/// packet number, the packet as aioquic protected it, the same under the next generation of keys)\n",
       "pub type AioquicVector = (u16, &'static str, &'static str, usize, usize, u64, &'static str, &'static str);\n\n",
       "pub const AIOQUIC: &[AioquicVector] = &[\n"]
for sid, secret, clear, pn_offset, pn_len, pn, sealed, sealed2 in rows:
    out.append('    (0x%04x, "%s", "%s", %d, %d, %d, "%s", "%s"),\n' % (sid, h(secret), h(clear), pn_offset, pn_len, pn, h(sealed), h(sealed2)))
out.append("];\n")
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "quic", "vectors_aioquic.rs"), "w").write("".join(out))
print(len(rows), "vectors")
