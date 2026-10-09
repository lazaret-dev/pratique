#!/usr/bin/env python3
"""The DNS of tools/acme_interop.sh (B-113): a tiny authoritative server for Pebble's validation authority, and the
DNS-01 hook of examples/acme_serve that publishes TXT records through it.

    acme_dns.py serve RECORDS.json ADDR PORT     answer over UDP and TCP: A 127.0.0.1 for every name, TXT from RECORDS.json
                                                 (read at each query), nothing for AAAA, CAA and the rest
    acme_dns.py hook RECORDS.json present|cleanup NAME VALUE

RECORDS.json maps a name (no final dot, lower case) to its TXT values.
"""
import fcntl
import json
import os
import socket
import struct
import sys
import threading


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def hook(path, action, name, value):
    name = name.rstrip(".").lower()
    with open(path + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        records = load(path)
        values = records.setdefault(name, [])
        if action == "present":
            values.append(value)
        elif value in values:
            values.remove(value)
        if not values:
            del records[name]
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(records, f)
        os.replace(tmp, path)


def parse_question(packet):
    labels, i = [], 12
    while True:
        n = packet[i]
        i += 1
        if n == 0:
            break
        labels.append(packet[i : i + n].decode("ascii", "replace"))
        i += n
    qtype, qclass = struct.unpack("!HH", packet[i : i + 4])
    return ".".join(labels).lower(), qtype, i + 4


def answer(packet, path):
    ident, flags, qd = struct.unpack("!HHH", packet[:6])
    if qd != 1:
        return None
    name, qtype, end = parse_question(packet)
    rdatas = []
    if qtype == 1:  # A
        rdatas = [(1, socket.inet_aton("127.0.0.1"))]
    elif qtype == 16:  # TXT
        for v in load(path).get(name, []):
            b = v.encode()
            rdatas.append((16, bytes([len(b)]) + b))
    rd = flags & 0x0100
    head = struct.pack("!HHHHHH", ident, 0x8400 | rd | 0x0080, 1, len(rdatas), 0, 0)
    out = head + packet[12:end]
    for t, data in rdatas:
        out += struct.pack("!HHHIH", 0xC00C, t, 1, 0, len(data)) + data
    return out


def serve_tcp(path, addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=tcp_client, args=(conn, path), daemon=True).start()


def tcp_client(conn, path):
    # each message is preceded by its length in two bytes (RFC 1035 section 4.2.2)
    with conn:
        conn.settimeout(5)
        try:
            while True:
                head = conn.recv(2)
                if len(head) < 2:
                    return
                n = struct.unpack("!H", head)[0]
                packet = b""
                while len(packet) < n:
                    more = conn.recv(n - len(packet))
                    if not more:
                        return
                    packet += more
                reply = answer(packet, path)
                if reply:
                    conn.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, ValueError, IndexError, struct.error) as e:
            print(f"dns tcp: {e}", file=sys.stderr, flush=True)


def serve(path, addr, port):
    threading.Thread(target=serve_tcp, args=(path, addr, port), daemon=True).start()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, int(port)))
    print(f"dns listening {addr}:{port} (UDP and TCP)", flush=True)
    while True:
        packet, peer = s.recvfrom(4096)
        try:
            reply = answer(packet, path)
        except Exception as e:  # a malformed query: no answer
            print(f"dns: {e}", file=sys.stderr, flush=True)
            continue
        if reply:
            s.sendto(reply, peer)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "serve":
        serve(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 6 and sys.argv[1] == "hook" and sys.argv[3] in ("present", "cleanup"):
        hook(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
