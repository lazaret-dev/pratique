#!/usr/bin/env python3
"""A second independent HTTP/2 client for the interop check of pratique's HTTP/2 server (tools/h2_interop.sh):
python-h2 (hyper-h2), a sans-IO implementation that raises on any frame a server should not send. It checks what
the Go client cannot see: the server's frames, one by one, through a strict state machine. Needs `h2` and
`hyperframe` (pip install h2); PYTHONPATH may point at a directory that has them.

    python3 tools/h2_interop.py --ca root.pem --addr 127.0.0.1:PORT [--name localhost]

Prints one line per check, "ok ..." or "FAIL ...", and exits non-zero if any failed.
"""
import argparse
import os
import socket
import ssl
import sys
import time

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.errors
import h2.settings

failed = False


def check(ok, msg):
    global failed
    print(("ok   " if ok else "FAIL ") + msg)
    if not ok:
        failed = True


def pattern(n):
    return bytes(97 + i % 26 for i in range(n))


class Result:
    def __init__(self):
        self.headers = []          # the final response's header fields
        self.interim = []          # (status, headers) of 1xx responses
        self.trailers = []
        self.body = b""
        self.ended = False
        self.reset = None          # error code of RST_STREAM
        self.pushed = []

    def header(self, name):
        for k, v in self.headers:
            k = k.decode() if isinstance(k, bytes) else k
            v = v.decode() if isinstance(v, bytes) else v
            if k == name:
                return v
        return None

    @property
    def status(self):
        return int(self.header(":status") or 0)


class Conn:
    def __init__(self, ca, addr, name, initial_window=None, max_frame=None, enable_push=None):
        host, port = addr.rsplit(":", 1)
        ctx = ssl.create_default_context(cafile=ca)
        ctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection((host, int(port)), timeout=30)
        self.sock = ctx.wrap_socket(raw, server_hostname=name)
        self.alpn = self.sock.selected_alpn_protocol()
        self.name = name
        self.port = port
        cfg = h2.config.H2Configuration(client_side=True, header_encoding=None)
        self.c = h2.connection.H2Connection(config=cfg)
        self.c.initiate_connection()
        if initial_window is not None:
            self.c.update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: initial_window})
        if max_frame is not None:
            self.c.update_settings({h2.settings.SettingCodes.MAX_FRAME_SIZE: max_frame})
        if enable_push is not None:
            self.c.update_settings({h2.settings.SettingCodes.ENABLE_PUSH: enable_push})
        self.flush()
        self.results = {}
        self.goaway = None
        self.closed = False
        self.pending = {}          # stream id -> bytes still to send
        self.pending_end = {}

    def flush(self):
        data = self.c.data_to_send()
        if data:
            self.sock.sendall(data)

    def request(self, path, method="GET", headers=(), body=None):
        sid = self.c.get_next_available_stream_id()
        hdrs = [(":method", method), (":scheme", "https"), (":authority", f"{self.name}:{self.port}"), (":path", path)] + list(headers)
        self.c.send_headers(sid, hdrs, end_stream=(body is None))
        self.results[sid] = Result()
        if body is not None:
            self.pending[sid] = body
            self.pending_end[sid] = True
        self.pump_body(sid)
        self.flush()
        return sid

    def pump_body(self, sid):
        data = self.pending.get(sid)
        if data is None:
            return
        while True:
            room = min(self.c.local_flow_control_window(sid), self.c.max_outbound_frame_size)
            if room <= 0:
                break
            if not data:
                self.c.end_stream(sid)
                del self.pending[sid]
                return
            chunk, data = data[:room], data[room:]
            self.c.send_data(sid, chunk, end_stream=False)
            self.pending[sid] = data
        if not data:
            pass

    def pump_all(self):
        for sid in list(self.pending):
            self.pump_body(sid)

    def step(self, timeout=30):
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65536)
        except (ssl.SSLError, ConnectionError) as e:
            self.closed = True
            return False
        if not data:
            self.closed = True
            return False
        events = self.c.receive_data(data)
        for ev in events:
            sid = getattr(ev, "stream_id", None)
            r = self.results.get(sid)
            if isinstance(ev, h2.events.ResponseReceived):
                r.headers = ev.headers
            elif isinstance(ev, h2.events.InformationalResponseReceived):
                r.interim.append(ev.headers)
            elif isinstance(ev, h2.events.TrailersReceived):
                r.trailers = ev.headers
            elif isinstance(ev, h2.events.DataReceived):
                r.body += ev.data
                self.c.acknowledge_received_data(ev.flow_controlled_length, sid)
            elif isinstance(ev, h2.events.StreamEnded):
                r.ended = True
            elif isinstance(ev, h2.events.StreamReset):
                r.reset = ev.error_code
                r.ended = True
            elif isinstance(ev, h2.events.PushedStreamReceived):
                parent = self.results.get(ev.parent_stream_id)
                if parent is not None:
                    parent.pushed.append(ev.pushed_stream_id)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                self.goaway = (ev.error_code, ev.last_stream_id)
            elif isinstance(ev, h2.events.WindowUpdated):
                pass
        self.pump_all()
        self.flush()
        return True

    def wait(self, sids, timeout=60):
        deadline = time.time() + timeout
        sids = list(sids)
        while time.time() < deadline:
            if all(self.results[s].ended for s in sids):
                return True
            if self.closed:
                return False
            self.step(timeout=max(0.1, deadline - time.time()))
        return False

    def fetch(self, path, **kw):
        sid = self.request(path, **kw)
        ok = self.wait([sid])
        return self.results[sid], ok

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ca", required=True)
    ap.add_argument("--addr", required=True)
    ap.add_argument("--name", default="localhost")
    ap.add_argument("--no-push", action="store_true", help="skip the PUSH_PROMISE checks (the production server never pushes)")
    a = ap.parse_args()

    c = Conn(a.ca, a.addr, a.name)
    check(c.alpn == "h2", f"ALPN selected {c.alpn!r}")

    # Sizes around the frame size and the window.
    good = True
    for n in [0, 1, 100, 16383, 16384, 16385, 65535, 65536, 65537, 1000000]:
        r, ok = c.fetch(f"/size/{n}")
        if not (ok and r.status == 200 and r.body == pattern(n) and r.header("content-length") == str(n)):
            good = False
            check(False, f"GET /size/{n}: ok={ok} status={r.status} len={len(r.body)}")
    if good:
        check(True, "GET /size/N for 10 sizes from 0 to 1000000 through a strict state machine")

    # Uploads, flow controlled by the server's windows.
    good = True
    for n in [0, 1, 16384, 65535, 65536, 1 << 20, 3 << 20]:
        body = os.urandom(n)
        r, ok = c.fetch("/echo", method="POST", body=body)
        if not (ok and r.status == 200 and r.body == body):
            good = False
            check(False, f"POST /echo {n} bytes: ok={ok} status={r.status} len={len(r.body)}")
    if good:
        check(True, "POST /echo of 7 sizes up to 3 MiB comes back unchanged")

    # Many streams at once.
    sids = []
    bodies = {}
    for i in range(30):
        if i % 2 == 0:
            sids.append(c.request(f"/size/{5000 + i * 3001}"))
        else:
            b = os.urandom(4000 + i * 1777)
            sid = c.request("/echo", method="POST", body=b)
            bodies[sid] = b
            sids.append(sid)
    ok = c.wait(sids)
    wrong = 0
    for i, sid in enumerate(sids):
        r = c.results[sid]
        want = pattern(5000 + i * 3001) if i % 2 == 0 else bodies[sid]
        if r.body != want:
            wrong += 1
    check(ok and wrong == 0, f"30 streams open at once (15 downloads, 15 echoes): {wrong} wrong")

    # HEAD, statuses, trailers, interim, many headers.
    r, ok = c.fetch("/size/500", method="HEAD")
    check(ok and r.status == 200 and r.header("content-length") == "500" and r.body == b"", "HEAD /size/500")
    for code in (204, 304, 404):
        r, ok = c.fetch(f"/status/{code}")
        check(ok and r.status == code and r.body == b"", f"GET /status/{code}")
    r, ok = c.fetch("/trailers")
    check(ok and r.body == b"a body with trailers\n" and any(k == b"x-sum" and v == b"21" for k, v in r.trailers), f"trailers: {r.trailers}")
    r, ok = c.fetch("/interim")
    check(ok and r.status == 200 and len(r.interim) == 1 and r.body == b"after the interim response\n", f"103 then 200: {len(r.interim)} interim")
    r, ok = c.fetch("/headers/400")
    n = sum(1 for k, v in r.headers if k.startswith(b"x-header-"))
    check(ok and n == 400 and r.body == b"many headers\n", f"/headers/400: {n} header fields (CONTINUATION frames)")
    big = [(f"x-big-{i}", "v" * 1000) for i in range(40)]
    r, ok = c.fetch("/size/10", headers=big)
    check(ok and r.status == 200, "a request with 40 header fields of 1000 bytes (HEADERS + CONTINUATION)")

    # A request that is reset by the server in the middle of the body.
    r, ok = c.fetch("/reset")
    check(ok and r.reset == 2 and r.status == 200 and len(r.body) == 1000, f"RST_STREAM(INTERNAL_ERROR) after 1000 bytes: reset={r.reset} len={len(r.body)}")
    r, ok = c.fetch("/size/10")
    check(ok and r.body == pattern(10), "the connection serves after the reset")

    # We reset a stream ourselves: the server must forget it and go on.
    sid = c.request("/size/5000000")
    while len(c.results[sid].body) < 100000:
        if not c.step():
            break
    c.c.reset_stream(sid, h2.errors.ErrorCodes.CANCEL)
    c.flush()
    r, ok = c.fetch("/size/70000")
    check(ok and r.body == pattern(70000), "a 5 MB download cancelled by RST_STREAM(CANCEL); the next stream works")

    # PING: the server must answer.
    c.c.ping(b"12345678")
    c.flush()
    got_ack = False
    c.sock.settimeout(5)
    deadline = time.time() + 5
    while time.time() < deadline and not got_ack:
        data = c.sock.recv(65536)
        if not data:
            break
        for ev in c.c.receive_data(data):
            if isinstance(ev, h2.events.PingAckReceived) and ev.ping_data == b"12345678":
                got_ack = True
        c.flush()
    check(got_ack, "PING is answered with the same eight bytes")

    # The server's SETTINGS as the strict client sees them.
    s = c.c.remote_settings
    check(s.max_frame_size >= 16384 and s.initial_window_size >= 65535, f"server settings: max_frame_size={s.max_frame_size} initial_window={s.initial_window_size} max_concurrent={s.max_concurrent_streams}")

    # GOAWAY.
    r, ok = c.fetch("/goaway")
    for _ in range(20):
        if c.goaway is not None or c.closed:
            break
        c.step(timeout=1)
    check(ok and r.body == b"going away\n" and c.goaway is not None and c.goaway[0] == 0, f"/goaway: answer, then GOAWAY {c.goaway}")
    c.close()

    if not a.no_push:
        # PUSH_PROMISE to a client that has push disabled: python-h2 raises ProtocolError on it.
        c2 = Conn(a.ca, a.addr, a.name, enable_push=0)
        r, ok = c2.fetch("/size/5")          # the server has acknowledged our SETTINGS by now
        sid = c2.request("/push")
        raised = False
        try:
            c2.wait([sid], timeout=10)
        except h2.exceptions.ProtocolError:
            raised = True
        check(raised, f"PUSH_PROMISE reaches a client that disabled push: python-h2 raises ProtocolError={raised}")
        c2.close()
        # ... and to one that did not, it is a well-formed PUSH_PROMISE with the promised request in it
        c2 = Conn(a.ca, a.addr, a.name)
        sid = c2.request("/push")
        ok = c2.wait([sid], timeout=10)
        check(ok and c2.results[sid].pushed == [2] and c2.results[sid].body == b"with a promise\n", f"PUSH_PROMISE to a client that allows it: pushed streams {c2.results[sid].pushed}")
        c2.close()

    # Small windows on our side: the server has to wait for WINDOW_UPDATE.
    c3 = Conn(a.ca, a.addr, a.name, initial_window=1000, max_frame=16384)
    r, ok = c3.fetch("/size/200000")
    check(ok and r.body == pattern(200000), "a 200000-byte download with an initial stream window of 1000 bytes")
    c3.close()

    print("h2 python interop: " + ("FAIL" if failed else "PASS"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
