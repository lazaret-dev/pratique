# An HTTP/3 server made with aioquic, for trying this crate's QUIC and HTTP/3 against an implementation that it did not come
# from, and (with --tcp-port) an HTTPS-over-TCP origin with the same routes, so that a client can be told about the
# HTTP/3 side in an Alt-Svc field. It answers
#   GET /              "hello" (text/plain)
#   GET /bytes/N       N bytes of a repeating pattern (HEAD: the length, no body)
#   GET /slow/N        N bytes in 1000-byte pieces, 5 ms apart (HTTP/3 only)
#   POST /echo         the body, back
#   GET /headers       the request headers, one per line
#   GET /status/N      status N with a short body
#   GET /redirect?to=P a 302 to P
#   GET /clear         "cleared", with `alt-svc: clear`; no later response advertises anything, until /advertise
#   GET /advertise     "advertised"; the --alt-svc value is in this response and in every later one
#   GET /trailers      "body", then a trailer field (HTTP/3 only)
#   GET /reset         100 of 1000 bytes, then the stream is reset (HTTP/3 only)
#   GET /nolength/N    N bytes with no content-length field (HTTP/3 only)
#   any /die           HTTP/3: the connection is closed with an error, with no answer; over TCP: "still here"
#   GET /stats         the connections accepted so far and the requests on each (HTTP/3 only)
#   any other path     404
# Every response carries `alt-svc: VALUE` if --alt-svc is given.
# Run:  AIOQUIC_PATH=/dir/with/aioquic python3 tools/quic_interop_server.py --cert CERT --key KEY [--port 4433] [--qlog DIR]
#         [--tcp-port P] [--alt-svc 'h3=":4433"; ma=3600']
# (aioquic 1.3.0: pip install --target DIR aioquic==1.3.0.) It prints "listening PORT" when it is ready.
import argparse, asyncio, http.server, os, ssl, sys, threading
from urllib.parse import parse_qs, urlsplit
sys.path.insert(0, os.environ.get("AIOQUIC_PATH", "."))
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from aioquic.quic.logger import QuicFileLogger

ALT_SVC = None        # what the responses advertise now
ALT_SVC_GIVEN = None  # what --alt-svc says
CONNECTIONS = []


def pattern(n):
    return (bytes(range(251)) * (n // 251 + 1))[:n]


def route(method, path, headers, body):
    """(status, [(name, value)], body) for the routes that need nothing of the transport."""
    global ALT_SVC
    url = urlsplit(path)
    path = url.path
    status, extra, out = 200, [("content-type", "text/plain")], b""
    if method in ("GET", "HEAD") and path == "/":
        out = b"hello"
    elif method in ("GET", "HEAD") and path.startswith("/bytes/"):
        out = pattern(int(path[7:]))
        extra = [("content-type", "application/octet-stream")]
    elif method == "POST" and path == "/echo":
        out = body
    elif method == "GET" and path == "/headers":
        out = b"".join(k + b": " + v + b"\n" for k, v in headers.items())
    elif path.startswith("/status/"):
        status = int(path[8:])
        out = b"" if status in (204, 304) else ("status %d" % status).encode()
    elif path == "/redirect":
        status, out = 302, b"moved"
        extra.append(("location", parse_qs(url.query).get("to", ["/"])[0]))
    elif path == "/die":
        out = b"still here"
    elif path == "/clear":
        out = b"cleared"
        extra.append(("alt-svc", "clear"))
        ALT_SVC = None
    elif path == "/advertise":
        out = b"advertised"
        ALT_SVC = ALT_SVC_GIVEN
    else:
        status, out = 404, b"not found"
    if ALT_SVC and not any(k == "alt-svc" for k, _ in extra):
        extra.append(("alt-svc", ALT_SVC))
    return status, extra, out


class Server(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.requests = {}
        self.served = 0
        CONNECTIONS.append(self)

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self.http = H3Connection(self._quic)
        if self.http is not None:
            for h3_event in self.http.handle_event(event):
                self.h3_event(h3_event)

    def h3_event(self, event):
        if isinstance(event, HeadersReceived):
            self.requests[event.stream_id] = [dict(event.headers), b""]
            if event.stream_ended:
                self.respond(event.stream_id)
        elif isinstance(event, DataReceived) and event.stream_id in self.requests:
            self.requests[event.stream_id][1] += event.data
            if event.stream_ended:
                self.respond(event.stream_id)

    def respond(self, stream_id):
        headers, body = self.requests.pop(stream_id)
        method, path = headers[b":method"].decode(), headers[b":path"].decode()
        self.served += 1
        bare = urlsplit(path).path
        if method == "GET" and bare.startswith("/slow/"):
            asyncio.ensure_future(self.slow(stream_id, int(bare[6:])))
            return
        if method == "GET" and bare == "/reset":
            self.http.send_headers(stream_id, [(b":status", b"200"), (b"content-length", b"1000")])
            self.http.send_data(stream_id, pattern(100), end_stream=False)
            self.transmit()
            self._quic.reset_stream(stream_id, 0x10C)
            self.transmit()
            return
        if bare == "/die":
            self._quic.close(error_code=0x101, reason_phrase="die")
            self.transmit()
            return
        if method == "GET" and bare.startswith("/nolength/"):
            self.http.send_headers(stream_id, [(b":status", b"200")])
            self.http.send_data(stream_id, pattern(int(bare[10:])), end_stream=True)
            self.transmit()
            return
        if method == "GET" and bare == "/trailers":
            self.http.send_headers(stream_id, [(b":status", b"200"), (b"trailer", b"x-trailer")])
            self.http.send_data(stream_id, b"body", end_stream=False)
            self.http.send_headers(stream_id, [(b"x-trailer", b"t")], end_stream=True)
            self.transmit()
            return
        if method == "GET" and bare == "/stats":
            out = ("connections %d\n" % len(CONNECTIONS) + "".join("connection %d requests %d\n" % (i, c.served) for i, c in enumerate(CONNECTIONS))).encode()
            status, extra = 200, [("content-type", "text/plain")]
        else:
            status, extra, out = route(method, path, headers, body)
        fields = [(b":status", str(status).encode())] + [(k.encode(), v.encode()) for k, v in extra] + [(b"content-length", str(len(out)).encode())]
        if method == "HEAD":
            self.http.send_headers(stream_id, fields, end_stream=True)
        else:
            self.http.send_headers(stream_id, fields)
            self.http.send_data(stream_id, out, end_stream=True)
        self.transmit()

    async def slow(self, stream_id, n):
        self.http.send_headers(stream_id, [(b":status", b"200"), (b"content-length", str(n).encode())])
        data = pattern(n)
        sent = 0
        while sent < n:
            piece = data[sent:min(sent + 1000, n)]
            sent += len(piece)
            self.http.send_data(stream_id, piece, end_stream=sent == n)
            self.transmit()
            await asyncio.sleep(0.005)


class TcpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def handle_any(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        headers = {k.lower().encode(): v.encode() for k, v in self.headers.items()}
        status, extra, out = route(self.command, self.path, headers, body)
        self.send_response(status)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_POST = do_HEAD = handle_any


def serve_tcp(port, cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), TcpHandler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()


async def main():
    global ALT_SVC, ALT_SVC_GIVEN
    p = argparse.ArgumentParser()
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--port", type=int, default=4433)
    p.add_argument("--tcp-port", type=int, help="also serve the routes over HTTPS on this TCP port")
    p.add_argument("--alt-svc", help="the value of the alt-svc field of every response")
    p.add_argument("--qlog")
    p.add_argument("--secrets")
    p.add_argument("--retry", action="store_true", help="answer the first Initial with a Retry")
    a = p.parse_args()
    ALT_SVC = ALT_SVC_GIVEN = a.alt_svc
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN + ["hq-interop"], max_datagram_frame_size=65536)
    config.load_cert_chain(a.cert, a.key)
    if a.qlog:
        config.quic_logger = QuicFileLogger(a.qlog)
    if a.secrets:
        config.secrets_log_file = open(a.secrets, "a")
    if a.tcp_port:
        serve_tcp(a.tcp_port, a.cert, a.key)
    await serve("127.0.0.1", a.port, configuration=config, create_protocol=Server, retry=a.retry)
    print("listening", a.port, flush=True)
    await asyncio.Event().wait()


asyncio.run(main())
