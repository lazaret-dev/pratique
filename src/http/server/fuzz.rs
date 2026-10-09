//! Fuzzing hooks for the HTTP server (B-111), for the `http_server_h1` and `h2_server` targets of `fuzz/`.
//!
//! | target | what must hold |
//! |--------|----------------|
//! | `http_server_h1` | a whole HTTP/1.1 connection over an in-memory transport, the input as what the client sends, with a handler that reads the body and answers in one of four ways the path picks: nothing panics, the connection ends, and every byte the server wrote parses strictly as responses (CRLF lines, a status line, framing that matches the bytes: a length or well-formed chunks) |
//! | `h2_server` | the HTTP/2 engine fed the input as frames after the preface (in pieces the first byte sizes), each new request answered by a handler that the stream id steers (reads its body, answers with a body and trailers, resets, or leaves it), the output pumped and taken as it would be sent: nothing panics, and the output is whole frames no larger than the client allows, beginning with SETTINGS, whose header blocks decode with an independent HPACK decoder, with nothing after a GOAWAY that ends the connection |

use super::super::h2::frame::{self, flag, kind, setting, ErrorCode, Header, DEFAULT_MAX_FRAME_SIZE, HEADER_LEN, MAX_FRAME_SIZE_LIMIT};
use super::super::h2::hpack::{Decoder, Encoder, FieldRef};
use super::h2::Engine;
use super::{h1, ConnInfo, HttpConfig, Request, Response, Transport};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

fn config() -> HttpConfig {
    let mut c = HttpConfig { max_request_line: 512, max_header_bytes: 2048, max_headers: 32, max_body: Some(16 * 1024), max_requests_per_connection: 50, drain_limit: 4096, ..HttpConfig::default() };
    c.h2.max_concurrent_streams = 8;
    c.h2.stream_send_buffer = 4096;
    c
}

/// What the client sends, then end of file; what the server writes, kept.
struct Mem {
    input: io::Cursor<Vec<u8>>,
    out: Arc<Mutex<Vec<u8>>>,
}

impl Read for Mem {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // a few bytes at a time, so that the server's reads stop in odd places
        let n = buf.len().min(7);
        self.input.read(&mut buf[..n])
    }
}

impl Write for Mem {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Out(Arc<Mutex<Vec<u8>>>);

impl Write for Out {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for Mem {
    fn split(self: Box<Self>) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
        let out = self.out.clone();
        Ok((Box::new(self.input), Box::new(Out(out))))
    }
}

fn h1_handler(mut req: Request) -> Response {
    if req.method() == "HEAD" {
        return Response::new(200); // so that every response with a length has its body after it
    }
    let body = req.read_body(16 * 1024);
    let trailers = req.body().trailers().len();
    let Ok(body) = body else { return Response::text(400, "body\n") };
    match req.path().len() % 4 {
        0 => Response::bytes(200, "x/y", body),
        1 => Response::stream(200, move |w| {
            w.write_all(&body)?;
            w.set_trailers(vec![("x-trailers".into(), trailers.to_string())]);
            Ok(())
        }),
        2 => Response::reader(200, io::Cursor::new(body), None),
        _ => Response::new(204).with_header("x-n", &trailers.to_string()),
    }
}

/// Runs one HTTP/1.1 connection on `data` and checks what the server wrote.
pub fn h1_exchange(data: &[u8]) {
    let out = Arc::new(Mutex::new(Vec::new()));
    let mem = Mem { input: io::Cursor::new(data.to_vec()), out: out.clone() };
    let _ = h1::serve_with(Box::new(mem), Vec::new(), Arc::new(ConnInfo::default()), Arc::new(h1_handler), &config(), super::runtime::Ctl::detached());
    let written = out.lock().unwrap().clone();
    check_responses(&written);
}

/// Every byte is part of a well-formed response.
fn check_responses(mut d: &[u8]) {
    fn line<'a>(d: &mut &'a [u8]) -> &'a [u8] {
        let i = d.windows(2).position(|w| w == b"\r\n").expect("a line ends with CRLF");
        let l = &d[..i];
        assert!(!l.contains(&b'\r') && !l.contains(&b'\n'), "a bare CR or LF in a line the server wrote");
        *d = &d[i + 2..];
        l
    }
    while !d.is_empty() {
        let status = line(&mut d);
        assert!(status.starts_with(b"HTTP/1.1 ") && status.len() >= 12 && status[9..12].iter().all(u8::is_ascii_digit), "a status line: {:?}", String::from_utf8_lossy(status));
        let code: u16 = std::str::from_utf8(&status[9..12]).unwrap().parse().unwrap();
        let (mut length, mut chunked) = (None, false);
        loop {
            let l = line(&mut d);
            if l.is_empty() {
                break;
            }
            let colon = l.iter().position(|&b| b == b':').expect("a field has a colon");
            assert!(colon > 0 && l[..colon].iter().all(|&b| super::is_tchar(b)), "a field name");
            let name = String::from_utf8_lossy(&l[..colon]).to_ascii_lowercase();
            let value = String::from_utf8_lossy(&l[colon + 1..]).trim().to_string();
            match name.as_str() {
                "content-length" => {
                    assert!(length.is_none(), "one Content-Length");
                    length = Some(value.parse::<usize>().expect("a Content-Length is a number"));
                }
                "transfer-encoding" => {
                    assert_eq!(value, "chunked");
                    chunked = true;
                }
                _ => {}
            }
        }
        assert!(!(chunked && length.is_some()), "never both Content-Length and chunked");
        if (100..200).contains(&code) || code == 204 || code == 304 {
            assert!(!chunked);
            continue;
        }
        if chunked {
            loop {
                let size = usize::from_str_radix(std::str::from_utf8(line(&mut d)).unwrap(), 16).expect("a chunk size");
                if size == 0 {
                    while !line(&mut d).is_empty() {}
                    break;
                }
                assert!(d.len() >= size + 2, "a whole chunk");
                assert_eq!(&d[size..size + 2], b"\r\n");
                d = &d[size + 2..];
            }
        } else if let Some(n) = length {
            assert!(d.len() >= n, "a whole body");
            d = &d[n..];
        } else {
            return; // until the close
        }
    }
}

pub fn h1_seeds() -> Vec<Vec<u8>> {
    [
        &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
        b"POST /ab HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhelloGET /abc HTTP/1.1\r\nHost: a\r\n\r\n",
        b"POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\n",
        b"POST /abc HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nxyz",
        b"GET http://x.example/abcd HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n",
        b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nHEAD /a HTTP/1.0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ]
    .iter()
    .map(|s| s.to_vec())
    .collect()
}

// ------------------------------------------------------------------------------------------------ HTTP/2

/// Feeds `data` (frames after the preface) to the engine, answering requests as the stream ids say, and checks the output.
pub fn h2_engine(data: &[u8]) {
    let Some((&piece, data)) = data.split_first() else { return };
    let piece = usize::from(piece % 64) + 1;
    let mut e = Engine::new(&config());
    let mut checker = OutputCheck::new();
    let mut open: Vec<u32> = Vec::new();
    for chunk in data.chunks(piece) {
        match e.receive(chunk) {
            Ok(new) => open.extend(new.iter().map(|s| s.id())),
            Err(_) => {}
        }
        // the handlers, a step each
        let mut still = Vec::new();
        for id in open.drain(..) {
            if !handler_step(&mut e, id) {
                still.push(id);
            }
        }
        open = still;
        e.pump();
        let out = std::mem::take(&mut e.out);
        checker.feed(&out, &e);
        if e.is_dead() {
            break;
        }
    }
    for id in open {
        e.handler_returned(id);
    }
    e.pump();
    let out = std::mem::take(&mut e.out);
    checker.feed(&out, &e);
}

/// One step of a handler; true when it is done.
fn handler_step(e: &mut Engine, id: u32) -> bool {
    match id % 8 {
        // reads what there is, and answers when the body ends
        1 => {
            let mut buf = [0u8; 300];
            match e.read_body(id, &mut buf) {
                Ok(Some(0)) | Err(_) => {
                    let _ = e.send_head(id, 200, &[("x-read".into(), "all".into())], false);
                    let _ = e.queue_data(id, b"read it all");
                    let _ = e.end_stream(id, vec![("x-trailer".into(), "1".into())]);
                    e.handler_returned(id);
                    true
                }
                _ => false,
            }
        }
        // answers at once with a body larger than the windows
        3 => {
            let _ = e.send_head(id, 200, &[], false);
            let _ = e.queue_data(id, &[b'x'; 5000]);
            let _ = e.end_stream(id, Vec::new());
            e.handler_returned(id);
            true
        }
        // a head with no body
        5 => {
            let _ = e.send_head(id, 204, &[("x-a".into(), "b".into())], true);
            e.handler_returned(id);
            true
        }
        // returns without an answer: the stream is reset
        _ => {
            e.handler_returned(id);
            true
        }
    }
}

/// Checks the server's output as a client would read it.
struct OutputCheck {
    buf: Vec<u8>,
    decoder: Decoder,
    first: bool,
    block: Option<Vec<u8>>,
    gone: bool,
}

impl OutputCheck {
    fn new() -> OutputCheck {
        OutputCheck { buf: Vec::new(), decoder: Decoder::new(4096, 1 << 20), first: true, block: None, gone: false }
    }

    fn feed(&mut self, out: &[u8], e: &Engine) {
        if out.is_empty() {
            return;
        }
        assert!(!self.gone, "output after a GOAWAY that ended the connection");
        self.buf.extend_from_slice(out);
        let mut pos = 0;
        while self.buf.len() - pos >= HEADER_LEN {
            let h = Header::parse(self.buf[pos..pos + HEADER_LEN].try_into().unwrap());
            assert!(h.length <= MAX_FRAME_SIZE_LIMIT && h.length as usize <= e.peer_max_frame_for_fuzz().max(DEFAULT_MAX_FRAME_SIZE as usize), "a frame larger than the client allows");
            let end = pos + HEADER_LEN + h.length as usize;
            assert!(self.buf.len() >= end, "the engine's output is whole frames");
            let payload = &self.buf[pos + HEADER_LEN..end];
            if self.first {
                assert!(h.kind == kind::SETTINGS && !h.has(flag::ACK), "the server begins with SETTINGS");
                self.first = false;
            }
            frame::parse(&h, payload).expect("the server's own frames parse");
            match h.kind {
                kind::HEADERS => {
                    assert!(self.block.is_none());
                    let mut b = payload.to_vec();
                    if h.has(flag::END_HEADERS) {
                        let mut fields = Vec::new();
                        self.decoder.decode(&std::mem::take(&mut b), &mut fields).expect("our header blocks decode");
                        assert!(fields.first().is_none_or(|f| f.name == b":status" || !f.name.starts_with(b":")));
                    } else {
                        self.block = Some(b);
                    }
                }
                kind::CONTINUATION => {
                    let mut b = self.block.take().expect("CONTINUATION after HEADERS");
                    b.extend_from_slice(payload);
                    if h.has(flag::END_HEADERS) {
                        let mut fields = Vec::new();
                        self.decoder.decode(&b, &mut fields).expect("our header blocks decode");
                    } else {
                        self.block = Some(b);
                    }
                }
                kind::GOAWAY => {
                    let code = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                    if code != ErrorCode::NO_ERROR.0 {
                        self.gone = true;
                    }
                }
                _ => assert!(self.block.is_none(), "a frame inside our own header block"),
            }
            pos = end;
        }
        assert_eq!(pos, self.buf.len(), "the engine's output is whole frames");
        self.buf.clear();
    }
}

pub fn h2_seeds() -> Vec<Vec<u8>> {
    let mut enc = Encoder::new();
    let mut block = |fields: &[(&str, &str)]| {
        let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
        let mut b = Vec::new();
        enc.encode(&refs, &mut b);
        b
    };
    fn get(path: &str) -> Vec<(&str, &str)> {
        vec![(":method", "GET"), (":scheme", "https"), (":authority", "a.example"), (":path", path)]
    }
    let mut seeds = Vec::new();
    for piece in [0u8, 6, 63] {
        let mut s = vec![piece];
        frame::write_settings(&mut s, &[(setting::INITIAL_WINDOW_SIZE, 1000), (setting::MAX_FRAME_SIZE, 16_384)]);
        frame::write_settings_ack(&mut s);
        let mut post = get("/up");
        post[0] = (":method", "POST");
        frame::write_header_block(&mut s, 1, false, &block(&post), 16_384);
        frame::write_data(&mut s, 1, false, b"some body");
        frame::write_header_block(&mut s, 1, true, &block(&[("x-t", "1")]), 16_384);
        frame::write_header_block(&mut s, 3, true, &block(&get("/big")), 16_384);
        frame::write_window_update(&mut s, 3, 3000);
        frame::write_window_update(&mut s, 0, 100_000);
        frame::write_header_block(&mut s, 5, true, &block(&get("/none")), 16_384);
        frame::write_header_block(&mut s, 7, false, &block(&get("/reset")), 16_384);
        frame::write_rst_stream(&mut s, 7, ErrorCode::CANCEL);
        frame::write_ping(&mut s, false, *b"12345678");
        frame::write_goaway(&mut s, 0, ErrorCode::NO_ERROR, b"");
        seeds.push(s);
    }
    seeds
}
