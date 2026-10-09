//! Helpers for the server's tests: servers on real sockets, a raw HTTP/1.1 exchange, and a strict reader of responses.

use super::{serve_plain, serve_tls, Body, ConnInfo, Handler, HttpConfig, Request, Version};
use crate::http::Client;
use crate::tls::pki::TestPki;
use crate::tls::server::{ServerConfig, ServerStream};
use crate::tls::ClientConfig;
use super::super::h2::frame::{self, flag, kind, Frame, Header, HEADER_LEN, PREFACE};
use super::super::h2::hpack::{Decoder, Encoder, FieldRef};
use std::io::{self, Read, Write};
use std::time::Instant;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// A request with no body, as a handler would get it.
pub(super) fn request(method: &str, target: &str, authority: &str) -> Request {
    Request {
        method: method.into(),
        target: target.into(),
        authority: authority.into(),
        scheme: "http".into(),
        version: Version::Http11,
        headers: Vec::new(),
        body: Body::new(None),
        info: Arc::new(ConnInfo::default()),
        interim: None,
        ctl: None,
    }
}

/// A server on a port of its own, serving each connection on a thread.
pub(super) struct Server {
    pub(super) addr: SocketAddr,
    pki: Option<TestPki>,
    stop: Arc<AtomicBool>,
    pub(super) connections: Arc<AtomicUsize>,
    /// How each connection ended, as `serve_*` returned.
    pub(super) results: Arc<Mutex<Vec<String>>>,
}

impl Server {
    pub(super) fn plain(handler: impl Handler, config: HttpConfig) -> Server {
        Server::launch(Arc::new(handler), config, None)
    }

    /// TLS, offering these ALPN protocols.
    pub(super) fn tls(handler: impl Handler, config: HttpConfig, alpn: &[&str]) -> Server {
        let pki = TestPki::new(&["127.0.0.1", "localhost"]).unwrap();
        let tls = Arc::new(ServerConfig::from_pki(&pki).with_alpn(alpn));
        let mut s = Server::launch(Arc::new(handler), config, Some(tls));
        s.pki = Some(pki);
        s
    }

    fn launch(handler: Arc<dyn Handler>, config: HttpConfig, tls: Option<Arc<ServerConfig>>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let results = Arc::new(Mutex::new(Vec::new()));
        {
            let (stop, connections, results) = (stop.clone(), connections.clone(), results.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok((stream, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (handler, config, tls, results) = (handler.clone(), config.clone(), tls.clone(), results.clone());
                    thread::spawn(move || {
                        let info = ConnInfo::of(&stream);
                        let result = match tls {
                            None => serve_plain(stream, info, handler, &config),
                            Some(tls) => match ServerStream::accept(stream, &tls) {
                                Ok(s) => serve_tls(s, info, handler, &config),
                                Err(e) => Err(io::Error::other(e.to_string())),
                            },
                        };
                        results.lock().unwrap().push(match result {
                            Ok(()) => "ok".into(),
                            Err(e) => e.to_string(),
                        });
                    });
                }
            });
        }
        Server { addr, pki: None, stop, connections, results }
    }

    /// The crate's own client for this server: HTTP/2 offered over TLS.
    pub(super) fn client(&self) -> Client {
        match &self.pki {
            Some(pki) => Client::with_tls_config(ClientConfig::new(pki.trust_store())).http2(true),
            None => Client::with_tls_config(ClientConfig::new(crate::x509::TrustStore::empty())).allow_insecure_http(true),
        }
        .timeout(Duration::from_secs(10))
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("{}://127.0.0.1:{}{}", if self.pki.is_some() { "https" } else { "http" }, self.addr.port(), path)
    }

    pub(super) fn connect(&self) -> TcpStream {
        let s = TcpStream::connect(self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s
    }

    /// Sends `bytes`, says it is done sending, and reads everything until the server closes.
    pub(super) fn exchange(&self, bytes: &[u8]) -> Vec<u8> {
        let mut s = self.connect();
        s.write_all(bytes).unwrap();
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// A response as read off the wire.
#[derive(Debug, Clone, Default)]
pub(super) struct Resp {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
    pub(super) trailers: Vec<(String, String)>,
    pub(super) chunked: bool,
}

impl Resp {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub(super) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Reads responses one after another, strictly: every line ends with CRLF, bodies are framed as the head says, and a
/// response to HEAD (`heads` says which, in order) has none. What follows the last whole response is left.
pub(super) fn responses(mut data: &[u8], heads: &[bool]) -> Vec<Resp> {
    let mut out = Vec::new();
    let line = |d: &mut &[u8]| -> Option<String> {
        let i = d.windows(2).position(|w| w == b"\r\n")?;
        let l = String::from_utf8(d[..i].to_vec()).unwrap();
        assert!(!l.contains('\n') && !l.contains('\r'), "a bare CR or LF in {l:?}");
        *d = &d[i + 2..];
        Some(l)
    };
    loop {
        if data.is_empty() {
            return out;
        }
        let mut d = data;
        let Some(status_line) = line(&mut d) else { return out };
        let status: u16 = status_line.strip_prefix("HTTP/1.1 ").and_then(|s| s.get(..3)).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("a status line: {status_line:?}"));
        let mut r = Resp { status, ..Resp::default() };
        loop {
            let Some(l) = line(&mut d) else { return out };
            if l.is_empty() {
                break;
            }
            let (n, v) = l.split_once(':').unwrap_or_else(|| panic!("a header line: {l:?}"));
            r.headers.push((n.to_ascii_lowercase(), v.trim().to_string()));
        }
        if (100..200).contains(&status) {
            data = d;
            continue; // interim: not counted
        }
        let head = heads.get(out.len()).copied().unwrap_or(false);
        if head || matches!(status, 204 | 304) {
        } else if r.header("transfer-encoding").is_some() {
            r.chunked = true;
            loop {
                let Some(size_line) = line(&mut d) else { return out };
                let size = usize::from_str_radix(size_line.split(';').next().unwrap(), 16).unwrap();
                if size == 0 {
                    loop {
                        let Some(l) = line(&mut d) else { return out };
                        if l.is_empty() {
                            break;
                        }
                        let (n, v) = l.split_once(':').unwrap();
                        r.trailers.push((n.to_ascii_lowercase(), v.trim().to_string()));
                    }
                    break;
                }
                if d.len() < size + 2 {
                    return out;
                }
                r.body.extend_from_slice(&d[..size]);
                assert_eq!(&d[size..size + 2], b"\r\n");
                d = &d[size + 2..];
            }
        } else if let Some(n) = r.header("content-length") {
            let n: usize = n.parse().unwrap();
            if d.len() < n {
                return out;
            }
            r.body = d[..n].to_vec();
            d = &d[n..];
        } else {
            r.body = d.to_vec();
            d = &[];
        }
        data = d;
        out.push(r);
    }
}

// ------------------------------------------------------------------------------------------------ a raw HTTP/2 client

/// A client that writes HTTP/2 frames by hand (prior knowledge, over plain TCP).
pub(super) struct Raw {
    s: TcpStream,
    enc: Encoder,
    dec: Decoder,
    buf: Vec<u8>,
    /// Frames read while looking for another stream's.
    pending: std::collections::VecDeque<F>,
}

/// A frame as read: its header and payload, and for HEADERS the fields, decoded as it arrived (the table depends on the
/// order).
#[derive(Debug, Clone)]
pub(super) struct F {
    pub(super) h: Header,
    pub(super) p: Vec<u8>,
    pub(super) fields: Vec<(String, String)>,
}

impl F {
    pub(super) fn is(&self, k: u8) -> bool {
        self.h.kind == k
    }
}

impl Raw {
    /// Connects, sends the preface and these SETTINGS, and reads the server's SETTINGS (acknowledging them).
    pub(super) fn connect(server: &Server, settings: &[(u16, u32)]) -> Raw {
        Raw::connect_to(server.addr, settings)
    }

    pub(super) fn connect_to(addr: SocketAddr, settings: &[(u16, u32)]) -> Raw {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut r = Raw { s, enc: Encoder::new(), dec: Decoder::new(4096, 1 << 20), buf: Vec::new(), pending: Default::default() };
        let mut out = PREFACE.to_vec();
        frame::write_settings(&mut out, settings);
        r.send(&out);
        let f = r.next().expect("the server's SETTINGS");
        assert!(f.is(kind::SETTINGS) && !f.h.has(flag::ACK), "{f:?}");
        let mut ack = Vec::new();
        frame::write_settings_ack(&mut ack);
        r.send(&ack);
        r
    }

    pub(super) fn send(&mut self, bytes: &[u8]) {
        let _ = self.s.write_all(bytes);
    }

    pub(super) fn headers(&mut self, id: u32, fields: &[(&str, &str)], end_stream: bool) {
        let block = self.block(fields);
        let mut out = Vec::new();
        frame::write_header_block(&mut out, id, end_stream, &block, 16_384);
        self.send(&out);
    }

    pub(super) fn block(&mut self, fields: &[(&str, &str)]) -> Vec<u8> {
        let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
        let mut block = Vec::new();
        self.enc.encode(&refs, &mut block);
        block
    }

    pub(super) fn get(&mut self, id: u32, path: &str) {
        self.headers(id, &[(":method", "GET"), (":scheme", "http"), (":authority", "a.example"), (":path", path)], true);
    }

    /// DATA, in frames of the largest size the server takes.
    pub(super) fn data(&mut self, id: u32, data: &[u8], end: bool) {
        let mut out = Vec::new();
        let mut chunks: Vec<&[u8]> = data.chunks(16_384).collect();
        if chunks.is_empty() {
            chunks.push(b"");
        }
        let last = chunks.len() - 1;
        for (i, c) in chunks.into_iter().enumerate() {
            frame::write_data(&mut out, id, end && i == last, c);
        }
        self.send(&out);
    }

    pub(super) fn raw_frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        let mut out = Vec::new();
        Header { length: payload.len() as u32, kind, flags, stream }.write(&mut out);
        out.extend_from_slice(payload);
        self.send(&out);
    }

    /// The next frame, or `None` when the server closes (or says nothing for five seconds).
    pub(super) fn next(&mut self) -> Option<F> {
        if let Some(f) = self.pending.pop_front() {
            return Some(f);
        }
        self.read_frame()
    }

    pub(super) fn read_frame(&mut self) -> Option<F> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.buf.len() >= HEADER_LEN {
                let h = Header::parse(self.buf[..HEADER_LEN].try_into().unwrap());
                let end = HEADER_LEN + h.length as usize;
                if self.buf.len() >= end {
                    let p = self.buf[HEADER_LEN..end].to_vec();
                    self.buf.drain(..end);
                    let mut fields = Vec::new();
                    if h.kind == kind::HEADERS {
                        if let Ok(Frame::Headers { fragment, .. }) = frame::parse(&h, &p) {
                            let mut out = Vec::new();
                            self.dec.decode(fragment, &mut out).unwrap();
                            fields = out.into_iter().map(|f| (String::from_utf8(f.name).unwrap(), String::from_utf8(f.value).unwrap())).collect();
                        }
                    }
                    return Some(F { h, p, fields });
                }
            }
            if Instant::now() > deadline {
                return None;
            }
            self.s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
            let mut chunk = [0u8; 65536];
            match self.s.read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => return None,
            }
        }
    }

    /// Frames until one matches, answering PINGs and SETTINGS; all of them.
    pub(super) fn until(&mut self, mut want: impl FnMut(&F) -> bool) -> Vec<F> {
        let mut seen = Vec::new();
        while let Some(f) = self.next() {
            if f.is(kind::SETTINGS) && !f.h.has(flag::ACK) {
                let mut ack = Vec::new();
                frame::write_settings_ack(&mut ack);
                self.send(&ack);
            }
            let done = want(&f);
            seen.push(f);
            if done {
                break;
            }
        }
        seen
    }

    /// The GOAWAY's error code, once it comes (`None` if the connection ends without one).
    pub(super) fn goaway(&mut self) -> Option<u32> {
        let frames = self.until(|f| f.is(kind::GOAWAY));
        frames.last().filter(|f| f.is(kind::GOAWAY)).map(|f| u32::from_be_bytes(f.p[4..8].try_into().unwrap()))
    }

    /// The RST_STREAM on `id`, if it comes before the stream ends.
    pub(super) fn reset_of(&mut self, id: u32) -> Option<u32> {
        let frames = self.until(|f| f.h.stream == id && (f.is(kind::RST_STREAM) || f.h.has(flag::END_STREAM)) || f.is(kind::GOAWAY));
        frames.last().filter(|f| f.is(kind::RST_STREAM)).map(|f| u32::from_be_bytes(f.p[..4].try_into().unwrap()))
    }

    /// The response on `id`: status, fields, body; reads until the stream ends.
    pub(super) fn response(&mut self, id: u32) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut status = 0;
        let mut fields = Vec::new();
        let mut body = Vec::new();
        loop {
            let f = match self.pending.iter().position(|f| f.h.stream == id) {
                Some(i) => self.pending.remove(i).unwrap(),
                None => {
                    let f = self.read_frame().unwrap_or_else(|| panic!("stream {id} did not end"));
                    if f.h.stream != id {
                        self.pending.push_back(f);
                        continue;
                    }
                    f
                }
            };
            match frame::parse(&f.h, &f.p).unwrap() {
                Frame::Headers { end_stream, .. } => {
                    for (n, v) in self.decode(&f) {
                        if n == ":status" {
                            let s: u16 = v.parse().unwrap();
                            if s >= 200 {
                                status = s;
                            }
                        } else {
                            fields.push((n, v));
                        }
                    }
                    if end_stream {
                        return (status, fields, body);
                    }
                }
                Frame::Data { data, end_stream, .. } => {
                    body.extend_from_slice(data);
                    if end_stream {
                        return (status, fields, body);
                    }
                }
                Frame::RstStream { code, .. } => panic!("stream {id} reset: {code:?}"),
                Frame::WindowUpdate { .. } => {}
                other => panic!("{other:?}"),
            }
        }
    }

    pub(super) fn decode(&mut self, f: &F) -> Vec<(String, String)> {
        assert!(f.is(kind::HEADERS));
        f.fields.clone()
    }
}

