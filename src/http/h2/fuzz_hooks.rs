//! Entry points for the fuzzer (`fuzz/`), which cannot reach the `pub(crate)` HTTP/2 layers. Built only with
//! `--cfg pratique_fuzzing`. Each one runs a layer on whatever bytes it is given and panics when a property that
//! must hold for any input does not: what the layer writes can be read back, the flow-control books balance, nothing
//! is left waiting after the connection is lost.

use super::connection::{Collected, Config, Connection, Direct, Request, StreamEvent};
use super::frame::{self, ErrorCode, Frame, Header, DEFAULT_MAX_FRAME_SIZE, HEADER_LEN, PREFACE};
use super::hpack::{Decoder, Encoder, FieldRef};

/// `data[0]` chooses the table size the decoder allows and the longest list it keeps; `data[1..]` is a header block,
/// decoded twice in a row (the second time against the dynamic table the first left). A list that decoded within
/// the limit must be written by an encoder and read back by a fresh decoder as the same list, with and without the
/// fields marked sensitive.
pub fn hpack(data: &[u8]) {
    let Some((&sel, block)) = data.split_first() else { return };
    let allowed = [0usize, 64, 512, 4096][(sel & 3) as usize];
    let list = [100usize, 1000, 64 << 10, 1 << 20][((sel >> 2) & 3) as usize];
    let mut decoder = Decoder::new(allowed, list);
    let mut fields = Vec::new();
    let first = decoder.decode(block, &mut fields);
    let mut again = Vec::new();
    let _ = decoder.decode(block, &mut again);
    if let Ok(true) = first {
        for sensitive in [false, true] {
            let refs: Vec<FieldRef<'_>> = fields.iter().map(|f| FieldRef { name: &f.name, value: &f.value, sensitive }).collect();
            let mut encoder = Encoder::new();
            let mut wire = Vec::new();
            encoder.encode(&refs, &mut wire);
            // and a second block on the same pair, which uses what the first put in the table
            let mut wire2 = Vec::new();
            encoder.encode(&refs, &mut wire2);
            let mut fresh = Decoder::new(4096, 1 << 24);
            let mut back = Vec::new();
            assert_eq!(fresh.decode(&wire, &mut back), Ok(true), "a block we wrote does not decode");
            assert_eq!(back, fields, "a block we wrote decodes to other fields");
            let mut back2 = Vec::new();
            assert_eq!(fresh.decode(&wire2, &mut back2), Ok(true), "a second block we wrote does not decode");
            assert_eq!(back2, fields, "a second block we wrote decodes to other fields");
        }
    }
}

/// Splits `data` into frames as far as it goes and takes each apart. The pieces of a frame that parsed must lie
/// within its payload.
pub fn frames(data: &[u8]) -> usize {
    let mut pos = 0;
    let mut count = 0;
    while data.len() - pos >= HEADER_LEN {
        let header = Header::parse(data[pos..pos + HEADER_LEN].try_into().unwrap());
        let end = pos + HEADER_LEN + header.length as usize;
        if end > data.len() {
            break;
        }
        let payload = &data[pos + HEADER_LEN..end];
        if let Ok(frame) = frame::parse(&header, payload) {
            match frame {
                Frame::Data { data, flow_len, .. } => assert!(data.len() <= flow_len as usize && flow_len == header.length),
                Frame::Headers { fragment, .. } | Frame::Continuation { fragment, .. } => assert!(fragment.len() <= payload.len()),
                Frame::Settings { ack, values } => assert!(values.len() * 6 == payload.len() && (!ack || values.is_empty())),
                Frame::GoAway { debug, .. } => assert!(debug.len() + 8 == payload.len()),
                Frame::Ping { .. } => assert_eq!(payload.len(), 8),
                Frame::WindowUpdate { .. } | Frame::RstStream { .. } => assert_eq!(payload.len(), 4),
                Frame::Priority { .. } | Frame::PushPromise { .. } | Frame::Unknown { .. } => {}
            }
        }
        count += 1;
        pos = end;
    }
    count
}

/// The client's connection against a server that sends `data[4..]`, twice: once with the bytes fed as they come, and once
/// fed by the reader of the first stream, whose body then goes straight into its buffer (as the transport does, B-87).
/// `data[0]` chooses the windows the client announces, whether the server's SETTINGS come first, the limit on a header
/// list and whether the first stream's reader takes one piece a step or all there is; `data[1]` how many requests
/// are made (one to three, a GET, a POST and a HEAD), whether the application reads the responses in pieces, has
/// every stream collect its whole body (with a limit that may be small), or switches the first stream to collecting
/// half way through the server's bytes, and that limit; `data[2]` how many bytes the server's bytes come in at a
/// time; `data[3]` the size of the application's reads. After every step the books must balance, what the client
/// writes must be frames that parse and header blocks that decode, a collected body is never longer than its
/// limit, and when the transport is lost every stream must end or fail, with nothing left in the connection once
/// they are released. And what each stream gave the application (read in pieces, straight into the reader's buffer, or
/// collected) is the start of what the server's DATA frames for it carry, in order; all of it, if the stream ended.
pub fn client(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    client_run(data, false);
    client_run(data, true);
}

fn client_run(data: &[u8], direct: bool) {
    let config = Config {
        stream_window: [1000u32, 65_535, 1 << 20, 8 << 20][(data[0] & 3) as usize],
        connection_window: [65_535u32, 100_000, 1 << 20, 32 << 20][((data[0] >> 2) & 3) as usize],
        max_header_list: [300u32, 64 << 10][((data[0] >> 4) & 1) as usize],
    };
    let settled = (data[0] >> 5) & 1 == 0;
    // the first stream's reader takes one piece a step instead of all there is (so that bytes are held unread when more come)
    let lazy = (data[0] >> 6) & 1 == 1;
    let requests = 1 + (data[1] % 3) as usize;
    // how bodies are taken: 0 in pieces, 1 and 2 collected from the start, 3 collected from half way (by the first stream)
    let collect_mode = (data[1] >> 2) & 3;
    let limit = [1u64 << 30, 200, 5000, 100][((data[1] >> 4) & 3) as usize];
    let piece = 1 + data[2] as usize % 200;
    let mut buf = vec![0u8; 1 + data[3] as usize % 600];

    let mut c = Connection::new(config);
    let mut wire = Writer::default();
    wire.take(&mut c);
    let mut input = Vec::new();
    if settled {
        frame::write_settings(&mut input, &[]);
    }
    input.extend_from_slice(&data[4..]);

    let mut ids = Vec::new();
    let mut posts = Vec::new();
    let open = |c: &mut Connection, ids: &mut Vec<u32>, posts: &mut Vec<u32>| {
        for i in 0..requests {
            let method = ["GET", "POST", "HEAD"][i % 3];
            let headers = vec![("accept".to_string(), "*/*".to_string()), ("x-n".to_string(), i.to_string())];
            let request = Request { method, scheme: "https", authority: "example.com", path: "/a?b=c", headers: &headers, secret: &[] };
            if let Ok(id) = c.open_stream(&request, method != "POST") {
                ids.push(id);
                if method == "POST" {
                    posts.push(id);
                }
            }
        }
    };

    let mut offset = 0;
    let mut lost = false;
    if settled {
        // the server's SETTINGS first, then the requests
        let first = HEADER_LEN.min(input.len());
        lost = c.feed(&input[..first]).is_err();
        offset = first;
    }
    open(&mut c, &mut ids, &mut posts);
    // what each stream has given the application so far, and whether a collected body was taken (it is given once)
    let mut delivered: Vec<Vec<u8>> = vec![Vec::new(); ids.len()];
    let mut taken = vec![false; ids.len()];
    let mut scratch = vec![0u8; buf.len()];
    let mut collecting: Vec<u32> = Vec::new();
    if collect_mode == 1 || collect_mode == 2 {
        for &id in &ids {
            c.collect_stream(id, limit);
            collecting.push(id);
        }
    }
    wire.take(&mut c);
    let switch_at = input.len() / 2;
    while !lost && offset < input.len() {
        let end = (offset + piece).min(input.len());
        match ids.first() {
            Some(&first) if direct => {
                let mut d = Direct::new(first, &mut scratch);
                lost = c.feed_direct(&input[offset..end], Some(&mut d)).is_err();
                let w = d.written();
                assert!(w == 0 || !collecting.contains(&first), "a stream that collects had its body written to a reader's buffer");
                delivered[0].extend_from_slice(&scratch[..w]);
            }
            _ => lost = c.feed(&input[offset..end]).is_err(),
        }
        offset = end;
        c.assert_books();
        if collect_mode == 3 && offset >= switch_at && collecting.is_empty() {
            if let Some(&first) = ids.first() {
                // what was read so far was read; the rest is collected
                read_all(&mut c, first, &mut buf, &mut delivered[0]);
                c.collect_stream(first, limit);
                collecting.push(first);
            }
        }
        for (i, &id) in ids.iter().enumerate() {
            if collecting.contains(&id) {
                poll_collected(&mut c, id, limit, false, &mut delivered[i], &mut taken[i]);
            } else if lazy && i == 0 {
                if let StreamEvent::Data(n) = c.poll_stream(id, &mut buf) {
                    assert!(n > 0 && n <= buf.len());
                    delivered[0].extend_from_slice(&buf[..n]);
                }
            } else {
                read_all(&mut c, id, &mut buf, &mut delivered[i]);
            }
        }
        for &id in &posts {
            let room = c.send_capacity(id);
            if room > 0 {
                let _ = c.send_data(id, &[7u8; 64][..room.min(64)], false);
            }
        }
        c.assert_books();
        wire.take(&mut c);
    }
    c.peer_closed();
    for (i, &id) in ids.iter().enumerate() {
        let (sent, end) = sent_body(&input, id);
        let ended = if collecting.contains(&id) {
            poll_collected(&mut c, id, limit, true, &mut delivered[i], &mut taken[i]);
            taken[i]
        } else {
            match read_all(&mut c, id, &mut buf, &mut delivered[i]) {
                StreamEvent::End => true,
                StreamEvent::Failed(_) => false,
                other => panic!("stream {id} is {other:?} after the connection was lost"),
            }
        };
        let got = &delivered[i];
        assert!(sent.starts_with(got), "stream {id} gave {} bytes that are not the start of the {} its DATA frames carry", got.len(), sent.len());
        if ended {
            assert_eq!(Some(got.len()), end, "stream {id} ended with {} bytes of body, where its DATA frames carry {end:?} to the end", got.len());
        }
        c.release_stream(id);
    }
    c.assert_books();
    assert_eq!(c.active_streams(), 0, "a stream is still active after every one was released");
    wire.take(&mut c);
    wire.check();
}

/// Asks a collecting stream for its body: if it is done, the body is within the limit, and the first time it is added to
/// what the stream gave (`taken` says it was); if the transport is lost (`over`), it must be done or failed, and not still
/// waiting.
fn poll_collected(c: &mut Connection, id: u32, limit: u64, over: bool, delivered: &mut Vec<u8>, taken: &mut bool) {
    let mut body = Vec::new();
    match c.collected(id, &mut body) {
        Collected::Done(_) => {
            assert!(body.len() as u64 <= limit, "a collected body of {} bytes is over the limit {limit}", body.len());
            if !*taken {
                delivered.extend_from_slice(&body);
                *taken = true;
            }
        }
        Collected::Failed { .. } => {}
        Collected::Pending(_) => assert!(!over, "stream {id} is still pending after the connection was lost"),
    }
}

/// Reads what a stream has until it has nothing new, adding the body to `delivered`; returns the last event.
fn read_all(c: &mut Connection, id: u32, buf: &mut [u8], delivered: &mut Vec<u8>) -> StreamEvent {
    loop {
        match c.poll_stream(id, buf) {
            StreamEvent::Data(n) => {
                assert!(n > 0 && n <= buf.len());
                delivered.extend_from_slice(&buf[..n]);
            }
            StreamEvent::Head(_) | StreamEvent::Trailers(_) => {}
            other => return other,
        }
    }
}

/// What the server's bytes carry as the body of stream `id`, read as a frame splitter that knows nothing else: the payloads
/// of its DATA frames in order (with the part of one that is cut off at the end, unless it is padded, since the client
/// passes on such a payload as it comes), and how long that is at the first frame on the stream with END_STREAM, if
/// there is one (a DATA frame, or HEADERS: the head of a response with no body, or trailers). Whatever the client made of
/// the bytes, what it gave the application for the stream can only be the start of this, and all of it if it ended.
fn sent_body(input: &[u8], id: u32) -> (Vec<u8>, Option<usize>) {
    let mut body = Vec::new();
    let mut pos = 0;
    while input.len() - pos >= HEADER_LEN {
        let header = Header::parse(input[pos..pos + HEADER_LEN].try_into().unwrap());
        if header.length > DEFAULT_MAX_FRAME_SIZE {
            break;
        }
        let end = pos + HEADER_LEN + header.length as usize;
        let ends_stream = header.flags & frame::flag::END_STREAM != 0;
        if header.stream == id && header.kind == frame::kind::DATA {
            if end > input.len() {
                if header.flags & frame::flag::PADDED == 0 {
                    body.extend_from_slice(&input[pos + HEADER_LEN..]);
                }
                break;
            }
            if let Ok(Frame::Data { data, .. }) = frame::parse(&header, &input[pos + HEADER_LEN..end]) {
                body.extend_from_slice(data);
            }
        }
        if end > input.len() {
            break;
        }
        if header.stream == id && ends_stream && (header.kind == frame::kind::DATA || header.kind == frame::kind::HEADERS) {
            let len = body.len();
            return (body, Some(len));
        }
        pos = end;
    }
    (body, None)
}

/// What a client connection has written, kept to be checked at the end.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    prefaced: bool,
}

impl Writer {
    fn take(&mut self, c: &mut Connection) {
        let n = c.output().len();
        self.bytes.extend_from_slice(c.output());
        c.consume_output(n);
    }

    /// The bytes are the preface and then whole frames that parse, and the header blocks in them decode.
    fn check(&mut self) {
        let mut rest = &self.bytes[..];
        if !self.prefaced {
            assert!(rest.starts_with(PREFACE), "the connection did not begin with the preface");
            rest = &rest[PREFACE.len()..];
            self.prefaced = true;
        }
        let mut decoder = Decoder::new(4096, 1 << 20);
        let mut block: Vec<u8> = Vec::new();
        let mut in_block = false;
        while !rest.is_empty() {
            assert!(rest.len() >= HEADER_LEN, "a frame header was cut short");
            let header = Header::parse(rest[..HEADER_LEN].try_into().unwrap());
            assert!(header.length <= DEFAULT_MAX_FRAME_SIZE, "a frame larger than the peer allows");
            let end = HEADER_LEN + header.length as usize;
            assert!(rest.len() >= end, "a frame was cut short");
            let frame = frame::parse(&header, &rest[HEADER_LEN..end]).unwrap_or_else(|e| panic!("a frame the client wrote does not parse: {e:?}"));
            match frame {
                Frame::Headers { end_headers, fragment, .. } => {
                    assert!(!in_block, "a HEADERS inside a header block");
                    block.clear();
                    block.extend_from_slice(fragment);
                    in_block = !end_headers;
                    if end_headers {
                        let mut fields = Vec::new();
                        assert_eq!(decoder.decode(&block, &mut fields), Ok(true), "a header block the client wrote does not decode");
                    }
                }
                Frame::Continuation { end_headers, fragment, .. } => {
                    assert!(in_block, "a CONTINUATION outside a header block");
                    block.extend_from_slice(fragment);
                    if end_headers {
                        in_block = false;
                        let mut fields = Vec::new();
                        assert_eq!(decoder.decode(&block, &mut fields), Ok(true), "a header block the client wrote does not decode");
                    }
                }
                _ => assert!(!in_block, "a frame inside a header block"),
            }
            rest = &rest[end..];
        }
        assert!(!in_block, "a header block was left open");
    }
}

/// The server's connection against a client that sends `data[3..]` after its preface (and, if `data[0]` says so, its
/// SETTINGS): every request is answered with a small body, a stream that is reset or ended is not answered twice,
/// and the books must balance as far as the server can say, which is that nothing panics and what it writes parses.
#[cfg(feature = "server")]
pub fn server(data: &[u8]) {
    use super::super::h2_server::{response, Event, ServerConn, Settings};
    if data.len() < 3 {
        return;
    }
    let settings = Settings {
        max_concurrent_streams: [1u32, 3, 100][(data[0] % 3) as usize],
        initial_window: [100u32, 65_535, 1 << 20][((data[0] >> 2) % 3) as usize],
        connection_window: [65_535u32, 1 << 20][((data[0] >> 4) & 1) as usize],
        max_body: [64usize, 1 << 16][((data[0] >> 5) & 1) as usize],
        ..Settings::default()
    };
    let piece = 1 + data[1] as usize % 200;
    let mut server = ServerConn::new(settings);
    let mut input = Vec::new();
    if (data[0] >> 6) & 1 == 0 {
        input.extend_from_slice(PREFACE);
        frame::write_settings(&mut input, &[]);
    }
    input.extend_from_slice(&data[3..]);
    let mut answered = std::collections::HashSet::new();
    let mut written = Vec::new();
    for chunk in input.chunks(piece) {
        server.receive(chunk);
        match server.process() {
            Ok(events) => {
                for event in events {
                    if let Event::Headers { stream, .. } = event {
                        if answered.insert(stream) {
                            for step in response(200, &[("x-a", "b")], b"hello") {
                                let _ = server.act(stream, step.action);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // the GOAWAY that says why
                written.extend_from_slice(server.output());
                break;
            }
        }
        server.pump_data();
        written.extend_from_slice(server.output());
        let n = server.output().len();
        server.consume_output(n);
    }
    // what the server wrote is whole frames that parse (its first frame is SETTINGS: it has no preface)
    let mut rest = &written[..];
    while !rest.is_empty() {
        assert!(rest.len() >= HEADER_LEN, "the server wrote a frame header and stopped");
        let header = Header::parse(rest[..HEADER_LEN].try_into().unwrap());
        let end = HEADER_LEN + header.length as usize;
        assert!(rest.len() >= end, "the server wrote a frame and stopped");
        frame::parse(&header, &rest[HEADER_LEN..end]).unwrap_or_else(|e| panic!("a frame the server wrote does not parse: {e:?}"));
        rest = &rest[end..];
    }
}

/// Valid flights from a server, for seeds: what a client sees for a response with a body and trailers, interim
/// responses, resets, window updates, a GOAWAY and a header block in pieces.
pub fn example_server_flights() -> Vec<Vec<u8>> {
    let mut encoder = Encoder::new();
    let mut block = |fields: &[(&str, &str)]| -> Vec<u8> {
        let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
        let mut out = Vec::new();
        encoder.encode(&refs, &mut out);
        out
    };
    let mut flights = Vec::new();

    let mut f = Vec::new();
    frame::write_header_block(&mut f, 1, false, &block(&[(":status", "200"), ("content-type", "text/plain"), ("content-length", "5")]), 16384);
    frame::write_data(&mut f, 1, true, b"hello");
    flights.push(f);

    let mut f = Vec::new();
    frame::write_header_block(&mut f, 1, false, &block(&[(":status", "103"), ("link", "</a>; rel=preload")]), 16384);
    frame::write_header_block(&mut f, 1, false, &block(&[(":status", "200"), ("server", "x")]), 16384);
    frame::write_data(&mut f, 1, false, &[b'a'; 300]);
    frame::write_header_block(&mut f, 1, true, &block(&[("x-trailer", "1")]), 16384);
    frame::write_ping(&mut f, false, *b"12345678");
    frame::write_window_update(&mut f, 0, 1000);
    flights.push(f);

    let mut f = Vec::new();
    frame::write_header_block(&mut f, 1, false, &block(&[(":status", "200")]), 16384);
    frame::write_data(&mut f, 1, false, b"partial");
    frame::write_rst_stream(&mut f, 1, ErrorCode::INTERNAL_ERROR);
    frame::write_header_block(&mut f, 3, true, &block(&[(":status", "204")]), 16384);
    frame::write_goaway(&mut f, 3, ErrorCode::NO_ERROR, b"bye");
    flights.push(f);

    // a big header block in pieces of 50 bytes: HEADERS and CONTINUATION frames
    let mut f = Vec::new();
    let long = "v".repeat(400);
    let whole = block(&[(":status", "200"), ("x-long", &long), ("x-other", "1")]);
    let pieces: Vec<&[u8]> = whole.chunks(50).collect();
    for (i, piece) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        let kind = if i == 0 { frame::kind::HEADERS } else { frame::kind::CONTINUATION };
        Header { length: piece.len() as u32, kind, flags: if last { frame::flag::END_HEADERS } else { 0 }, stream: 1 }.write(&mut f);
        f.extend_from_slice(piece);
    }
    frame::write_data(&mut f, 1, true, b"x");
    flights.push(f);

    let mut f = Vec::new();
    frame::write_settings(&mut f, &[(frame::setting::INITIAL_WINDOW_SIZE, 100), (frame::setting::MAX_FRAME_SIZE, 16384)]);
    frame::write_settings_ack(&mut f);
    frame::write_window_update(&mut f, 1, 50);
    frame::write_header_block(&mut f, 5, true, &block(&[(":status", "304")]), 16384);
    flights.push(f);
    flights
}

/// Header blocks that decode, for seeds.
pub fn example_header_blocks() -> Vec<Vec<u8>> {
    let mut encoder = Encoder::new();
    let mut out = Vec::new();
    for fields in [
        &[(":status", "200"), ("content-type", "text/html"), ("content-length", "1234")][..],
        &[(":method", "GET"), (":scheme", "https"), (":path", "/index.html"), (":authority", "example.com"), ("accept", "*/*")][..],
        &[("cookie", "a=b"), ("set-cookie", "c=d; Path=/"), ("x-same", "x-same"), ("x-same", "x-same")][..],
    ] {
        let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: n == &"set-cookie" }).collect();
        let mut block = vec![0u8];
        encoder.encode(&refs, &mut block);
        out.push(block);
    }
    out
}

/// What a client writes after its preface: requests with bodies, header blocks in pieces, window updates, a ping
/// and a reset, for seeds of the server's target.
pub fn example_client_flights() -> Vec<Vec<u8>> {
    let mut flights = Vec::new();
    for (method, end, long) in [("GET", true, false), ("POST", false, false), ("GET", true, true)] {
        let mut c = Connection::new(Config::default());
        let mut headers = vec![("accept".to_string(), "*/*".to_string())];
        if long {
            headers.push(("x-long".to_string(), "v".repeat(40_000)));
        }
        let request = Request { method, scheme: "https", authority: "example.com", path: "/a?b=c", headers: &headers, secret: &[] };
        let _ = c.feed(&{
            let mut s = Vec::new();
            frame::write_settings(&mut s, &[]);
            s
        });
        if let Ok(id) = c.open_stream(&request, end) {
            if !end {
                let _ = c.send_data(id, b"a request body", true);
            }
        }
        let out = c.output().to_vec();
        // the preface and the client's SETTINGS are the fuzz target's own business
        let mut rest = &out[PREFACE.len()..];
        let settings_len = HEADER_LEN + Header::parse(rest[..HEADER_LEN].try_into().unwrap()).length as usize;
        rest = &rest[settings_len..];
        flights.push(rest.to_vec());
    }
    flights
}
