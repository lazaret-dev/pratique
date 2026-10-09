use super::*;
use crate::http::h2::hpack::FieldRef;
use crate::http::h3::frame::{put_data, put_frame_header, put_headers, FrameReader};
use crate::http::h3::qpack;

use crate::http::h3::connection::harness::{Fake, SERVER_CONTROL, SERVER_QPACK_DECODER, SERVER_QPACK_ENCODER};

// ---------------------------------------------------------------------------------------------------- a server of sorts

fn settings_frame(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut payload = vec![];
    for &(id, v) in pairs {
        wire::put_varint(&mut payload, id);
        wire::put_varint(&mut payload, v);
    }
    let mut out = vec![];
    put_frame_header(&mut out, frame::ty::SETTINGS, payload.len() as u64);
    out.extend_from_slice(&payload);
    out
}

/// A connection, a transport, and the server's three streams opened with `settings` on the control stream.
fn started_with(cfg: Config, settings: &[(u64, u64)]) -> (Connection, Fake) {
    let mut c = Connection::new(cfg);
    let mut f = Fake::new();
    c.process(&mut f).unwrap();
    let mut control = vec![0x00];
    control.extend_from_slice(&settings_frame(settings));
    f.push(SERVER_CONTROL, &control, false);
    f.push(SERVER_QPACK_ENCODER, &[0x02], false);
    f.push(SERVER_QPACK_DECODER, &[0x03], false);
    c.process(&mut f).unwrap();
    (c, f)
}

fn started() -> (Connection, Fake) {
    started_with(Config::default(), &[(0x01, 0), (0x07, 0)])
}

fn fields_block(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut enc = Encoder::new(EncoderConfig { table_capacity: 0, blocked_streams: 0, only_safe_names: true });
    let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
    let mut out = vec![];
    enc.encode(0, &refs, &mut out);
    out
}

/// A response as the server writes it: HEADERS and DATA frames.
fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    let st = status.to_string();
    let mut fields = vec![(":status", st.as_str())];
    fields.extend_from_slice(headers);
    put_headers(&mut out, &fields_block(&fields));
    if !body.is_empty() {
        put_data(&mut out, body);
    }
    out
}

fn get(c: &mut Connection, f: &mut Fake) -> u64 {
    request(c, f, "GET", "/index.html")
}

fn request(c: &mut Connection, f: &mut Fake, method: &str, path: &str) -> u64 {
    let headers = vec![("accept".to_string(), "*/*".to_string())];
    let r = Request { method, scheme: "https", authority: "example.com", path, headers: &headers, secret: &[] };
    c.open_stream(f, &r, true).unwrap()
}

/// What the application would see of a stream, in the order it comes, until it says it is pending.
fn events(c: &mut Connection, id: u64) -> Vec<StreamEvent> {
    let mut out = vec![];
    let mut buf = [0u8; 4096];
    loop {
        match c.poll_stream(id, &mut buf) {
            StreamEvent::Pending => return out,
            StreamEvent::Data(n) => {
                if let Some(StreamEvent::Data(m)) = out.last_mut() {
                    *m += n;
                } else {
                    out.push(StreamEvent::Data(n));
                }
            }
            e @ (StreamEvent::End | StreamEvent::Failed(_)) => {
                out.push(e);
                return out;
            }
            e => out.push(e),
        }
    }
}

fn status_of(e: &StreamEvent) -> u16 {
    match e {
        StreamEvent::Head(h) => h.status,
        e => panic!("{e:?} is not a head"),
    }
}

fn failure(e: &StreamEvent) -> &StreamError {
    match e {
        StreamEvent::Failed(f) => f,
        e => panic!("{e:?} is not a failure"),
    }
}

fn frames_of(bytes: &[u8], kind: Kind) -> Vec<Event> {
    let mut r = FrameReader::new(kind, 1 << 20);
    let mut ev = vec![];
    r.feed(bytes, &mut ev).unwrap();
    ev
}

// ---------------------------------------------------------------------------------------------------- the streams of a client

#[test]
fn the_client_opens_its_control_stream_and_the_two_of_qpack() {
    let mut c = Connection::new(Config::default());
    let mut f = Fake::new();
    c.process(&mut f).unwrap();
    // (the streams are 2, 6 and 10: the first three unidirectional ones of a client)
    let control = f.written(2);
    assert_eq!(control[0], 0x00, "the control stream's type");
    let ev = frames_of(&control[1..], Kind::Control);
    let Event::Settings(pairs) = &ev[0] else { panic!("{ev:?}") };
    assert_eq!(&pairs[..3], &[(0x01, 4096), (0x07, 16), (0x06, 64 << 10)]);
    assert_eq!(f.written(6), &[0x02]);
    assert_eq!(f.written(10), &[0x03]);
    assert!(f.sent.values().all(|s| !s.fin), "none of them ends");
}

#[test]
fn the_streams_are_opened_when_the_server_allows_them() {
    let mut c = Connection::new(Config::default());
    let mut f = Fake::new();
    f.max_open = [100, 1];
    c.process(&mut f).unwrap();
    assert_eq!(f.written(2)[0], 0x00);
    assert!(f.sent.get(&6).is_none());
    f.max_open[1] = 3;
    c.process(&mut f).unwrap();
    assert_eq!(f.written(6), &[0x02]);
    assert_eq!(f.written(10), &[0x03]);
    // and a request waits for its own limit
    f.max_open[0] = 0;
    let headers = vec![];
    let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    assert_eq!(c.open_stream(&mut f, &r, true), Err(OpenError::Full));
    assert!(c.usable());
    f.max_open[0] = 1;
    assert_eq!(c.open_stream(&mut f, &r, true), Ok(0));
}

#[test]
fn a_request_is_a_headers_frame_and_the_end_of_the_stream() {
    let (mut c, mut f) = started();
    let headers = vec![("Accept".to_string(), "*/*".to_string()), ("Connection".to_string(), "close".to_string()), ("Host".to_string(), "other".to_string())];
    let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/a?b=c", headers: &headers, secret: &[] };
    let id = c.open_stream(&mut f, &r, true).unwrap();
    assert_eq!(id, 0);
    let s = &f.sent[&0];
    assert!(s.fin);
    let ev = frames_of(&s.data, Kind::Request);
    let Event::Headers(block) = &ev[0] else { panic!("{ev:?}") };
    assert_eq!(ev.len(), 1);
    // what a decoder makes of it: the pseudo-headers, then the fields in lower case, with the connection-specific ones and Host gone
    let mut dec = Decoder::new(0, 0, 1 << 20);
    let mut got = vec![];
    assert!(matches!(dec.decode(0, block, &mut got), Ok(Decoded::Done { within_limit: true })));
    let got: Vec<(String, String)> = got.iter().map(|f| (String::from_utf8(f.name.clone()).unwrap(), String::from_utf8(f.value.clone()).unwrap())).collect();
    let want = [(":method", "GET"), (":scheme", "https"), (":authority", "example.com"), (":path", "/a?b=c"), ("accept", "*/*")];
    assert_eq!(got, want.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>());
    c.assert_books();
}

#[test]
fn a_request_with_a_body_is_headers_then_data_frames() {
    let (mut c, mut f) = started();
    let headers = vec![];
    let r = Request { method: "POST", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    let id = c.open_stream(&mut f, &r, false).unwrap();
    assert!(!f.sent[&id].fin);
    assert_eq!(c.send_data(&mut f, id, b"hello ", false), Ok(6));
    assert_eq!(c.send_data(&mut f, id, b"world", true), Ok(5));
    assert!(f.sent[&id].fin);
    let ev = frames_of(f.written(id), Kind::Request);
    assert!(matches!(ev[0], Event::Headers(_)));
    let body: Vec<u8> = {
        let mut all = vec![];
        let bytes = f.written(id);
        let mut r = FrameReader::new(Kind::Request, 1 << 20);
        let mut ev = vec![];
        r.feed(bytes, &mut ev).unwrap();
        for e in ev {
            if let Event::Data(range) = e {
                all.extend_from_slice(&bytes[range]);
            }
        }
        all
    };
    assert_eq!(body, b"hello world");
    // nothing more after the end
    assert!(c.send_data(&mut f, id, b"x", false).is_err());
}

#[test]
fn what_the_transport_does_not_take_is_written_when_it_does() {
    let (mut c, mut f) = started();
    f.room = 10;
    let headers = vec![];
    let r = Request { method: "POST", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    let id = c.open_stream(&mut f, &r, false).unwrap();
    let body = vec![7u8; 5000];
    assert_eq!(c.send_data(&mut f, id, &body, true), Ok(5000));
    // (ten bytes were taken by the writes so far: the rest waits)
    assert!(f.written(id).len() <= 10 + 10);
    assert!(!f.sent[&id].fin);
    for _ in 0..2000 {
        f.events.push_back(TransportEvent::Writable(id));
        c.process(&mut f).unwrap();
        if f.sent[&id].fin {
            break;
        }
    }
    assert!(f.sent[&id].fin);
    let mut r = FrameReader::new(Kind::Request, 1 << 20);
    let mut ev = vec![];
    r.feed(f.written(id), &mut ev).unwrap();
    let got: usize = ev.iter().map(|e| if let Event::Data(r) = e { r.len() } else { 0 }).sum();
    assert_eq!(got, 5000);
}

#[test]
fn how_much_body_is_taken_is_bounded() {
    let cfg = Config { send_buffer: 1000, ..Config::default() };
    let (mut c, mut f) = started_with(cfg, &[]);
    f.room = 0;
    let headers = vec![];
    let r = Request { method: "POST", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    let id = c.open_stream(&mut f, &r, false).unwrap();
    let before = c.send_capacity(id);
    assert!(before < 1000 && before > 900, "{before}: what is left of 1000 after the request's head");
    let n = c.send_data(&mut f, id, &[1; 5000], true).unwrap();
    assert_eq!(n, before);
    assert_eq!(c.send_capacity(id), 0);
    // the end is not marked while some of the body was not taken, and nothing more fits
    assert!(!c.streams[&id].out.fin);
    assert_eq!(c.send_data(&mut f, id, &[1; 10], true), Ok(0));
    assert!(!c.streams[&id].out.fin);
    c.assert_books();
}

// ---------------------------------------------------------------------------------------------------- responses

#[test]
fn a_response_is_a_head_a_body_and_an_end() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[("content-type", "text/plain"), ("content-length", "11")], b"hello ");
    put_data(&mut bytes, b"world");
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(ev.len(), 3, "{ev:?}");
    let StreamEvent::Head(h) = &ev[0] else { panic!() };
    assert_eq!(h.status, 200);
    assert_eq!(h.headers, vec![("content-type".to_string(), "text/plain".to_string()), ("content-length".to_string(), "11".to_string())]);
    assert_eq!(ev[1], StreamEvent::Data(11));
    assert_eq!(ev[2], StreamEvent::End);
    // (it stays ended)
    assert_eq!(c.poll_stream(id, &mut [0; 8]), StreamEvent::End);
    c.assert_books();
}

#[test]
fn the_pieces_a_response_comes_in_do_not_matter() {
    let mut bytes = response(200, &[("content-type", "text/plain"), ("server", "x")], b"");
    for i in 0..30u8 {
        put_data(&mut bytes, &vec![i; 100 + usize::from(i) * 7]);
    }
    let expected: Vec<u8> = (0..30u8).flat_map(|i| vec![i; 100 + usize::from(i) * 7]).collect();
    for step in [1usize, 2, 3, 7, 50, 1000, 100_000] {
        let (mut c, mut f) = started();
        let id = get(&mut c, &mut f);
        let mut body = vec![];
        let mut head = None;
        let mut ended = false;
        for (i, chunk) in bytes.chunks(step).enumerate() {
            f.push(id, chunk, (i + 1) * step >= bytes.len());
            c.process(&mut f).unwrap();
            for e in events(&mut c, id) {
                match e {
                    StreamEvent::Head(h) => head = Some(h),
                    StreamEvent::Data(n) => body.push(n),
                    StreamEvent::End => ended = true,
                    e => panic!("{e:?}"),
                }
            }
        }
        assert!(ended && head.is_some(), "step {step}");
        assert_eq!(head.unwrap().status, 200);
        assert_eq!(body.iter().sum::<usize>(), expected.len(), "step {step}");
        c.assert_books();
    }
}

#[test]
fn the_body_is_what_the_server_sent() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[], b"");
    put_data(&mut bytes, b"abc");
    put_data(&mut bytes, b"defgh");
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    assert!(matches!(c.poll_stream(id, &mut [0; 1]), StreamEvent::Head(_)));
    let mut got = vec![];
    let mut buf = [0u8; 3];
    loop {
        match c.poll_stream(id, &mut buf) {
            StreamEvent::Data(n) => got.extend_from_slice(&buf[..n]),
            StreamEvent::End => break,
            e => panic!("{e:?}"),
        }
    }
    assert_eq!(got, b"abcdefgh");
    // taking in one go
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    assert!(matches!(c.take_stream_data(id, &mut vec![]), StreamEvent::Head(_)));
    let mut into = vec![];
    assert_eq!(c.take_stream_data(id, &mut into), StreamEvent::Data(8));
    assert_eq!(into, b"abcdefgh");
    assert_eq!(c.take_stream_data(id, &mut into), StreamEvent::End);
}

#[test]
fn trailers_come_after_the_body() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[], b"body");
    put_headers(&mut bytes, &fields_block(&[("x-checksum", "abc")]));
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(ev.len(), 4, "{ev:?}");
    assert_eq!(ev[2], StreamEvent::Trailers(vec![("x-checksum".to_string(), "abc".to_string())]));
    assert_eq!(ev[3], StreamEvent::End);
}

#[test]
fn a_stream_is_ready_when_the_application_has_something_to_poll() {
    // what the transport asks whom to wake: a stream that has news is ready, one that has none is not, a stream that is not known is
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    assert!(c.ready(id + 400), "an unknown stream fails when it is polled");
    assert!(!c.ready(id), "nothing has come");
    // the head
    let head = response(200, &[], b"");
    f.push(id, &head, false);
    c.process(&mut f).unwrap();
    assert!(c.ready(id));
    assert_eq!(status_of(&c.poll_stream(id, &mut [0; 8])), 200);
    assert!(!c.ready(id));
    // one byte of body
    let mut data = vec![];
    put_data(&mut data, b"x");
    f.push(id, &data, false);
    c.process(&mut f).unwrap();
    assert!(c.ready(id), "one byte is something");
    assert_eq!(c.poll_stream(id, &mut [0; 8]), StreamEvent::Data(1));
    assert!(!c.ready(id));
    // trailers whose stream has not ended yet
    let mut trailers = vec![];
    put_headers(&mut trailers, &fields_block(&[("x-checksum", "abc")]));
    f.push(id, &trailers, false);
    c.process(&mut f).unwrap();
    assert!(c.ready(id), "the trailers are something");
    assert!(matches!(c.poll_stream(id, &mut [0; 8]), StreamEvent::Trailers(_)));
    assert!(!c.ready(id));
    // the end, with nothing with it
    f.push(id, &[], true);
    c.process(&mut f).unwrap();
    assert!(c.ready(id), "the end is something");
    assert_eq!(c.poll_stream(id, &mut [0; 8]), StreamEvent::End);
    // a stream that failed is ready (and what it says is the failure)
    let id = get(&mut c, &mut f);
    f.reset_by_server(id, 0x10c);
    c.process(&mut f).unwrap();
    assert!(c.ready(id));
    assert!(matches!(c.poll_stream(id, &mut [0; 8]), StreamEvent::Failed(_)));
}

#[test]
fn trailers_with_a_pseudo_header_are_a_stream_error() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[], b"body");
    put_headers(&mut bytes, &fields_block(&[(":status", "200")]));
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(failure(ev.last().unwrap()).code, code::H3_MESSAGE_ERROR);
    assert!(c.usable() && f.closed.is_none(), "the connection is not lost for it");
    // the server is told, both ways
    assert_eq!(f.stopped_by_us.get(&id), Some(&code::H3_MESSAGE_ERROR));
    assert_eq!(f.sent[&id].reset, Some(code::H3_MESSAGE_ERROR));
    // and the encoder is told that nothing more will be read from the stream (a Stream Cancellation on the decoder stream)
    let out = f.written(10);
    assert_eq!(out.last(), Some(&(0x40 | id as u8)), "{out:02x?}");
}

#[test]
fn interim_responses_are_dropped_and_a_101_is_an_error() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(103, &[("link", "</style.css>; rel=preload")], b"");
    bytes.extend_from_slice(&response(100, &[], b""));
    bytes.extend_from_slice(&response(200, &[], b"x"));
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(status_of(&ev[0]), 200);
    assert_eq!(ev[ev.len() - 1], StreamEvent::End);

    let id = get(&mut c, &mut f);
    f.push(id, &response(101, &[], b""), false);
    c.process(&mut f).unwrap();
    assert_eq!(failure(&events(&mut c, id)[0]).code, code::H3_MESSAGE_ERROR);

    // a response that is only interim, and ends
    let id = get(&mut c, &mut f);
    f.push(id, &response(100, &[], b""), true);
    c.process(&mut f).unwrap();
    assert_eq!(failure(&events(&mut c, id)[0]).code, code::H3_REQUEST_INCOMPLETE);
    assert!(f.closed.is_none());
}

#[test]
fn a_response_that_is_not_one_is_a_stream_error() {
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("no status", vec![("content-type", "x")]),
        ("a status twice", vec![(":status", "200"), (":status", "200")]),
        ("a pseudo-header after a field", vec![("a", "b"), (":status", "200")]),
        ("a pseudo-header of a request", vec![(":status", "200"), (":path", "/")]),
        ("a connection-specific field", vec![(":status", "200"), ("transfer-encoding", "chunked")]),
        ("a status that is not a number", vec![(":status", "2xx")]),
        ("two lengths that differ", vec![(":status", "200"), ("content-length", "1"), ("content-length", "2")]),
    ];
    for (what, fields) in cases {
        let (mut c, mut f) = started();
        let id = get(&mut c, &mut f);
        let mut bytes = vec![];
        put_headers(&mut bytes, &fields_block(&fields));
        f.push(id, &bytes, false);
        c.process(&mut f).unwrap();
        let ev = events(&mut c, id);
        assert_eq!(failure(ev.last().unwrap()).code, code::H3_MESSAGE_ERROR, "{what}");
        assert!(f.closed.is_none(), "{what}");
    }
}

#[test]
fn the_length_a_response_says_is_the_length_it_has() {
    // more data than the length says: at once
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &response(200, &[("content-length", "3")], b"abcd"), false);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(failure(ev.last().unwrap()).code, code::H3_MESSAGE_ERROR);
    // less: when the stream ends
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &response(200, &[("content-length", "5")], b"abcd"), false);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, id).len(), 2, "head and data, and the rest to come");
    f.push(id, &[], true);
    c.process(&mut f).unwrap();
    assert_eq!(failure(&events(&mut c, id)[0]).code, code::H3_MESSAGE_ERROR);
    // as it says: fine
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &response(200, &[("content-length", "4")], b"abcd"), true);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, id).last(), Some(&StreamEvent::End));
}

#[test]
fn a_response_with_no_body_has_none() {
    // 204 and 304, whatever the length says
    for status in [204u16, 304] {
        let (mut c, mut f) = started();
        let id = get(&mut c, &mut f);
        f.push(id, &response(status, &[("content-length", "100")], b""), true);
        c.process(&mut f).unwrap();
        let ev = events(&mut c, id);
        assert_eq!(ev.last(), Some(&StreamEvent::End), "{status}");
        let (mut c, mut f) = started();
        let id = get(&mut c, &mut f);
        f.push(id, &response(status, &[], b"x"), true);
        c.process(&mut f).unwrap();
        assert_eq!(failure(events(&mut c, id).last().unwrap()).code, code::H3_MESSAGE_ERROR, "{status} with data");
    }
    // the response to HEAD
    let (mut c, mut f) = started();
    let id = request(&mut c, &mut f, "HEAD", "/");
    f.push(id, &response(200, &[("content-length", "100")], b""), true);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, id).last(), Some(&StreamEvent::End));
}

#[test]
fn a_response_that_ends_before_its_head_is_incomplete() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &[], true);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    let e = failure(&ev[0]);
    assert_eq!(e.code, code::H3_REQUEST_INCOMPLETE);
    assert!(!e.retry_safe);
    assert!(f.closed.is_none());
}

#[test]
fn a_stream_the_server_resets_fails_and_a_rejected_request_may_be_sent_again() {
    let (mut c, mut f) = started();
    let a = get(&mut c, &mut f);
    let b = get(&mut c, &mut f);
    f.reset_by_server(a, code::H3_REQUEST_REJECTED);
    f.reset_by_server(b, code::H3_INTERNAL_ERROR);
    c.process(&mut f).unwrap();
    let ea = events(&mut c, a);
    let eb = events(&mut c, b);
    assert_eq!((failure(&ea[0]).code, failure(&ea[0]).retry_safe), (code::H3_REQUEST_REJECTED, true));
    assert_eq!((failure(&eb[0]).code, failure(&eb[0]).retry_safe), (code::H3_INTERNAL_ERROR, false));
    assert!(c.usable());
}

#[test]
fn what_arrived_before_a_reset_is_seen_first() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &response(200, &[], b"partial"), false);
    c.process(&mut f).unwrap();
    f.reset_by_server(id, code::H3_REQUEST_CANCELLED);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(status_of(&ev[0]), 200);
    assert_eq!(ev[1], StreamEvent::Data(7));
    assert_eq!(failure(&ev[2]).code, code::H3_REQUEST_CANCELLED);
}

#[test]
fn a_body_that_is_not_read_holds_the_server_back() {
    let cfg = Config { body_buffer: 10_000, ..Config::default() };
    let (mut c, mut f) = started_with(cfg, &[]);
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[], b"");
    for _ in 0..50 {
        put_data(&mut bytes, &[9; 4000]);
    }
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    // some of it was taken in, no more than the limit and a read's worth, and the rest is still with the transport
    let waiting = f.recv[&id].data.len();
    assert!(waiting > 100_000, "{waiting} bytes are left for the transport to hold");
    c.assert_books();
    // as the application reads, the rest comes (nothing says so but the call: the connection has to be asked)
    let mut buf = vec![0u8; 100_000];
    let mut total = 0;
    let mut ended = false;
    for _ in 0..1000 {
        match c.poll_stream(id, &mut buf) {
            StreamEvent::Data(n) => total += n,
            StreamEvent::Head(_) => {}
            StreamEvent::End => {
                ended = true;
                break;
            }
            StreamEvent::Pending => {
                assert!(c.needs_processing(), "the stream waits and nothing will wake the connection");
                c.process(&mut f).unwrap();
            }
            e => panic!("{e:?}"),
        }
        c.assert_books();
    }
    assert!(ended);
    assert_eq!(total, 200_000);
}

// ---------------------------------------------------------------------------------------------------- QPACK

/// A server's encoder that makes a table for the client (4096 bytes, 16 streams may wait).
fn server_encoder() -> Encoder {
    let mut e = Encoder::new(EncoderConfig { table_capacity: 4096, blocked_streams: 16, only_safe_names: false });
    e.set_peer_settings(4096, 16);
    e
}

fn encode_with(e: &mut Encoder, stream: u64, fields: &[(&str, &str)]) -> Vec<u8> {
    let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
    let mut out = vec![];
    e.encode(stream, &refs, &mut out);
    out
}

fn server_headers(e: &mut Encoder, stream: u64, status: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut fields = vec![(":status", status)];
    fields.extend_from_slice(headers);
    let mut out = vec![];
    put_headers(&mut out, &encode_with(e, stream, &fields));
    out
}

#[test]
fn a_response_that_waits_for_the_table_is_read_when_it_comes() {
    let (mut c, mut f) = started_with(Config::default(), &[(0x01, 4096), (0x07, 16)]);
    let id = get(&mut c, &mut f);
    let mut enc = server_encoder();
    // the first response makes entries; the encoder will use them before they are acknowledged
    let first = server_headers(&mut enc, id, "200", &[("x-a", "1111"), ("x-b", "2222")]);
    let inserts = enc.take_output();
    let mut second = server_headers(&mut enc, id + 4, "200", &[("x-a", "1111"), ("x-b", "2222")]);
    second.extend_from_slice(&{
        let mut d = vec![];
        put_data(&mut d, b"two");
        d
    });
    let more = enc.take_output();
    let id2 = get(&mut c, &mut f);
    assert_eq!(id2, id + 4);
    // the sections come first, the instructions after
    f.push(id, &first, true);
    f.push(id2, &second, true);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, id), vec![]);
    assert_eq!(events(&mut c, id2), vec![]);
    c.assert_books();
    assert_eq!(c.decoder.blocked_streams(), 2);
    f.push(SERVER_QPACK_ENCODER, &[inserts, more].concat(), false);
    c.process(&mut f).unwrap();
    assert_eq!(c.decoder.blocked_streams(), 0);
    let ev = events(&mut c, id);
    assert_eq!(status_of(&ev[0]), 200);
    if let StreamEvent::Head(h) = &ev[0] {
        assert_eq!(h.headers, vec![("x-a".to_string(), "1111".to_string()), ("x-b".to_string(), "2222".to_string())]);
    }
    assert_eq!(ev.last(), Some(&StreamEvent::End));
    let ev2 = events(&mut c, id2);
    assert_eq!(ev2[1], StreamEvent::Data(3), "{ev2:?}");
    assert_eq!(ev2.last(), Some(&StreamEvent::End));
    c.assert_books();
    // the client told the server: a section acknowledgment for each stream, on the QPACK decoder stream
    let out = f.written(10);
    assert_eq!(out[0], 0x03);
    assert!(out.contains(&(0x80 | id as u8)) && out.contains(&(0x80 | id2 as u8)), "{out:02x?}");
}

#[test]
fn what_comes_behind_a_waiting_section_waits_with_it() {
    let (mut c, mut f) = started_with(Config::default(), &[(0x01, 4096), (0x07, 16)]);
    let id = get(&mut c, &mut f);
    let mut enc = server_encoder();
    let mut bytes = server_headers(&mut enc, id, "200", &[("x-a", "1111")]);
    put_data(&mut bytes, b"first");
    // trailers that refer to the table too
    put_headers(&mut bytes, &encode_with(&mut enc, id, &[("x-a", "1111")]));
    let inserts = enc.take_output();
    f.push(id, &bytes, true);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, id), vec![], "nothing is seen of a stream whose head waits");
    assert_eq!(c.decoder.blocked_streams(), 1);
    c.assert_books();
    f.push(SERVER_QPACK_ENCODER, &inserts, false);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(status_of(&ev[0]), 200);
    assert_eq!(ev[1], StreamEvent::Data(5));
    assert_eq!(ev[2], StreamEvent::Trailers(vec![("x-a".to_string(), "1111".to_string())]));
    assert_eq!(ev[3], StreamEvent::End);
    c.assert_books();
}

#[test]
fn more_streams_waiting_than_were_allowed_is_an_error_of_the_connection() {
    let cfg = Config { qpack_blocked_streams: 1, ..Config::default() };
    let (mut c, mut f) = started_with(cfg, &[(0x01, 4096), (0x07, 1)]);
    let a = get(&mut c, &mut f);
    let b = get(&mut c, &mut f);
    let mut enc = server_encoder();
    let one = server_headers(&mut enc, a, "200", &[("x-a", "1111")]);
    let two = server_headers(&mut enc, b, "200", &[("x-a", "1111")]);
    f.push(a, &one, false);
    f.push(b, &two, false);
    c.process(&mut f).unwrap_err();
    assert_eq!(f.closed_with(), Some(qpack::DECOMPRESSION_FAILED));
}

#[test]
fn an_instruction_that_makes_no_sense_ends_the_connection() {
    let (mut c, mut f) = started_with(Config::default(), &[(0x01, 4096), (0x07, 16)]);
    // an insert that names an entry that is not there
    f.push(SERVER_QPACK_ENCODER, &[0x3f, 0xe1, 0x1f, 0x80, 0x00], false);
    let e = c.process(&mut f).unwrap_err();
    assert_eq!(e.code, qpack::ENCODER_STREAM_ERROR);
    assert_eq!(f.closed_with(), Some(qpack::ENCODER_STREAM_ERROR));
    assert!(!c.usable());
    // and from then on every call says so
    assert_eq!(c.process(&mut f).unwrap_err().code, qpack::ENCODER_STREAM_ERROR);

    // an acknowledgment of a stream that has no section waiting
    let (mut c, mut f) = started();
    f.push(SERVER_QPACK_DECODER, &[0x84], false);
    assert_eq!(c.process(&mut f).unwrap_err().code, qpack::DECODER_STREAM_ERROR);
}

#[test]
fn a_section_that_cannot_be_decoded_ends_the_connection() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    // an indexed line that names an entry of the static table that is not there (190)
    let mut bytes = vec![];
    put_headers(&mut bytes, &[0x00, 0x00, 0xff, 0x7f]);
    f.push(id, &bytes, false);
    let e = c.process(&mut f).unwrap_err();
    assert_eq!(e.code, qpack::DECOMPRESSION_FAILED);
}

#[test]
fn a_stream_given_up_tells_the_encoder() {
    // (our capacity is 4096, so that the decoder has a stream to write on)
    let (mut c, mut f) = started_with(Config::default(), &[(0x01, 4096), (0x07, 16)]);
    let id = get(&mut c, &mut f);
    f.push(id, &response(200, &[], b"part"), false);
    c.process(&mut f).unwrap();
    let before = f.written(10).len();
    c.release_stream(&mut f, id);
    assert_eq!(f.stopped_by_us.get(&id), Some(&code::H3_REQUEST_CANCELLED));
    // a Stream Cancellation for it on the decoder stream
    let out = f.written(10);
    assert!(out.len() > before, "{out:02x?}");
    assert_eq!(out[out.len() - 1], 0x40 | id as u8);
    assert_eq!(c.active_streams(), 0);
}

// ---------------------------------------------------------------------------------------------------- what a server may not do

fn lost(f: &Fake, c: &Connection, code: u64) {
    assert_eq!(f.closed_with(), Some(code), "closed with {:?}", f.closed);
    assert!(!c.usable());
    assert_eq!(c.error().map(|e| e.code), Some(code));
}

#[test]
fn data_before_the_headers_ends_the_connection() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = vec![];
    put_data(&mut bytes, b"x");
    f.push(id, &bytes, false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_FRAME_UNEXPECTED);
    // a stream that was waiting fails with the connection
    let ev = events(&mut c, id);
    assert_eq!(failure(&ev[0]).code, code::H3_FRAME_UNEXPECTED);
}

#[test]
fn headers_after_the_trailers_end_the_connection() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[], b"x");
    put_headers(&mut bytes, &fields_block(&[("a", "b")]));
    put_headers(&mut bytes, &fields_block(&[("a", "b")]));
    f.push(id, &bytes, false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_FRAME_UNEXPECTED);
}

#[test]
fn data_after_the_trailers_ends_the_connection() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = response(200, &[], b"x");
    put_headers(&mut bytes, &fields_block(&[("a", "b")]));
    put_data(&mut bytes, b"late");
    f.push(id, &bytes, false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_FRAME_UNEXPECTED);
}

#[test]
fn a_push_promise_or_a_push_stream_ends_the_connection() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let mut bytes = vec![];
    put_frame_header(&mut bytes, frame::ty::PUSH_PROMISE, 2);
    bytes.extend_from_slice(&[0, 0]);
    f.push(id, &bytes, false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_ID_ERROR);

    let (mut c, mut f) = started();
    f.push(15, &[0x01, 0x00], false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_ID_ERROR);
}

#[test]
fn a_second_control_stream_or_qpack_stream_ends_the_connection() {
    for ty in [0x00u8, 0x02, 0x03] {
        let (mut c, mut f) = started();
        f.push(15, &[ty], false);
        c.process(&mut f).unwrap_err();
        lost(&f, &c, code::H3_STREAM_CREATION_ERROR);
    }
}

#[test]
fn a_critical_stream_that_ends_or_is_reset_ends_the_connection() {
    for id in [SERVER_CONTROL, SERVER_QPACK_ENCODER, SERVER_QPACK_DECODER] {
        let (mut c, mut f) = started();
        f.push(id, &[], true);
        c.process(&mut f).unwrap_err();
        lost(&f, &c, code::H3_CLOSED_CRITICAL_STREAM);
        let (mut c, mut f) = started();
        f.reset_by_server(id, 0);
        c.process(&mut f).unwrap_err();
        lost(&f, &c, code::H3_CLOSED_CRITICAL_STREAM);
    }
    // and when the server stops one of ours
    let (mut c, mut f) = started();
    f.events.push_back(TransportEvent::Stopped(6, 0));
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_CLOSED_CRITICAL_STREAM);
}

#[test]
fn the_control_stream_must_begin_with_settings_and_have_them_once() {
    let mut c = Connection::new(Config::default());
    let mut f = Fake::new();
    c.process(&mut f).unwrap();
    f.push(SERVER_CONTROL, &[0x00, 0x07, 0x01, 0x00], false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_MISSING_SETTINGS);

    let (mut c, mut f) = started();
    f.push(SERVER_CONTROL, &settings_frame(&[]), false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_FRAME_UNEXPECTED);

    // settings that are not allowed
    for pairs in [vec![(0x02u64, 0u64)], vec![(0x01, 1), (0x01, 2)]] {
        let mut c = Connection::new(Config::default());
        let mut f = Fake::new();
        c.process(&mut f).unwrap();
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(&settings_frame(&pairs));
        f.push(SERVER_CONTROL, &bytes, false);
        c.process(&mut f).unwrap_err();
        lost(&f, &c, code::H3_SETTINGS_ERROR);
    }
}

#[test]
fn the_servers_settings_are_what_the_client_keeps_to() {
    let (mut c, mut f) = started_with(Config::default(), &[(0x01, 2048), (0x07, 5), (0x06, 200), (0x21, 9)]);
    assert_eq!(c.peer_settings().copied(), Some(PeerSettings { qpack_max_table_capacity: 2048, qpack_blocked_streams: 5, max_field_section_size: Some(200) }));
    // a request whose header list is over what the server takes is not sent
    let big = vec![("x-long".to_string(), "v".repeat(300))];
    let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &big, secret: &[] };
    assert!(matches!(c.open_stream(&mut f, &r, true), Err(OpenError::Invalid(_))));
    // (and no stream was opened for it)
    assert_eq!(f.opened[0], 0);
    let small = vec![];
    let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &small, secret: &[] };
    assert!(c.open_stream(&mut f, &r, true).is_ok());
    // the limit is on a size that is the sum of the lengths of names and values and 32 for each field: 177 for this one, which is let
    // through at that and not at one less
    for (limit, ok) in [(177u64, true), (176, false)] {
        let (mut c, mut f) = started_with(Config::default(), &[(0x06, limit)]);
        assert_eq!(c.open_stream(&mut f, &r, true).is_ok(), ok, "a limit of {limit}");
    }
}

#[test]
fn a_stream_of_a_type_that_is_not_known_is_turned_away() {
    let (mut c, mut f) = started();
    f.push(15, &[0x40, 0x21, 1, 2, 3], false);
    c.process(&mut f).unwrap();
    assert_eq!(f.stopped_by_us.get(&15), Some(&code::H3_STREAM_CREATION_ERROR));
    assert!(f.closed.is_none());
    // what still comes is thrown away: not read as the start of another stream, whatever it is
    f.push(15, &[0x00, 0x04, 0x00, 0x03], false);
    c.process(&mut f).unwrap();
    assert!(c.usable());
    f.push(15, &[], true);
    c.process(&mut f).unwrap();
    assert!(c.ignored.is_empty());
    c.assert_books();
}

#[test]
fn a_stream_that_says_nothing_of_what_it_is_costs_nothing() {
    let (mut c, mut f) = started();
    // the type is two bytes long, and only one comes; then the stream ends
    f.push(15, &[0x40], false);
    c.process(&mut f).unwrap();
    f.push(15, &[], true);
    c.process(&mut f).unwrap();
    assert!(c.usable());
    assert!(c.uni.get(&15).is_none());
    // a stream with a type in two pieces
    f.push(19, &[0x40], false);
    c.process(&mut f).unwrap();
    f.push(19, &[0x21], false);
    c.process(&mut f).unwrap();
    assert_eq!(f.stopped_by_us.get(&19), Some(&code::H3_STREAM_CREATION_ERROR));
}

#[test]
fn a_bidirectional_stream_of_the_server_ends_the_connection() {
    let (mut c, mut f) = started();
    f.push(1, &[0x01], false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_STREAM_CREATION_ERROR);
}

#[test]
fn a_stream_that_ends_inside_a_frame_ends_the_connection() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    let bytes = response(200, &[], b"body");
    f.push(id, &bytes[..bytes.len() - 2], true);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_FRAME_ERROR);
}

#[test]
fn a_field_section_over_the_limit_loses_the_stream_not_the_connection() {
    let cfg = Config { max_header_list: 200, ..Config::default() };
    let (mut c, mut f) = started_with(cfg, &[]);
    let id = get(&mut c, &mut f);
    // the frame is longer than the limit: it is refused as soon as its length is known
    let mut bytes = vec![];
    put_frame_header(&mut bytes, frame::ty::HEADERS, 5000);
    f.push(id, &bytes, false);
    c.process(&mut f).unwrap();
    let ev = events(&mut c, id);
    assert_eq!(failure(&ev[0]).code, code::H3_EXCESSIVE_LOAD);
    assert!(c.usable());
    // a section that is small as sent and large as a list (it repeats a long static entry): the decoder says so
    let id = get(&mut c, &mut f);
    let mut fields = vec![(":status", "200")];
    let many: Vec<(&str, &str)> = (0..20).map(|_| ("content-type", "application/x-www-form-urlencoded")).collect();
    fields.extend(many);
    let mut bytes = vec![];
    put_headers(&mut bytes, &fields_block(&fields));
    f.push(id, &bytes, false);
    c.process(&mut f).unwrap();
    assert_eq!(failure(&events(&mut c, id)[0]).code, code::H3_EXCESSIVE_LOAD);
    assert!(f.closed.is_none());
}

// ---------------------------------------------------------------------------------------------------- going away

#[test]
fn goaway_ends_new_requests_and_fails_the_ones_that_were_not_taken() {
    let (mut c, mut f) = started();
    let a = get(&mut c, &mut f);
    let b = get(&mut c, &mut f);
    let d = get(&mut c, &mut f);
    assert_eq!((a, b, d), (0, 4, 8));
    let mut bytes = vec![];
    put_frame_header(&mut bytes, frame::ty::GOAWAY, 1);
    bytes.push(4);
    f.push(SERVER_CONTROL, &bytes, false);
    c.process(&mut f).unwrap();
    assert!(!c.usable());
    assert!(c.error().is_none(), "the connection is not lost: what was taken goes on");
    // stream 0 goes on; 4 and 8 were not taken, and may be sent again
    f.push(a, &response(200, &[], b"ok"), true);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, a).last(), Some(&StreamEvent::End));
    for id in [b, d] {
        let ev = events(&mut c, id);
        let e = failure(&ev[0]);
        assert_eq!((e.code, e.retry_safe), (code::H3_REQUEST_REJECTED, true), "stream {id}");
        assert_eq!(f.stopped_by_us.get(&id), Some(&code::H3_REQUEST_REJECTED));
    }
    let headers = vec![];
    let r = Request { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    assert_eq!(c.open_stream(&mut f, &r, true), Err(OpenError::Unavailable));
}

#[test]
fn goaway_may_only_go_down_and_must_name_a_request_stream() {
    let goaway = |id: u64| {
        let mut bytes = vec![];
        let mut payload = vec![];
        wire::put_varint(&mut payload, id);
        put_frame_header(&mut bytes, frame::ty::GOAWAY, payload.len() as u64);
        bytes.extend_from_slice(&payload);
        bytes
    };
    let (mut c, mut f) = started();
    f.push(SERVER_CONTROL, &goaway(100), false);
    f.push(SERVER_CONTROL, &goaway(100), false);
    f.push(SERVER_CONTROL, &goaway(40), false);
    c.process(&mut f).unwrap();
    assert!(c.error().is_none());
    f.push(SERVER_CONTROL, &goaway(44), false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_ID_ERROR);
    // (a number that is not a client's bidirectional stream)
    let (mut c, mut f) = started();
    f.push(SERVER_CONTROL, &goaway(6), false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_ID_ERROR);
    // and a cancelled push, which was never allowed
    let (mut c, mut f) = started();
    let mut bytes = vec![];
    put_frame_header(&mut bytes, frame::ty::CANCEL_PUSH, 1);
    bytes.push(0);
    f.push(SERVER_CONTROL, &bytes, false);
    c.process(&mut f).unwrap_err();
    lost(&f, &c, code::H3_ID_ERROR);
}

#[test]
fn the_server_stopping_our_request_is_not_the_end_of_its_response() {
    let (mut c, mut f) = started();
    let headers = vec![];
    let r = Request { method: "POST", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    let id = c.open_stream(&mut f, &r, false).unwrap();
    f.events.push_back(TransportEvent::Stopped(id, code::H3_NO_ERROR));
    f.push(id, &response(413, &[], b"too big"), true);
    c.process(&mut f).unwrap();
    // the application learns when it sends more
    let e = c.send_data(&mut f, id, b"more", false).unwrap_err();
    assert_eq!(e.code, code::H3_NO_ERROR);
    assert!(!e.retry_safe);
    assert_eq!(c.send_capacity(id), 0);
    // and the response is read all the same
    let ev = events(&mut c, id);
    assert_eq!(status_of(&ev[0]), 413);
    assert_eq!(ev.last(), Some(&StreamEvent::End));
}

#[test]
fn when_the_transport_is_gone_every_unfinished_stream_fails() {
    let (mut c, mut f) = started();
    let a = get(&mut c, &mut f);
    let b = get(&mut c, &mut f);
    f.push(a, &response(200, &[], b"all"), true);
    c.process(&mut f).unwrap();
    c.transport_closed(code::H3_NO_ERROR, "the idle timeout");
    // the finished one is read to its end; the other fails
    assert_eq!(events(&mut c, a).last(), Some(&StreamEvent::End));
    let ev = events(&mut c, b);
    assert_eq!(failure(&ev[0]).reason, "the idle timeout");
    assert!(!c.usable());
    assert_eq!(c.process(&mut f).unwrap_err().local, false);
}

#[test]
fn a_released_stream_that_is_done_costs_nothing_more() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    f.push(id, &response(200, &[], b"all"), true);
    c.process(&mut f).unwrap();
    assert_eq!(events(&mut c, id).last(), Some(&StreamEvent::End));
    c.release_stream(&mut f, id);
    assert_eq!(c.active_streams(), 0);
    assert!(f.stopped_by_us.is_empty(), "nothing is cancelled that was complete");
    assert_eq!(f.sent[&id].reset, None);
    // (and what comes for a stream that is gone is not looked at)
    f.push(id, &[0, 1, 2], false);
    c.process(&mut f).unwrap();
    assert!(c.usable());
    c.assert_books();
}

#[test]
fn a_released_stream_that_is_not_done_is_cancelled_both_ways() {
    let (mut c, mut f) = started();
    let headers = vec![];
    let r = Request { method: "POST", scheme: "https", authority: "example.com", path: "/", headers: &headers, secret: &[] };
    let id = c.open_stream(&mut f, &r, false).unwrap();
    f.push(id, &response(200, &[], b"part"), false);
    c.process(&mut f).unwrap();
    c.release_stream(&mut f, id);
    assert_eq!(f.stopped_by_us.get(&id), Some(&code::H3_REQUEST_CANCELLED));
    assert_eq!(f.sent[&id].reset, Some(code::H3_REQUEST_CANCELLED));
    assert_eq!(c.active_streams(), 0);
}

#[test]
fn the_application_closing_the_connection_is_not_an_error_code() {
    let (mut c, mut f) = started();
    let id = get(&mut c, &mut f);
    c.close(&mut f);
    assert_eq!(f.closed_with(), Some(code::H3_NO_ERROR));
    assert_eq!(failure(&events(&mut c, id)[0]).code, code::H3_NO_ERROR);
    assert!(!c.usable());
}

#[test]
fn everything_a_server_may_say_leaves_the_books_balanced() {
    // random streams from the server, in random pieces: the connection may end, and then it does so with a code of the RFC, but no panic
    // and no unbounded holding
    use super::super::qpack::harness::{Choose, Xorshift};
    let mut rng = Xorshift(0x1234_5678_9abc_def1);
    let mut ended = 0;
    for _ in 0..300 {
        let (mut c, mut f) = started_with(Config { body_buffer: 5000, ..Config::default() }, &[(0x01, 4096), (0x07, 16)]);
        let ids: Vec<u64> = (0..3).map(|_| get(&mut c, &mut f)).collect();
        for _ in 0..40 {
            let id = [SERVER_CONTROL, SERVER_QPACK_ENCODER, ids[rng.below(3)], ids[rng.below(3)]][rng.below(4)];
            let n = rng.below(60);
            let bytes: Vec<u8> = (0..n).map(|_| [0u8, 1, 2, 3, 4, 0x80, 0xc0, 0x40, 0x21, 7, 0xff][rng.below(11)]).collect();
            f.push(id, &bytes, rng.below(20) == 0);
            let _ = c.process(&mut f);
            c.assert_books();
            for &s in &ids {
                let mut buf = [0u8; 100];
                let _ = c.poll_stream(s, &mut buf);
            }
        }
        if c.error().is_some() {
            ended += 1;
            assert!(f.closed_with().is_some());
        }
    }
    assert!(ended > 100, "{ended}");
}

#[test]
fn whatever_a_script_makes_of_a_well_made_server_the_connection_is_not_lost() {
    use super::harness::exchange;
    use crate::http::h3::qpack::harness::Xorshift;
    let (mut responses, mut waited, mut inserted) = (0, 0, 0);
    for seed in 1..=1500u64 {
        let s = exchange(&mut Xorshift(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1), 150, false);
        assert_eq!(s.lost, 0);
        responses += s.responses;
        waited += s.waited;
        inserted += s.inserted;
    }
    assert!(responses > 3000, "{responses} responses were read");
    assert!(waited > 100, "{waited} steps with a stream waiting for the table");
    assert!(inserted > 500, "{inserted} entries in the tables of the servers");
}

#[test]
fn whatever_a_script_makes_of_a_bad_server_the_books_balance() {
    use super::harness::exchange;
    use crate::http::h3::qpack::harness::Xorshift;
    let (mut lost, mut responses) = (0, 0);
    for seed in 1..=1500u64 {
        let s = exchange(&mut Xorshift(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1), 150, true);
        lost += s.lost;
        responses += s.responses;
    }
    assert!(lost > 300, "{lost} connections were lost");
    assert!(responses > 100, "{responses} responses were read");
}

/// A long run of both kinds of script, for looking for what the short ones do not reach: `H3_SWEEP=200000 cargo test --lib h3::connection::tests::sweep -- --ignored`.
#[test]
#[ignore]
fn sweep() {
    use super::harness::exchange;
    use crate::http::h3::qpack::harness::Xorshift;
    let n: u64 = std::env::var("H3_SWEEP").ok().and_then(|v| v.parse().ok()).unwrap_or(20_000);
    let (mut responses, mut lost) = (0, 0);
    for seed in 1..=n {
        let run = |garbage: bool, mul: u64| {
            std::panic::catch_unwind(|| exchange(&mut Xorshift(seed.wrapping_mul(mul) | 1), 300, garbage)).unwrap_or_else(|_| panic!("the failure above is of seed {seed} (garbage: {garbage})"))
        };
        let s = run(false, 0x9e37_79b9_7f4a_7c15);
        assert_eq!(s.lost, 0, "seed {seed}");
        responses += s.responses;
        lost += run(true, 0xd1b5_4a32_d192_ed03).lost;
    }
    eprintln!("{responses} responses, {lost} connections lost");
}

/// Runs the script in the file named by `H3_REPLAY` (an input of the fuzzer's `h3_connection`).
#[test]
#[ignore]
fn replay() {
    let path = std::env::var("H3_REPLAY").expect("H3_REPLAY names a file");
    let data = std::fs::read(path).unwrap();
    let (sel, rest) = data.split_first().unwrap();
    struct Bytes<'a>(&'a [u8], usize);
    impl super::super::qpack::harness::Choose for Bytes<'_> {
        fn below(&mut self, n: usize) -> usize {
            let mut next = || {
                let b = self.0.get(self.1).copied().unwrap_or(0);
                self.1 += 1;
                usize::from(b)
            };
            if n <= 1 {
                0
            } else if n <= 256 {
                next() % n
            } else {
                (next() << 8 | next()) % n
            }
        }
        fn exhausted(&self) -> bool {
            self.1 >= self.0.len()
        }
    }
    super::harness::exchange(&mut Bytes(rest, 0), 300, sel & 1 == 1);
}
