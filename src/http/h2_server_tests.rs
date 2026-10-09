//! Tests of the HTTP/2 test server: against the crate's own HTTP/2 client state machine in memory (which tests both),
//! against hand-made frames (what the server notices and refuses), and over TCP (the driver's timers).

use super::h2::connection::{Config, Connection, ConnectionError, Head, OpenError, Request as ClientRequest, StreamEvent};
use super::h2::frame::{self, flag, kind, setting, ErrorCode, Header, PREFACE};
use super::h2::hpack::{Encoder, FieldRef};
use super::h2_server::{response, serve, Action, ConnError, Ended, Event, Request, ServerConn, Settings, Step};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
}

// ------------------------------------------------------------------------------------------------ in memory

/// The client state machine and the server state machine, with the bytes carried between them.
struct Link {
    client: Connection,
    server: ServerConn,
    partial: HashMap<u32, Request>,
    done: Vec<Request>,
    resets: Vec<(u32, u32)>,
    goaways: Vec<u32>,
    client_error: Option<ConnectionError>,
    server_error: Option<ConnError>,
}

/// What a client stream delivered.
#[derive(Debug, Default)]
struct Got {
    head: Option<Head>,
    body: Vec<u8>,
    trailers: Option<Vec<(String, String)>>,
    ended: bool,
    failed: Option<super::h2::connection::StreamError>,
}

impl Link {
    fn new(settings: Settings, config: Config) -> Link {
        Link {
            client: Connection::new(config),
            server: ServerConn::new(settings),
            partial: HashMap::new(),
            done: Vec::new(),
            resets: Vec::new(),
            goaways: Vec::new(),
            client_error: None,
            server_error: None,
        }
    }

    fn default() -> Link {
        Link::new(Settings::default(), Config::default())
    }

    /// Carries bytes both ways until neither side has anything more to say.
    fn run(&mut self) {
        for _ in 0..100_000 {
            let mut moved = false;
            if self.client.wants_write() {
                let bytes = self.client.output().to_vec();
                self.client.consume_output(bytes.len());
                self.server.receive(&bytes);
                moved = true;
            }
            match self.server.process() {
                Ok(events) => {
                    for e in events {
                        self.on_event(e);
                    }
                }
                Err(e) => self.server_error = Some(e),
            }
            self.server.pump_data();
            if self.server.wants_write() {
                let bytes = self.server.output().to_vec();
                self.server.consume_output(bytes.len());
                self.client.receive(&bytes);
                moved = true;
            }
            if let Err(e) = self.client.process() {
                self.client_error = Some(e);
            }
            if !moved && !self.client.wants_write() && !self.server.wants_write() {
                return;
            }
        }
        panic!("the link does not settle");
    }

    fn on_event(&mut self, e: Event) {
        let finished = match e {
            Event::Headers { stream, fields, end_stream } => {
                match self.partial.get_mut(&stream) {
                    Some(r) => r.trailers = fields,
                    None => {
                        let mut r = Request { stream, ..Request::default() };
                        for (n, v) in fields {
                            match n.as_str() {
                                ":method" => r.method = v,
                                ":scheme" => r.scheme = v,
                                ":authority" => r.authority = v,
                                ":path" => r.path = v,
                                _ => r.headers.push((n, v)),
                            }
                        }
                        self.partial.insert(stream, r);
                    }
                }
                end_stream.then_some(stream)
            }
            Event::Data { stream, data, end_stream } => {
                self.partial.get_mut(&stream).expect("data for a request").body.extend_from_slice(&data);
                end_stream.then_some(stream)
            }
            Event::Reset { stream, code } => {
                self.partial.remove(&stream);
                self.resets.push((stream, code));
                None
            }
            Event::GoAway { code } => {
                self.goaways.push(code);
                None
            }
        };
        if let Some(s) = finished {
            self.done.push(self.partial.remove(&s).unwrap());
        }
    }

    fn open(&mut self, method: &str, path: &str, headers: &[(&str, &str)], end_stream: bool) -> u32 {
        let headers = pairs(headers);
        self.client.open_stream(&ClientRequest { method, scheme: "https", authority: "example.com", path, headers: &headers, secret: &[] }, end_stream).unwrap()
    }

    fn reply(&mut self, stream: u32, steps: Vec<Step>) {
        for step in steps {
            self.server.act(stream, step.action);
        }
    }

    /// Reads all the stream has now, with a buffer of `size`.
    fn read(&mut self, id: u32, size: usize) -> Got {
        let mut got = Got::default();
        let mut buf = vec![0u8; size];
        loop {
            match self.client.poll_stream(id, &mut buf) {
                StreamEvent::Pending => return got,
                StreamEvent::Head(h) => got.head = Some(h),
                StreamEvent::Data(n) => got.body.extend_from_slice(&buf[..n]),
                StreamEvent::Trailers(t) => got.trailers = Some(t),
                StreamEvent::End => {
                    got.ended = true;
                    return got;
                }
                StreamEvent::Failed(e) => {
                    got.failed = Some(e);
                    return got;
                }
            }
        }
    }

    /// Reads the stream to its end, running the link between reads (the client's credit goes back as it reads).
    fn read_to_end(&mut self, id: u32, size: usize) -> Got {
        let mut all = Got::default();
        for _ in 0..1_000_000 {
            self.run();
            let g = self.read(id, size);
            all.head = g.head.or(all.head);
            all.body.extend_from_slice(&g.body);
            all.trailers = g.trailers.or(all.trailers);
            if g.ended || g.failed.is_some() {
                all.ended = g.ended;
                all.failed = g.failed;
                return all;
            }
        }
        panic!("the stream does not end");
    }

    /// Sends a request body as the windows allow, running the link in between.
    fn upload(&mut self, id: u32, body: &[u8]) {
        let mut sent = 0;
        let mut stalls = 0;
        while sent < body.len() {
            let n = self.client.send_data(id, &body[sent..], true).unwrap();
            sent += n;
            self.run();
            stalls = if n == 0 { stalls + 1 } else { 0 };
            assert!(stalls < 100, "the upload is stuck at {sent} of {}", body.len());
        }
    }
}

fn client_get(link: &mut Link, path: &str) -> u32 {
    link.open("GET", path, &[], true)
}

#[test]
fn a_request_arrives_as_the_client_wrote_it_and_the_answer_comes_back() {
    let mut link = Link::default();
    let id = link.open("GET", "/hello?x=1", &[("User-Agent", "tiny"), ("Accept", "*/*"), ("X-Mixed", "Case")], true);
    link.run();
    assert_eq!(link.done.len(), 1);
    let r = &link.done[0];
    assert_eq!((r.method.as_str(), r.scheme.as_str(), r.authority.as_str(), r.path.as_str()), ("GET", "https", "example.com", "/hello?x=1"));
    assert_eq!(r.headers, pairs(&[("user-agent", "tiny"), ("accept", "*/*"), ("x-mixed", "Case")]));
    assert!(r.body.is_empty());
    assert_eq!(link.server.complaints(), &[] as &[String], "the client did nothing the server objects to");
    link.reply(id, response(200, &[("content-type", "text/plain")], b"hello"));
    let got = link.read_to_end(id, 100);
    assert_eq!(got.head.unwrap().headers, pairs(&[("content-type", "text/plain")]));
    assert_eq!(got.body, b"hello");
    assert!(got.ended);
    assert!(link.client_error.is_none() && link.server_error.is_none());
}

#[test]
fn a_response_with_no_body_is_a_head_that_ends_the_stream() {
    let mut link = Link::default();
    let id = link.open("HEAD", "/", &[], true);
    link.run();
    assert!(link.server.is_head_request(id));
    link.reply(id, response(200, &[("content-length", "123456")], b""));
    let got = link.read_to_end(id, 10);
    assert_eq!(got.head.unwrap().status, 200);
    assert!(got.ended && got.body.is_empty() && got.failed.is_none());
}

#[test]
fn a_request_body_larger_than_the_windows_is_sent_as_they_open() {
    let mut link = Link::default();
    let body: Vec<u8> = (0..5_000_000u32).map(|i| (i % 251) as u8).collect();
    let id = link.open("POST", "/up", &[("content-length", &body.len().to_string())], false);
    link.upload(id, &body);
    assert_eq!(link.done.len(), 1);
    assert_eq!(link.done[0].body.len(), body.len());
    assert!(link.done[0].body == body, "the body is what was sent");
    assert_eq!(link.server.complaints(), &[] as &[String]);
    link.reply(id, response(201, &[], b"stored"));
    assert_eq!(link.read_to_end(id, 100).body, b"stored");
}

#[test]
fn a_response_body_larger_than_the_windows_is_sent_as_the_client_reads() {
    let mut link = Link::default();
    let id = client_get(&mut link, "/big");
    link.run();
    let body: Vec<u8> = (0..7_000_000u32).map(|i| (i % 253) as u8).collect();
    link.reply(id, response(200, &[], &body));
    // with a small buffer and the link run only when the buffer has been emptied: the server is held to the
    // client's windows, and never gets ahead of what is read
    let got = link.read_to_end(id, 20_000);
    assert!(got.body == body);
    assert!(got.ended);
    assert!(link.client_error.is_none());
}

#[test]
fn a_server_that_has_not_been_given_window_sends_no_more() {
    // a stream window of 100 bytes: the server must stop after 100 until the client reads
    let config = Config { stream_window: 100, connection_window: 65_535, max_header_list: 64 << 10 };
    let mut link = Link::new(Settings::default(), config);
    let id = client_get(&mut link, "/");
    link.run();
    link.reply(id, response(200, &[], &[9u8; 1000]));
    link.run();
    // 100 bytes are in the client's hands and no more
    let got = link.read(id, 1 << 20);
    assert_eq!(got.body.len(), 100);
    let got = link.read_to_end(id, 1 << 20);
    assert_eq!(got.body.len(), 900);
    assert!(got.ended);
}

#[test]
fn many_requests_at_once_each_get_their_own_answer() {
    let mut link = Link::default();
    let ids: Vec<u32> = (0..60).map(|i| link.open("GET", &format!("/n/{i}"), &[], true)).collect();
    link.run();
    assert_eq!(link.done.len(), 60);
    // answered in the reverse order, in pieces, interleaved
    for (i, &id) in ids.iter().enumerate().rev() {
        link.reply(id, response(200, &[("x-i", &i.to_string())], format!("answer {i}").as_bytes()));
    }
    link.run();
    for (i, &id) in ids.iter().enumerate() {
        let got = link.read(id, 100);
        assert_eq!(got.body, format!("answer {i}").as_bytes());
        assert_eq!(got.head.unwrap().headers, pairs(&[("x-i", &i.to_string())]));
        assert!(got.ended);
    }
    assert_eq!(link.server.complaints(), &[] as &[String]);
}

#[test]
fn streams_past_the_servers_limit_are_refused_and_may_be_tried_again() {
    let settings = Settings { max_concurrent_streams: 2, ..Settings::default() };
    let mut link = Link::new(settings, Config::default());
    // before the server's SETTINGS have arrived the client does not know the limit
    let ids: Vec<u32> = (0..4).map(|_| client_get(&mut link, "/")).collect();
    link.run();
    assert_eq!(link.done.len(), 2, "two were taken");
    for &id in &ids[2..] {
        let got = link.read(id, 10);
        let failed = got.failed.expect("refused");
        assert_eq!(failed.code, ErrorCode::REFUSED_STREAM);
        assert!(failed.retry_safe);
    }
    // now the client knows
    assert!(!link.client.can_open_stream());
    assert_eq!(link.client.open_stream(&ClientRequest { method: "GET", scheme: "https", authority: "a", path: "/", headers: &[], secret: &[] }, true), Err(OpenError::Full));
    link.reply(ids[0], response(200, &[], b""));
    link.run();
    assert!(link.client.can_open_stream());
    let again = client_get(&mut link, "/again");
    link.run();
    assert_eq!(link.done.last().unwrap().path, "/again");
    let _ = again;
    assert_eq!(link.server.complaints(), &[] as &[String], "a refusal is not a complaint");
}

#[test]
fn trailers_and_interim_responses_come_through() {
    let mut link = Link::default();
    let id = client_get(&mut link, "/");
    link.run();
    link.reply(
        id,
        vec![
            Step::now(Action::Interim { status: 103, headers: pairs(&[("link", "</x>; rel=preload")]) }),
            Step::now(Action::Head { status: 200, headers: pairs(&[("trailer", "x-sum")]), end: false }),
            Step::now(Action::Data(b"some body".to_vec())),
            Step::now(Action::Trailers(pairs(&[("x-sum", "9")]))),
        ],
    );
    let got = link.read_to_end(id, 4);
    assert_eq!(got.head.unwrap().status, 200);
    assert_eq!(got.body, b"some body");
    assert_eq!(got.trailers, Some(pairs(&[("x-sum", "9")])));
    assert!(got.ended);
}

#[test]
fn a_reset_and_a_goaway_reach_the_client() {
    let mut link = Link::default();
    let a = client_get(&mut link, "/a");
    let b = client_get(&mut link, "/b");
    let c = client_get(&mut link, "/c");
    link.run();
    link.reply(a, vec![Step::now(Action::Head { status: 200, headers: vec![], end: false }), Step::now(Action::Data(b"partly".to_vec())), Step::now(Action::Reset(ErrorCode::INTERNAL_ERROR.0))]);
    link.run();
    let got = link.read(a, 100);
    assert_eq!(got.failed.unwrap().code, ErrorCode::INTERNAL_ERROR);
    // a graceful GOAWAY after the second stream: the third was not taken
    link.server.act(0, Action::GoAway { code: 0, last_stream: Some(b) });
    link.run();
    assert!(!link.client.usable());
    let failed = link.read(c, 10).failed.unwrap();
    assert!(failed.retry_safe);
    link.reply(b, response(200, &[], b"fine"));
    let got = link.read_to_end(b, 10);
    assert_eq!(got.body, b"fine");
    assert!(got.ended);
}

#[test]
fn a_push_promise_is_refused_by_the_client() {
    let mut link = Link::default();
    let id = client_get(&mut link, "/");
    link.run();
    link.reply(id, vec![Step::now(Action::PushPromise { promised: 2, headers: pairs(&[(":method", "GET"), (":scheme", "https"), (":authority", "example.com"), (":path", "/pushed")]) })]);
    link.run();
    let e = link.client_error.expect("the client lost the connection");
    assert_eq!(e.code, ErrorCode::PROTOCOL_ERROR);
    assert_eq!(link.goaways, vec![ErrorCode::PROTOCOL_ERROR.0], "and said why");
}

#[test]
fn pings_and_settings_from_the_server_are_answered() {
    let mut link = Link::default();
    let id = client_get(&mut link, "/");
    link.run();
    link.reply(id, vec![Step::now(Action::Ping), Step::now(Action::Settings(vec![(setting::MAX_CONCURRENT_STREAMS, 1), (setting::INITIAL_WINDOW_SIZE, 70_000)]))]);
    link.run();
    assert!(link.client_error.is_none() && link.server_error.is_none());
    // the new limit holds: one stream is open
    assert!(!link.client.can_open_stream());
    assert_eq!(link.server.complaints(), &[] as &[String]);
}

#[test]
fn raw_bytes_the_client_cannot_make_sense_of_end_the_connection() {
    let mut link = Link::default();
    let id = client_get(&mut link, "/");
    link.run();
    link.reply(id, vec![Step::now(Action::Raw(vec![0xff; 9]))]);
    link.run();
    assert!(link.client_error.is_some());
}

#[test]
fn an_upload_waits_for_the_servers_window() {
    // a server that gives no credit: the client may send what the initial windows allow and then must wait
    let settings = Settings { initial_window: 100_000, connection_window: 65_535, auto_credit: false, ..Settings::default() };
    let mut link = Link::new(settings, Config::default());
    let id = link.open("POST", "/up", &[], false);
    link.run();
    let body = vec![7u8; 500_000];
    assert_eq!(link.client.send_capacity(id), 65_535, "the connection window is the smaller");
    let n = link.client.send_data(id, &body, true).unwrap();
    assert_eq!(n, 65_535);
    link.run();
    assert_eq!(link.client.send_capacity(id), 0);
    assert_eq!(link.client.send_data(id, &body[n..], true).unwrap(), 0);
    // the server opens the connection window; the stream's is 100000 - 65535 = 34465 more
    link.server.act(0, Action::WindowUpdate(200_000));
    link.run();
    assert_eq!(link.client.send_capacity(id), 34_465);
    link.server.act(id, Action::WindowUpdate(400_000));
    link.run();
    assert_eq!(link.client.send_capacity(id), 200_000, "now the connection window is the smaller");
    let sent = link.client.send_data(id, &body[n..], true).unwrap();
    assert_eq!(sent, 200_000);
    link.server.act(0, Action::WindowUpdate(300_000));
    link.run();
    let rest = link.client.send_data(id, &body[n + sent..], true).unwrap();
    assert_eq!(n + sent + rest, body.len());
    link.run();
    assert_eq!(link.done.len(), 1, "the whole request arrived");
    assert_eq!(link.done[0].body.len(), body.len());
    assert!(link.server_error.is_none());
}

// ------------------------------------------------------------------------------------------------ what the server refuses

fn good_head() -> Vec<(&'static str, &'static str)> {
    vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "example.com")]
}

/// A server that has been through the preface and the client's SETTINGS.
fn started() -> ServerConn {
    let mut s = ServerConn::new(Settings::default());
    s.receive(PREFACE);
    let mut settings = Vec::new();
    frame::write_settings(&mut settings, &[]);
    s.receive(&settings);
    s.process().unwrap();
    let n = s.output().len();
    s.consume_output(n);
    s
}

fn raw(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    Header { length: payload.len() as u32, kind, flags, stream }.write(&mut out);
    out.extend_from_slice(payload);
    out
}

fn block(fields: &[(&str, &str)]) -> Vec<u8> {
    let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
    let mut out = Vec::new();
    Encoder::new().encode(&refs, &mut out);
    out
}

/// What the server wrote: (kind, stream, the first four bytes after the 8 of a GOAWAY / the number of RST_STREAM).
fn written(s: &mut ServerConn) -> Vec<(u8, u32, u32)> {
    let out = s.output().to_vec();
    s.consume_output(out.len());
    let mut frames = Vec::new();
    let mut rest = &out[..];
    while rest.len() >= 9 {
        let h = Header::parse(rest[..9].try_into().unwrap());
        let payload = &rest[9..9 + h.length as usize];
        let number = match h.kind {
            kind::RST_STREAM => u32::from_be_bytes(payload[..4].try_into().unwrap()),
            kind::GOAWAY => u32::from_be_bytes(payload[4..8].try_into().unwrap()),
            _ => 0,
        };
        frames.push((h.kind, h.stream, number));
        rest = &rest[9 + h.length as usize..];
    }
    frames
}

#[test]
fn a_good_request_is_let_through() {
    let mut s = started();
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block(&good_head())));
    let events = s.process().unwrap();
    assert!(matches!(&events[..], [Event::Headers { stream: 1, end_stream: true, .. }]));
    assert!(s.complaints().is_empty());
    // a Host header will do for the authority
    let mut s = started();
    let fields = [(":method", "GET"), (":scheme", "https"), (":path", "/"), ("host", "example.com"), ("te", "trailers"), ("content-length", "0")];
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block(&fields)));
    assert_eq!(s.process().unwrap().len(), 1);
}

#[test]
fn a_goaway_or_a_reset_comes_after_the_data_written_before_it() {
    let head = |end| Step::now(Action::Head { status: 200, headers: vec![], end });
    let kinds = |s: &mut ServerConn| written(s).into_iter().map(|(k, id, _)| (k, id)).collect::<Vec<_>>();
    // the response, then GOAWAY: the data (and its END_STREAM) are on the wire before the GOAWAY
    let mut s = started();
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block(&good_head())));
    s.process().unwrap();
    for step in [head(false), Step::now(Action::Data(b"all of it".to_vec())), Step::now(Action::End), Step::now(Action::GoAway { code: 0, last_stream: None })] {
        s.act(1, step.action);
    }
    assert_eq!(kinds(&mut s), vec![(kind::HEADERS, 1), (kind::DATA, 1), (kind::GOAWAY, 0)]);
    // data and then a reset: the data goes first
    let mut s = started();
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block(&good_head())));
    s.process().unwrap();
    for step in [head(false), Step::now(Action::Data(b"part".to_vec())), Step::now(Action::Reset(2))] {
        s.act(1, step.action);
    }
    assert_eq!(kinds(&mut s), vec![(kind::HEADERS, 1), (kind::DATA, 1), (kind::RST_STREAM, 1)]);
    // data that the windows do not let through is dropped by the reset
    let mut s = started();
    let mut settings = Vec::new();
    frame::write_settings(&mut settings, &[(setting::INITIAL_WINDOW_SIZE, 0)]);
    s.receive(&settings);
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block(&good_head())));
    s.process().unwrap();
    s.consume_output(s.output().len());
    for step in [head(false), Step::now(Action::Data(b"stuck".to_vec())), Step::now(Action::Reset(8))] {
        s.act(1, step.action);
    }
    assert_eq!(kinds(&mut s), vec![(kind::HEADERS, 1), (kind::RST_STREAM, 1)]);
}

#[test]
fn a_malformed_request_loses_its_stream_and_nothing_more() {
    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("no :method", vec![(":scheme", "https"), (":path", "/"), (":authority", "a")]),
        ("no :scheme", vec![(":method", "GET"), (":path", "/"), (":authority", "a")]),
        ("no :path", vec![(":method", "GET"), (":scheme", "https"), (":authority", "a")]),
        ("an empty :path", vec![(":method", "GET"), (":scheme", "https"), (":path", ""), (":authority", "a")]),
        ("no authority", vec![(":method", "GET"), (":scheme", "https"), (":path", "/")]),
        ("a pseudo-header twice", vec![(":method", "GET"), (":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
        ("a response pseudo-header", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), (":status", "200")]),
        ("a pseudo-header after a field", vec![(":method", "GET"), (":scheme", "https"), ("x", "y"), (":path", "/"), (":authority", "a")]),
        ("a capital in a name", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("X-Upper", "1")]),
        ("Connection", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("connection", "close")]),
        ("Transfer-Encoding", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("transfer-encoding", "chunked")]),
        ("te: gzip", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("te", "gzip")]),
        ("a NUL in a value", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("x", "a\0b")]),
        ("a value with a space at the end", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("x", "a ")]),
        ("a Content-Length that is not a number", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("content-length", "abc")]),
    ];
    for (what, fields) in cases {
        let mut s = started();
        s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &block(&fields)));
        let events = s.process().unwrap_or_else(|e| panic!("{what}: lost the connection: {e:?}"));
        assert!(events.is_empty(), "{what}");
        assert_eq!(written(&mut s), vec![(kind::RST_STREAM, 1, ErrorCode::PROTOCOL_ERROR.0)], "{what}");
        assert_eq!(s.complaints().len(), 1, "{what}");
        // and the connection goes on
        s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 3, &block(&good_head())));
        // (a new encoder was used for the first block: the second is by a fresh one too, so no table is shared)
        assert!(s.process().is_ok(), "{what}");
    }
}

#[test]
fn what_is_wrong_with_the_connection_ends_it() {
    let head = |stream: u32, flags: u8| raw(kind::HEADERS, flags, stream, &block(&good_head()));
    let data = |stream: u32, n: usize| raw(kind::DATA, 0, stream, &vec![0u8; n]);
    let cases: Vec<(&str, Vec<u8>, ErrorCode)> = vec![
        ("HEADERS on an even stream", head(2, flag::END_HEADERS), ErrorCode::PROTOCOL_ERROR),
        ("a stream id that goes down", [head(5, flag::END_HEADERS | flag::END_STREAM), head(3, flag::END_HEADERS)].concat(), ErrorCode::PROTOCOL_ERROR),
        ("DATA on a stream never opened", data(1, 1), ErrorCode::PROTOCOL_ERROR),
        ("WINDOW_UPDATE on a stream never opened", raw(kind::WINDOW_UPDATE, 0, 9, &[0, 0, 0, 1]), ErrorCode::PROTOCOL_ERROR),
        ("RST_STREAM on a stream never opened", raw(kind::RST_STREAM, 0, 9, &[0; 4]), ErrorCode::PROTOCOL_ERROR),
        ("PUSH_PROMISE from a client", raw(kind::PUSH_PROMISE, flag::END_HEADERS, 1, &[0, 0, 0, 2, 0x88]), ErrorCode::PROTOCOL_ERROR),
        ("a frame over the size announced", raw(kind::DATA, 0, 1, &vec![0u8; 16_385]), ErrorCode::FRAME_SIZE_ERROR),
        ("a connection window past the limit", raw(kind::WINDOW_UPDATE, 0, 0, &[0x7f, 0xff, 0xff, 0xff]), ErrorCode::FLOW_CONTROL_ERROR),
        ("a HEADERS block that is not finished and then a PING", [raw(kind::HEADERS, 0, 1, &[0x82]), raw(kind::PING, 0, 0, &[0; 8])].concat(), ErrorCode::PROTOCOL_ERROR),
        ("CONTINUATION with no HEADERS", raw(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x82]), ErrorCode::PROTOCOL_ERROR),
        ("a header block that does not decode", raw(kind::HEADERS, flag::END_HEADERS, 1, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), ErrorCode::COMPRESSION_ERROR),
        ("SETTINGS_ENABLE_PUSH of 7", raw(kind::SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 7]), ErrorCode::PROTOCOL_ERROR),
        ("SETTINGS_MAX_FRAME_SIZE under the minimum", raw(kind::SETTINGS, 0, 0, &[0, 5, 0, 0, 0, 100]), ErrorCode::PROTOCOL_ERROR),
        ("an initial window over 2^31 - 1", raw(kind::SETTINGS, 0, 0, &[0, 4, 0x80, 0, 0, 0]), ErrorCode::FLOW_CONTROL_ERROR),
    ];
    for (what, bytes, code) in cases {
        let mut s = started();
        s.receive(&bytes);
        let e = s.process().expect_err(what);
        assert_eq!(e.code, code.0, "{what}: {}", e.reason);
        let out = written(&mut s);
        assert_eq!(out.last().map(|f| (f.0, f.2)), Some((kind::GOAWAY, code.0)), "{what}");
        assert!(!s.complaints().is_empty());
        assert!(s.process().is_err(), "a lost connection stays lost");
    }
}

#[test]
fn the_preface_and_the_first_frame_are_checked() {
    for bad in [&b"GET / HTTP/1.1\r\n\r\n"[..], b"\x00", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\x00"] {
        let mut s = ServerConn::new(Settings::default());
        s.receive(bad);
        assert!(s.process().is_err(), "{bad:?}");
    }
    // a preface that arrives in pieces
    let mut s = ServerConn::new(Settings::default());
    for b in PREFACE.iter() {
        s.receive(&[*b]);
        assert!(s.process().unwrap().is_empty());
    }
    // and then something other than SETTINGS
    s.receive(&raw(kind::PING, 0, 0, &[0; 8]));
    assert!(s.process().is_err());
    let mut s = ServerConn::new(Settings::default());
    s.receive(PREFACE);
    s.receive(&raw(kind::SETTINGS, flag::ACK, 0, &[]));
    assert!(s.process().is_err(), "an acknowledgement is not the client's SETTINGS");
}

#[test]
fn request_bodies_are_held_to_their_content_length_and_the_windows() {
    // more than it says
    let mut s = started();
    let fields = [(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "a"), ("content-length", "3")];
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &block(&fields)));
    s.receive(&raw(kind::DATA, 0, 1, b"abcd"));
    assert!(matches!(&s.process().unwrap()[..], [Event::Headers { .. }]));
    assert_eq!(written(&mut s).iter().filter(|f| f.0 == kind::RST_STREAM).count(), 1);
    // less
    let mut s = started();
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &block(&fields)));
    s.receive(&raw(kind::DATA, flag::END_STREAM, 1, b"ab"));
    s.process().unwrap();
    assert_eq!(written(&mut s).iter().filter(|f| f.0 == kind::RST_STREAM).count(), 1);
    // over the stream window (a window of 100)
    let mut s = ServerConn::new(Settings { initial_window: 100, ..Settings::default() });
    s.receive(PREFACE);
    s.receive(&raw(kind::SETTINGS, 0, 0, &[]));
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &block(&[(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "a")])));
    s.receive(&raw(kind::DATA, 0, 1, &[0; 101]));
    s.process().unwrap();
    assert!(written(&mut s).iter().any(|f| (f.0, f.1, f.2) == (kind::RST_STREAM, 1, ErrorCode::FLOW_CONTROL_ERROR.0)));
}

#[test]
fn request_data_is_given_credit_as_it_is_taken() {
    let mut s = ServerConn::new(Settings { initial_window: 1000, connection_window: 65_535, ..Settings::default() });
    s.receive(PREFACE);
    s.receive(&raw(kind::SETTINGS, 0, 0, &[]));
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &block(&[(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "a")])));
    s.process().unwrap();
    written(&mut s);
    s.receive(&raw(kind::DATA, 0, 1, &[0; 400]));
    s.process().unwrap();
    assert!(written(&mut s).is_empty(), "less than half");
    s.receive(&raw(kind::DATA, 0, 1, &[0; 200]));
    s.process().unwrap();
    // 600 of 1000 taken: the stream is given it back
    assert_eq!(written(&mut s), vec![(kind::WINDOW_UPDATE, 1, 0)]);
}

#[test]
fn a_client_that_sends_more_than_the_connection_window_loses_the_connection() {
    // (a server that gives credit as it goes is never overrun; one that does not is)
    let mut s = ServerConn::new(Settings { connection_window: 65_535, initial_window: 1 << 20, auto_credit: false, ..Settings::default() });
    s.receive(PREFACE);
    s.receive(&raw(kind::SETTINGS, 0, 0, &[]));
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &block(&[(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "a")])));
    for _ in 0..3 {
        s.receive(&raw(kind::DATA, 0, 1, &[0; 16_384]));
    }
    s.process().unwrap();
    s.receive(&raw(kind::DATA, 0, 1, &[0; 16_384]));
    let e = s.process().unwrap_err();
    assert_eq!(e.code, ErrorCode::FLOW_CONTROL_ERROR.0);
}

#[test]
fn a_request_may_have_trailers_and_they_are_checked() {
    let post = [(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "a")];
    let mut enc = Encoder::new();
    let mut encode = |fields: &[(&str, &str)]| {
        let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
        let mut out = Vec::new();
        enc.encode(&refs, &mut out);
        out
    };
    // good trailers end the request
    let mut s = started();
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &encode(&post)));
    s.receive(&raw(kind::DATA, 0, 1, b"body"));
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &encode(&[("x-sum", "4")])));
    let events = s.process().unwrap();
    assert!(matches!(&events[..], [Event::Headers { .. }, Event::Data { .. }, Event::Headers { stream: 1, end_stream: true, .. }]));
    assert!(s.complaints().is_empty());
    // trailers that do not end the stream, with a pseudo-header, with a capital; and HEADERS after the end
    for (what, flags, fields) in [
        ("trailers without the end", flag::END_HEADERS, vec![("x", "1")]),
        ("a pseudo-header", flag::END_HEADERS | flag::END_STREAM, vec![(":path", "/")]),
        ("a capital", flag::END_HEADERS | flag::END_STREAM, vec![("X", "1")]),
    ] {
        let mut s = started();
        let mut enc = Encoder::new();
        let refs = |fields: &[(&str, &str)], enc: &mut Encoder| {
            let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
            let mut out = Vec::new();
            enc.encode(&refs, &mut out);
            out
        };
        s.receive(&raw(kind::HEADERS, flag::END_HEADERS, 1, &refs(&post, &mut enc)));
        s.receive(&raw(kind::HEADERS, flags, 1, &refs(&fields, &mut enc)));
        s.process().unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert!(written(&mut s).iter().any(|f| f.0 == kind::RST_STREAM && f.1 == 1), "{what}");
    }
    let mut s = started();
    let mut enc = Encoder::new();
    let mut with = |fields: &[(&str, &str)]| {
        let refs: Vec<FieldRef<'_>> = fields.iter().map(|(n, v)| FieldRef { name: n.as_bytes(), value: v.as_bytes(), sensitive: false }).collect();
        let mut out = Vec::new();
        enc.encode(&refs, &mut out);
        out
    };
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &with(&post)));
    s.receive(&raw(kind::HEADERS, flag::END_HEADERS | flag::END_STREAM, 1, &with(&[("x", "1")])));
    s.process().unwrap();
    assert!(written(&mut s).iter().any(|f| (f.0, f.1, f.2) == (kind::RST_STREAM, 1, ErrorCode::STREAM_CLOSED.0)));
}

// ------------------------------------------------------------------------------------------------ over TCP

/// Runs the server on one accepted connection in a thread, with `handler`.
fn spawn_server(settings: Settings, handler: impl FnMut(&Request) -> Vec<Step> + Send + 'static) -> (std::net::SocketAddr, thread::JoinHandle<Ended>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut handler = handler;
        serve(&mut stream, &settings, &mut handler).unwrap()
    });
    (addr, handle)
}

/// A client over a socket, as simple as can be: write what is queued, read what comes, until `done`.
struct Wire {
    conn: Connection,
    io: TcpStream,
}

impl Wire {
    fn connect(addr: std::net::SocketAddr) -> Wire {
        let io = TcpStream::connect(addr).unwrap();
        io.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
        Wire { conn: Connection::new(Config::default()), io }
    }

    fn drive(&mut self, mut done: impl FnMut(&mut Connection) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if self.conn.wants_write() {
                let n = self.conn.output().len();
                self.io.write_all(self.conn.output()).unwrap();
                self.conn.consume_output(n);
            }
            if done(&mut self.conn) {
                return;
            }
            assert!(Instant::now() < deadline, "the exchange does not finish");
            match self.io.read(&mut buf) {
                Ok(0) => {
                    self.conn.peer_closed();
                    return;
                }
                Ok(n) => {
                    self.conn.receive(&buf[..n]);
                    let _ = self.conn.process();
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                // a server that closes with something of ours unread resets the connection
                Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof) => {
                    self.conn.peer_closed();
                    return;
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    fn fetch(&mut self, method: &str, path: &str) -> (u32, Got) {
        let id = self.conn.open_stream(&ClientRequest { method, scheme: "https", authority: "example.com", path, headers: &[], secret: &[] }, true).unwrap();
        let got = self.collect(id);
        (id, got)
    }

    /// Reads the stream to its end (or to its loss, or the loss of the connection).
    fn collect(&mut self, id: u32) -> Got {
        let mut got = Got::default();
        self.drive(|c| collect_into(c, id, &mut got));
        // a connection that closed ends the loop without the closure seeing it
        collect_into(&mut self.conn, id, &mut got);
        got
    }
}

/// Takes what the stream has into `got`; true once the stream is over.
fn collect_into(c: &mut Connection, id: u32, got: &mut Got) -> bool {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match c.poll_stream(id, &mut buf) {
            StreamEvent::Pending => return false,
            StreamEvent::Head(h) => got.head = Some(h),
            StreamEvent::Data(n) => got.body.extend_from_slice(&buf[..n]),
            StreamEvent::Trailers(t) => got.trailers = Some(t),
            StreamEvent::End => {
                got.ended = true;
                return true;
            }
            StreamEvent::Failed(e) => {
                got.failed = Some(e);
                return true;
            }
        }
    }
}

#[test]
fn over_tcp_a_request_is_answered_and_the_connection_ends_when_the_client_leaves() {
    let (addr, server) = spawn_server(Settings::default(), |r| response(200, &[("x-path", &r.path)], format!("you asked for {}", r.path).as_bytes()));
    let mut wire = Wire::connect(addr);
    let (_, got) = wire.fetch("GET", "/one");
    assert_eq!(got.body, b"you asked for /one");
    assert_eq!(got.head.unwrap().headers, pairs(&[("x-path", "/one")]));
    let (_, got) = wire.fetch("GET", "/two");
    assert_eq!(got.body, b"you asked for /two");
    drop(wire);
    assert_eq!(server.join().unwrap(), Ended::PeerClosed);
}

#[test]
fn over_tcp_steps_happen_when_they_are_due_and_streams_do_not_wait_for_each_other() {
    let (addr, server) = spawn_server(Settings::default(), |r| {
        if r.path == "/slow" {
            vec![
                Step::now(Action::Head { status: 200, headers: vec![], end: false }),
                Step::later(Duration::from_millis(300), Action::Data(b"late".to_vec())),
                Step::now(Action::End),
            ]
        } else {
            response(200, &[], b"quick")
        }
    });
    let mut wire = Wire::connect(addr);
    let started = Instant::now();
    let slow = wire.conn.open_stream(&ClientRequest { method: "GET", scheme: "https", authority: "example.com", path: "/slow", headers: &[], secret: &[] }, true).unwrap();
    let (_, quick) = wire.fetch("GET", "/quick");
    assert_eq!(quick.body, b"quick");
    assert!(started.elapsed() < Duration::from_millis(250), "the quick one did not wait for the slow one");
    let mut got = Got::default();
    wire.drive(|c| {
        let mut buf = [0u8; 100];
        loop {
            match c.poll_stream(slow, &mut buf) {
                StreamEvent::Pending => return false,
                StreamEvent::Head(h) => got.head = Some(h),
                StreamEvent::Data(n) => got.body.extend_from_slice(&buf[..n]),
                StreamEvent::End => {
                    got.ended = true;
                    return true;
                }
                other => panic!("{other:?}"),
            }
        }
    });
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(got.body, b"late");
    drop(wire);
    server.join().unwrap();
}

#[test]
fn over_tcp_a_request_body_is_uploaded_and_echoed() {
    let (addr, server) = spawn_server(Settings::default(), |r| response(200, &[], &r.body));
    let mut wire = Wire::connect(addr);
    let body: Vec<u8> = (0..3_000_000u32).map(|i| (i % 249) as u8).collect();
    let id = wire.conn.open_stream(&ClientRequest { method: "POST", scheme: "https", authority: "example.com", path: "/echo", headers: &[], secret: &[] }, false).unwrap();
    let mut sent = 0;
    let mut got = Got::default();
    wire.drive(|c| {
        if sent < body.len() {
            sent += c.send_data(id, &body[sent..], true).unwrap();
        }
        collect_into(c, id, &mut got)
    });
    assert!(got.ended && got.failed.is_none());
    assert!(got.body == body);
    drop(wire);
    server.join().unwrap();
}

#[test]
fn over_tcp_the_handler_may_close_or_cut_the_connection() {
    for (action, ended) in [(Action::Close, Ended::Closed), (Action::Cut, Ended::Cut)] {
        let a = action.clone();
        let (addr, server) = spawn_server(Settings::default(), move |_| vec![Step::now(a.clone())]);
        let mut wire = Wire::connect(addr);
        let (_, got) = wire.fetch("GET", "/");
        assert!(got.failed.is_some(), "the stream is lost with the connection");
        assert_eq!(server.join().unwrap(), ended);
    }
}

#[test]
fn over_tcp_a_client_goaway_lets_the_open_streams_finish() {
    let (addr, server) = spawn_server(Settings::default(), |_| {
        vec![Step::now(Action::Head { status: 200, headers: vec![], end: false }), Step::later(Duration::from_millis(100), Action::Data(b"done".to_vec())), Step::now(Action::End)]
    });
    let mut wire = Wire::connect(addr);
    let id = wire.conn.open_stream(&ClientRequest { method: "GET", scheme: "https", authority: "example.com", path: "/", headers: &[], secret: &[] }, true).unwrap();
    let mut got = Got::default();
    // until the head is in
    wire.drive(|c| {
        collect_into(c, id, &mut got);
        got.head.is_some()
    });
    // the client says it will open no more streams, by a GOAWAY of its own making (the state machine has no
    // graceful close: its close() abandons what is open)
    let mut goaway = Vec::new();
    frame::write_goaway(&mut goaway, 0, ErrorCode::NO_ERROR, b"bye");
    wire.io.write_all(&goaway).unwrap();
    wire.drive(|c| collect_into(c, id, &mut got));
    assert_eq!(got.body, b"done");
    assert!(got.ended);
    drop(wire);
    assert_eq!(server.join().unwrap(), Ended::Closed, "the server finished its streams and ended the connection");
}
