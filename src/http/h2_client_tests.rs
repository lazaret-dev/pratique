//! Tests of the blocking client's HTTP/2 transport against the crate's own HTTP/2 server (`h2_testserver`) over
//! its own TLS server: that requests share one connection, that a burst dials once, that what goes out is a
//! well-formed HTTP/2 request (the server checks and complains), that refused and unprocessed requests are sent
//! again and others are not, that limits and timeouts hold, that a connection that dies is replaced, and that an
//! origin that speaks only HTTP/1.1 is spoken to as before.

use super::h2::connection::Request;
use super::h2_server::{response, Action, Settings, Step};
use super::h2_transport::{H2Stream, Pause, Shared, Waits};
use super::h2_testserver::*;
use super::testserver::{ok, TestServer};
use crate::asyncio::block_on;
use crate::error::Error;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn hello(seen: &Seen) -> Vec<Step> {
    response(200, &[], format!("hello {}", seen.path()).as_bytes())
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'a' + (i % 26) as u8).collect()
}

/// A response whose head comes `delay` after the request, with `body`.
fn after(delay: Duration, body: &[u8]) -> Vec<Step> {
    vec![
        Step::later(delay, Action::Head { status: 200, headers: vec![("content-length".into(), body.len().to_string())], end: body.is_empty() }),
        Step::now(Action::Data(body.to_vec())),
        Step::now(Action::End),
    ]
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < give_up, "waited too long for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

// ------------------------------------------------------------------------------------------------ headers for each hop

#[test]
fn what_the_hook_gives_goes_over_http2_to_the_host_it_was_given_for_and_a_connection_is_never_shared_between_hosts() {
    // one server with two names (the same address, the same certificate): a client that put both on one connection, as RFC 9113 section 9.1.1
    // lets it, would be able to send one host's credentials to the other; this one has a connection for each origin
    let server = H2Server::start(hello);
    let port = server.port;
    let client = server.client().hop_headers(|info| {
        Ok(vec![("Authorization".to_string(), format!("Bearer for-{}", info.url.host)), ("Private-Token".to_string(), format!("p-{}", info.url.host))])
    });
    for (host, path) in [("127.0.0.1", "/one"), ("localhost", "/two"), ("127.0.0.1", "/three"), ("localhost", "/four")] {
        assert_eq!(client.get(&format!("https://{host}:{port}{path}")).unwrap().text(), format!("hello {path}"));
    }
    assert_eq!(server.connections(), 2, "a connection for each host, and each is used again");
    let seen = server.requests();
    for (path, host) in [("/one", "127.0.0.1"), ("/two", "localhost"), ("/three", "127.0.0.1"), ("/four", "localhost")] {
        let q = seen.iter().find(|s| s.path() == path).unwrap();
        assert_eq!(q.header("authorization"), Some(format!("Bearer for-{host}").as_str()), "{path}");
        assert_eq!(q.header("private-token"), Some(format!("p-{host}").as_str()), "{path}");
    }
    // a redirect from one to the other: the credentials of the host it lands on, and not those of the host it left
    let redirecting = H2Server::start(move |seen: &Seen| {
        if seen.path() == "/start" {
            let to = format!("https://{}/landed", seen.request.authority.replace("127.0.0.1", "localhost"));
            response(302, &[("location", to.as_str())], b"")
        } else {
            response(200, &[], b"landed")
        }
    });
    let port = redirecting.port;
    let client = redirecting.client().hop_headers(|info| Ok(vec![("Private-Token".to_string(), format!("p-{}", info.url.host))]));
    assert_eq!(client.get(&format!("https://127.0.0.1:{port}/start")).unwrap().text(), "landed");
    let seen = redirecting.requests();
    assert_eq!(seen.iter().find(|s| s.path() == "/start").unwrap().header("private-token"), Some("p-127.0.0.1"));
    assert_eq!(seen.iter().find(|s| s.path() == "/landed").unwrap().header("private-token"), Some("p-localhost"));
}

// ------------------------------------------------------------------------------------------------ a request

#[test]
fn a_get_goes_over_http2_as_a_well_formed_request() {
    let server = H2Server::start(hello);
    let client = server.client();
    let r = client.get(&server.url("/a/b?c=d")).unwrap();
    assert_eq!((r.status, r.text().as_str()), (200, "hello /a/b?c=d"));
    assert_eq!(r.reason, "", "HTTP/2 has no reason phrase");
    let seen = server.requests();
    assert_eq!(seen.len(), 1);
    let q = &seen[0].request;
    assert_eq!((q.method.as_str(), q.scheme.as_str(), q.path.as_str()), ("GET", "https", "/a/b?c=d"));
    assert_eq!(q.authority, format!("127.0.0.1:{}", server.port));
    assert!(q.header("user-agent").unwrap().starts_with("pratique/"));
    assert_eq!(q.header("accept"), Some("*/*"));
    assert_eq!(q.header("accept-encoding"), Some("identity"));
    assert!(q.header("host").is_none() && q.header("connection").is_none(), "no Host and no Connection in an HTTP/2 request: {:?}", q.headers);
    assert!(q.headers.iter().all(|(n, _)| n.chars().all(|c| !c.is_ascii_uppercase())));
    drop(client);
    assert_eq!(server.end_and_complaints(), Vec::<String>::new());
}

#[test]
fn headers_are_lowered_and_connection_specific_ones_dropped() {
    let server = H2Server::start(hello);
    let client = server.client();
    let r = client
        .request("GET", &server.url("/"))
        .header("X-Mixed-Case", "Value Kept")
        .header("Host", "other.example")
        .header("Connection", "keep-alive")
        .header("Keep-Alive", "timeout=5")
        .header("Upgrade", "websocket")
        .header("Transfer-Encoding", "chunked")
        .header("Accept", "text/plain")
        .send()
        .unwrap();
    assert_eq!(r.status, 200);
    let seen = server.requests();
    let q = &seen[0].request;
    assert_eq!(q.header("x-mixed-case"), Some("Value Kept"));
    assert_eq!(q.header("accept"), Some("text/plain"));
    for gone in ["host", "connection", "keep-alive", "upgrade", "transfer-encoding"] {
        assert!(q.header(gone).is_none(), "{gone} must not be sent over HTTP/2");
    }
    assert_eq!(q.authority, format!("127.0.0.1:{}", server.port), "the authority comes from the URL");
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn request_bodies_of_all_sizes_arrive_whole() {
    let server = H2Server::start(|s| response(200, &[], s.body()));
    let client = server.client();
    for size in [0usize, 1, 100, 16_384, 16_385, 70_000, 300_000, 3_000_000] {
        let body: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
        let r = client.request("POST", &server.url("/echo")).body(body.clone()).send().unwrap();
        assert_eq!(r.status, 200, "size {size}");
        assert!(r.body == body, "the echo of {size} bytes differs");
    }
    let seen = server.requests();
    assert_eq!(seen[2].header("content-length"), Some("100"));
    assert_eq!(seen[0].header("content-length"), Some("0"), "a POST with no body says so");
    drop(client);
    assert_eq!(server.connections(), 1);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn a_big_response_streams_through_with_bounded_reads() {
    let body = pattern(5_000_000);
    let b = body.clone();
    let server = H2Server::start(move |_| response(200, &[("content-length", &b.len().to_string())], &b));
    let client = server.client();
    let mut stream = client.get_stream(&server.url("/big")).unwrap();
    assert_eq!(stream.content_length, Some(5_000_000));
    let mut got = Vec::new();
    let mut buf = [0u8; 7000];
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got == body);
    drop(stream);
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn head_and_bodiless_statuses() {
    let server = H2Server::start(|s| match s.path() {
        "/head" => vec![Step::now(Action::Head { status: 200, headers: vec![("content-length".into(), "12345".into())], end: true })],
        "/204" => response(204, &[], b""),
        _ => response(304, &[("content-length", "99")], b""),
    });
    let client = server.client().max_body_bytes(100);
    let h = client.head(&server.url("/head")).unwrap();
    assert_eq!((h.status, h.body.len(), h.header("content-length")), (200, 0, Some("12345")), "a HEAD response may declare more than the limit: it has no body");
    assert_eq!(client.get(&server.url("/204")).unwrap().status, 204);
    assert_eq!(client.get(&server.url("/304")).unwrap().status, 304);
    assert_eq!(server.connections(), 1);
}

#[test]
fn big_header_lists_both_ways_need_continuation_frames() {
    let server = H2Server::start(|s| {
        let n: usize = s.header("x-want").and_then(|v| v.parse().ok()).unwrap_or(0);
        let headers: Vec<(String, String)> = (0..n).map(|i| (format!("x-header-{i}"), format!("{i:0>100}"))).collect();
        let mut steps = vec![Step::now(Action::Head { status: 200, headers, end: false })];
        steps.push(Step::now(Action::Data(format!("saw {} big headers", s.request.headers.iter().filter(|(k, _)| k.starts_with("x-big-")).count()).into_bytes())));
        steps.push(Step::now(Action::End));
        steps
    });
    let client = server.client();
    let mut req = client.request("GET", &server.url("/")).header("X-Want", "300");
    for i in 0..40 {
        req = req.header(&format!("X-Big-{i}"), &"v".repeat(1000));
    }
    let r = req.send().unwrap();
    assert_eq!(r.text(), "saw 40 big headers");
    assert_eq!(r.headers.iter().filter(|(k, _)| k.starts_with("x-header-")).count(), 300);
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn trailers_and_interim_responses_do_not_get_in_the_way() {
    let server = H2Server::start(|s| match s.path() {
        "/trailers" => vec![
            Step::now(Action::Head { status: 200, headers: vec![("trailer".into(), "x-sum".into())], end: false }),
            Step::now(Action::Data(b"with trailers".to_vec())),
            Step::now(Action::Trailers(vec![("x-sum".into(), "13".into())])),
        ],
        _ => {
            let mut steps = vec![Step::now(Action::Interim { status: 103, headers: vec![("link".into(), "</a.css>; rel=preload".into())] })];
            steps.extend(response(200, &[], b"after the hint"));
            steps
        }
    });
    let client = server.client();
    let r = client.get(&server.url("/trailers")).unwrap();
    assert_eq!((r.status, r.text().as_str()), (200, "with trailers"));
    let r = client.get(&server.url("/interim")).unwrap();
    assert_eq!((r.status, r.text().as_str()), (200, "after the hint"));
    assert!(r.header("link").is_none(), "the 103's headers are not the response's");
    assert_eq!(server.connections(), 1);
}

#[test]
fn redirects_are_followed_on_the_same_connection() {
    let server = H2Server::start(|s| match s.path() {
        "/start" => response(302, &[("location", "/middle")], b"moved"),
        "/middle" => response(301, &[("location", "final?x=1")], b""),
        p => response(200, &[], p.as_bytes()),
    });
    let client = server.client();
    let r = client.get(&server.url("/start")).unwrap();
    assert_eq!((r.status, r.text().as_str(), r.url.path_and_query.as_str()), (200, "/final?x=1", "/final?x=1"));
    assert_eq!(server.connections(), 1);
    assert_eq!(server.requests().len(), 3);
}

// ------------------------------------------------------------------------------------------------ one connection

#[test]
fn requests_one_after_another_share_a_connection() {
    let server = H2Server::start(hello);
    let client = server.client();
    for i in 0..6 {
        let r = client.get(&server.url(&format!("/{i}"))).unwrap();
        assert_eq!(r.text(), format!("hello /{i}"));
        assert_eq!(client.idle_connections(), 1, "the connection waits between requests");
    }
    assert_eq!(server.connections(), 1);
    assert!(server.requests().iter().all(|s| s.conn == 0));
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn concurrent_requests_are_in_flight_together_on_one_connection() {
    // each answer takes 400 ms; run one after another the sixteen would take over six seconds
    let server = H2Server::start(|s| after(Duration::from_millis(400), format!("hello {}", s.path()).as_bytes()));
    let client = server.client();
    let started = Instant::now();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let (client, server) = (&client, &server);
                scope.spawn(move || client.get(&server.url(&format!("/{i}"))).unwrap().text())
            })
            .collect();
        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), format!("hello /{i}"));
        }
    });
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    assert_eq!(server.connections(), 1, "one connection for all sixteen");
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn a_burst_of_first_requests_dials_once() {
    for _ in 0..5 {
        let server = H2Server::start(hello);
        let client = server.client();
        thread::scope(|scope| {
            for i in 0..12 {
                let (client, server) = (&client, &server);
                scope.spawn(move || assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().status, 200));
            }
        });
        assert_eq!(server.connections(), 1, "twelve requests that arrived together to a new origin made more than one connection");
    }
}

#[test]
fn a_server_that_limits_concurrent_streams_gets_more_connections() {
    let settings = Settings { max_concurrent_streams: 2, ..Settings::default() };
    let server = H2Server::start_with(|s| after(Duration::from_millis(300), s.path().as_bytes()), settings, |c| c);
    let client = server.client();
    thread::scope(|scope| {
        let hs: Vec<_> = (0..6)
            .map(|i| {
                let (client, server) = (&client, &server);
                scope.spawn(move || client.get(&server.url(&format!("/{i}"))).unwrap().text())
            })
            .collect();
        for (i, h) in hs.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), format!("/{i}"));
        }
    });
    assert!(server.connections() >= 2, "six requests at once, two streams each: {} connection(s)", server.connections());
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn clones_of_a_client_share_the_connections() {
    let server = H2Server::start(hello);
    let a = server.client();
    let b = a.clone();
    a.get(&server.url("/1")).unwrap();
    b.get(&server.url("/2")).unwrap();
    assert_eq!(server.connections(), 1);
    drop(a);
    // b still has the connection
    thread::sleep(Duration::from_millis(100));
    b.get(&server.url("/3")).unwrap();
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_async_methods_use_the_shared_connection() {
    let server = H2Server::start(hello);
    let client = server.client();
    let futs: Vec<_> = (0..4).map(|i| client.get_async(&server.url(&format!("/{i}")))).collect();
    for (i, r) in block_on(crate::asyncio::join_all(futs)).into_iter().enumerate() {
        assert_eq!(r.unwrap().text(), format!("hello /{i}"));
    }
    assert_eq!(server.connections(), 1);
}

// ------------------------------------------------------------------------------------------------ closing

#[test]
fn an_idle_connection_is_closed_after_the_idle_timeout() {
    let server = H2Server::start(hello);
    let client = server.client().pool_idle_timeout(Duration::from_millis(300));
    client.get(&server.url("/1")).unwrap();
    assert_eq!(client.idle_connections(), 1);
    wait_until("the idle connection to be closed", || client.idle_connections() == 0);
    wait_until("the server to see it close", || server.ended_connections() == 1);
    client.get(&server.url("/2")).unwrap();
    assert_eq!(server.connections(), 2, "a new connection for the request after the old one expired");
}

#[test]
fn close_idle_connections_closes_them() {
    let server = H2Server::start(hello);
    let client = server.client();
    client.get(&server.url("/")).unwrap();
    assert_eq!(client.idle_connections(), 1);
    client.close_idle_connections();
    wait_until("the connection to go", || client.idle_connections() == 0);
    client.get(&server.url("/")).unwrap();
    assert_eq!(server.connections(), 2);
}

#[test]
fn dropping_the_client_closes_the_connection_after_the_streams_are_done() {
    let body = pattern(2_000_000);
    let b = body.clone();
    let server = H2Server::start(move |_| response(200, &[], &b));
    let client = server.client();
    let mut stream = client.get_stream(&server.url("/")).unwrap();
    let mut first = [0u8; 100];
    stream.read_exact(&mut first).unwrap();
    drop(client);
    // the stream in flight goes on to its end
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert_eq!(rest.len() + 100, body.len());
    drop(stream);
    // and then the connection closes
    let give_up = Instant::now() + Duration::from_secs(5);
    while server.ended_connections() < 1 && Instant::now() < give_up {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(server.ended_connections(), 1, "the server did not see the connection close");
}

#[test]
fn a_connection_the_server_closed_is_replaced() {
    let server = H2Server::start(hello);
    let client = server.client();
    assert_eq!(client.get(&server.url("/1")).unwrap().status, 200);
    server.close_all();
    wait_until("the client to notice", || client.idle_connections() == 0);
    assert_eq!(client.get(&server.url("/2")).unwrap().text(), "hello /2");
    assert_eq!(server.connections(), 2);
}

#[test]
fn a_connection_cut_under_a_request_is_replaced_for_requests_that_may_be_repeated() {
    // the server drops the connection when the second request on it arrives, answering only the first
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let server = H2Server::start(move |s| {
        if s.conn == 0 && c.fetch_add(1, Ordering::SeqCst) >= 1 {
            vec![Step::now(Action::Cut)]
        } else {
            hello(s)
        }
    });
    let client = server.client();
    assert_eq!(client.get(&server.url("/1")).unwrap().status, 200);
    // GET: sent again, on a new connection
    assert_eq!(client.get(&server.url("/2")).unwrap().text(), "hello /2");
    assert_eq!(server.connections(), 2);

    // POST: not sent again, because it may have been acted on
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let server = H2Server::start(move |s| {
        if s.conn == 0 && c.fetch_add(1, Ordering::SeqCst) >= 1 {
            vec![Step::now(Action::Cut)]
        } else {
            hello(s)
        }
    });
    let client = server.client();
    assert_eq!(client.get(&server.url("/1")).unwrap().status, 200);
    let err = client.post(&server.url("/2"), "data").unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    assert_eq!(server.requests().len(), 2, "the POST was not sent again");
    // the client carries on with a new connection
    assert_eq!(client.get(&server.url("/3")).unwrap().text(), "hello /3");
}

// ------------------------------------------------------------------------------------------------ what the server says

#[test]
fn a_refused_stream_is_sent_again_whatever_the_method() {
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let server = H2Server::start(move |s| {
        if c.fetch_add(1, Ordering::SeqCst) == 0 {
            vec![Step::now(Action::Reset(7))] // REFUSED_STREAM
        } else {
            response(200, &[], s.body())
        }
    });
    let client = server.client();
    let r = client.post(&server.url("/"), "payload").unwrap();
    assert_eq!(r.text(), "payload");
    assert_eq!(server.requests().len(), 2, "refused once, then taken");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_stream_the_server_resets_for_another_reason_is_an_error_and_not_sent_again() {
    let server = H2Server::start(|s| match s.path() {
        "/reset" => vec![Step::now(Action::Head { status: 200, headers: vec![], end: false }), Step::now(Action::Data(b"part".to_vec())), Step::now(Action::Reset(2))],
        "/early" => vec![Step::now(Action::Reset(2))],
        _ => hello(s),
    });
    let client = server.client();
    // reset before the head: an error, once
    let err = client.get(&server.url("/early")).unwrap_err();
    assert!(matches!(err, Error::Http(_)) && err.to_string().contains("INTERNAL_ERROR"), "{err:?}");
    assert_eq!(server.requests().len(), 1);
    // reset in the middle of the body: the read fails, the connection is fine
    let mut stream = client.get_stream(&server.url("/reset")).unwrap();
    let mut out = Vec::new();
    assert!(stream.read_to_end(&mut out).is_err());
    assert_eq!(out, b"part");
    drop(stream);
    assert_eq!(client.get(&server.url("/ok")).unwrap().text(), "hello /ok");
    assert_eq!(server.connections(), 1);
}

#[test]
fn requests_the_server_did_not_get_to_move_to_a_new_connection_after_goaway() {
    // the first connection says GOAWAY with last stream 0 on the first request: nothing was processed
    let server = H2Server::start(|s| {
        if s.conn == 0 {
            vec![Step::now(Action::GoAway { code: 0, last_stream: Some(0) })]
        } else {
            response(200, &[], s.body())
        }
    });
    let client = server.client();
    for method in ["GET", "POST"] {
        let r = client.request(method, &server.url("/x")).body("body").send().unwrap();
        assert_eq!(r.status, 200, "{method}");
    }
    assert_eq!(server.connections(), 2, "the second connection took both");
}

#[test]
fn a_graceful_goaway_after_an_answer_retires_the_connection() {
    let server = H2Server::start(|s| {
        let mut steps = hello(s);
        if s.path() == "/goaway" {
            steps.push(Step::now(Action::GoAway { code: 0, last_stream: None }));
        }
        steps
    });
    let client = server.client();
    assert_eq!(client.get(&server.url("/goaway")).unwrap().text(), "hello /goaway");
    assert_eq!(client.get(&server.url("/next")).unwrap().text(), "hello /next");
    assert_eq!(server.connections(), 2);
    assert_eq!(server.requests().iter().map(|s| s.conn).collect::<Vec<_>>(), [0, 1]);
}

#[test]
fn a_push_promise_fails_the_connection_and_the_request() {
    let server = H2Server::start(|s| {
        if s.path() == "/push" {
            let promised = vec![(":method".to_string(), "GET".to_string()), (":scheme".into(), "https".into()), (":authority".into(), s.request.authority.clone()), (":path".into(), "/pushed".into())];
            let mut steps = vec![Step::now(Action::PushPromise { promised: 2, headers: promised })];
            steps.extend(hello(s));
            steps
        } else {
            hello(s)
        }
    });
    let client = server.client();
    let err = client.get(&server.url("/push")).unwrap_err();
    assert!(err.to_string().contains("PUSH_PROMISE"), "{err}");
    // the connection was lost; the next request makes another
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
    assert_eq!(server.connections(), 2);
}

// ------------------------------------------------------------------------------------------------ limits and time

#[test]
fn the_body_size_limit_holds_and_the_connection_survives_it() {
    let server = H2Server::start(|s| match s.path() {
        "/declared" => response(200, &[("content-length", "500")], &pattern(500)),
        "/undeclared" => vec![Step::now(Action::Head { status: 200, headers: vec![], end: false }), Step::now(Action::Data(pattern(500))), Step::now(Action::End)],
        _ => hello(s),
    });
    let client = server.client().max_body_bytes(100);
    let err = client.get(&server.url("/declared")).unwrap_err();
    assert!(err.to_string().contains("size limit"), "{err}");
    let err = client.get(&server.url("/undeclared")).unwrap_err();
    assert!(err.to_string().contains("size limit"), "{err}");
    // a request may raise the limit for itself
    assert_eq!(client.request("GET", &server.url("/declared")).max_body_bytes(1000).send().unwrap().body.len(), 500);
    assert_eq!(client.get(&server.url("/small")).unwrap().text(), "hello /small");
    assert_eq!(server.connections(), 1, "the oversized responses cost the connection nothing");
}

#[test]
fn a_silent_server_times_out_the_request_and_not_the_connection() {
    let server = H2Server::start(|s| if s.path() == "/slow" { after(Duration::from_secs(3), b"late") } else { hello(s) });
    let client = server.client().timeout(Duration::from_millis(300));
    let started = Instant::now();
    let err = client.get(&server.url("/slow")).unwrap_err();
    assert!(matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
    assert_eq!(client.get(&server.url("/quick")).unwrap().text(), "hello /quick");
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_total_time_limit_cuts_off_a_server_that_drips() {
    let server = H2Server::start(|_| {
        let mut steps = vec![Step::now(Action::Head { status: 200, headers: vec![], end: false })];
        for b in pattern(40) {
            steps.push(Step::later(Duration::from_millis(50), Action::Data(vec![b])));
        }
        steps.push(Step::now(Action::End));
        steps
    });
    // every wait is well inside the per-operation limit, but the whole takes two seconds
    let client = server.client().total_timeout(Duration::from_millis(400));
    let started = Instant::now();
    let err = client.get(&server.url("/")).unwrap_err();
    assert!(err.to_string().contains("total time limit"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(1), "took {:?}", started.elapsed());
    let ok = server.client().total_timeout(Duration::from_secs(10)).get(&server.url("/")).unwrap();
    assert_eq!(ok.body.len(), 40);
}

#[test]
fn giving_up_on_a_response_early_cancels_the_stream_and_the_connection_goes_on() {
    let big = pattern(20_000_000);
    let b = big.clone();
    let server = H2Server::start(move |s| if s.path() == "/big" { response(200, &[], &b) } else { hello(s) });
    let client = server.client();
    let mut stream = client.get_stream(&server.url("/big")).unwrap();
    let mut buf = [0u8; 1000];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf[..], &big[..1000]);
    drop(stream);
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
    assert_eq!(server.connections(), 1);
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn threads_that_share_a_connection_read_and_send_for_each_other() {
    // eight threads making small requests on one connection (B-89): a caller who has its response gives the right to read to
    // one who waits for its own, so the callers read and the reader thread is seldom needed; and a caller who finds another
    // writing leaves its request to it, so the writer thread is seldom woken
    let server = H2Server::start(hello);
    let client = Arc::new(server.client());
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let (callers_before, reader_before) = client.h2_reads();
    let wakes_before = conn.writer_wakes();
    let workers: Vec<_> = (0..8)
        .map(|t| {
            let (client, url) = (client.clone(), server.url(&format!("/t{t}")));
            thread::spawn(move || {
                for _ in 0..50 {
                    assert_eq!(client.get(&url).unwrap().text(), format!("hello /t{t}"));
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let (callers, reader) = client.h2_reads();
    let (callers, reader) = (callers - callers_before, reader - reader_before);
    let wakes = conn.writer_wakes() - wakes_before;
    eprintln!("400 requests on 8 threads: the callers read {callers} times, the reader thread {reader}; the writer thread was woken {wakes} times");
    assert!(callers > 2 * reader, "the callers read {callers} times, the reader thread {reader}");
    assert!(wakes < 40, "the writer thread was woken {wakes} times for 400 requests");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_request_queued_while_another_thread_sends_is_sent_by_that_thread() {
    // A's thread sends its request itself and, having found nothing more to send, is about to let go of the outbox; B's request
    // is queued then, and B's thread finds the outbox taken: A's thread sends it before it goes, and nobody else has to (B-89).
    // (A's response is a second late, so that A's thread, which reads the socket for it, has nothing to read that would make it
    // send B's request on the way)
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };
    conn.set_pause(Pause::Armed);
    let a = {
        let conn = conn.clone();
        let authority = authority.clone();
        thread::spawn(move || {
            let request = Request { method: "GET", scheme: "https", authority: &authority, path: "/slow/1000", headers: &[], secret: &[] };
            let mut a = conn.start(&request, &[], waits).unwrap();
            a.response(1000, waits).unwrap()
        })
    };
    conn.wait_for_pause(Pause::Held);
    let request = Request { method: "GET", scheme: "https", authority: &authority, path: "/b", headers: &[], secret: &[] };
    let mut b = conn.start(&request, &[], waits).unwrap();
    assert!(conn.output_queued(), "B's request went out while A's thread held the outbox");
    let wakes = conn.writer_wakes();
    conn.set_pause(Pause::Off);
    let since = Instant::now();
    while conn.output_queued() {
        assert!(since.elapsed() < Duration::from_millis(100), "B's request waits to be sent");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(conn.writer_wakes(), wakes, "the writer thread was woken for it");
    let (head, body) = b.response(1000, waits).unwrap();
    assert_eq!((head.status, body.as_slice()), (200, &b"hello /b"[..]));
    let (head, body) = a.join().unwrap();
    assert_eq!((head.status, body.as_slice()), (200, &b"late"[..]));
}

#[test]
fn a_stream_that_is_given_up_tells_the_server_at_once() {
    // the server is held back by the stream's window (nothing was read), so nothing comes that would make somebody write: the
    // reset (and the credit for what was received and is dropped) goes from the thread that gives the stream up (B-89)
    let big = pattern(20_000_000);
    let b = big.clone();
    let server = H2Server::start(move |s| if s.path() == "/big" { response(200, &[], &b) } else { hello(s) });
    let client = server.client();
    let mut stream = client.get_stream(&server.url("/big")).unwrap();
    let mut buf = [0u8; 1000];
    stream.read_exact(&mut buf).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    // (the reader thread takes over from the caller, who has stopped reading, and reads what the window let the server send,
    // until nothing more comes)
    wait_until("the reader thread to take over", || conn.reading_caller().is_none());
    let mut reads = client.h2_reads();
    loop {
        thread::sleep(Duration::from_millis(200));
        let now = client.h2_reads();
        if now == reads {
            break;
        }
        reads = now;
    }
    assert!(!conn.output_queued());
    drop(stream);
    let since = Instant::now();
    while conn.output_queued() {
        assert!(since.elapsed() < Duration::from_millis(100), "the reset waits to be sent");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn a_slow_reader_holds_the_server_back_and_others_go_on() {
    // one response is read slowly (the windows fill and the server waits), another is fetched meanwhile
    let big = pattern(8_000_000);
    let b = big.clone();
    let server = H2Server::start(move |s| if s.path() == "/big" { response(200, &[], &b) } else { hello(s) });
    let client = server.client();
    let mut slow = client.get_stream(&server.url("/big")).unwrap();
    let mut one = [0u8; 10];
    slow.read_exact(&mut one).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(client.get(&server.url("/other")).unwrap().text(), "hello /other");
    let mut rest = Vec::new();
    slow.read_to_end(&mut rest).unwrap();
    assert_eq!(rest.len() + 10, big.len());
    assert_eq!(server.connections(), 1);
}

// ------------------------------------------------------------------------------------------------ whole bodies

#[test]
fn a_whole_body_larger_than_the_windows_is_collected_whole() {
    // 20 MB through a stream window of 8 MiB: the server has to be given credit as the body comes, since nobody reads
    // it piece by piece
    let body = pattern(20_000_000);
    let b = body.clone();
    let server = H2Server::start(move |_| response(200, &[("content-length", &b.len().to_string())], &b));
    let client = server.client();
    let r = client.get(&server.url("/big")).unwrap();
    assert_eq!(r.body.len(), body.len());
    assert!(r.body == body);
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn a_whole_body_of_unknown_length_is_collected_whole() {
    let server = H2Server::start(|_| {
        let mut steps = vec![Step::now(Action::Head { status: 200, headers: vec![], end: false })];
        for i in 0..7u8 {
            steps.push(Step::now(Action::Data(vec![b'a' + i; 100_000 + i as usize])));
        }
        steps.push(Step::now(Action::End));
        steps
    });
    let client = server.client();
    let r = client.get(&server.url("/")).unwrap();
    let expected: Vec<u8> = (0..7u8).flat_map(|i| vec![b'a' + i; 100_000 + i as usize]).collect();
    assert!(r.body == expected);
    assert_eq!(r.body.len(), 700_021);
}

#[test]
fn a_whole_body_that_goes_on_slowly_is_not_timed_out_but_one_that_stops_is() {
    let server = H2Server::start(|s| {
        let mut steps = vec![Step::now(Action::Head { status: 200, headers: vec![], end: false })];
        if s.path() == "/stops" {
            steps.push(Step::now(Action::Data(b"some".to_vec())));
            steps.push(Step::later(Duration::from_secs(3), Action::Data(b"more".to_vec())));
        } else {
            // 20 drips 60 ms apart: more than a second all told, and never as long as the limit between two
            for b in pattern(20) {
                steps.push(Step::later(Duration::from_millis(60), Action::Data(vec![b])));
            }
        }
        steps.push(Step::now(Action::End));
        steps
    });
    let client = server.client().timeout(Duration::from_millis(400));
    let started = Instant::now();
    let r = client.get(&server.url("/drips")).unwrap();
    assert_eq!(r.body, pattern(20));
    assert!(started.elapsed() > Duration::from_millis(1000), "took {:?}", started.elapsed());
    let started = Instant::now();
    let err = client.get(&server.url("/stops")).unwrap_err();
    assert!(matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
    // the connection was not hurt: the stream is let go
    assert_eq!(client.get(&server.url("/drips")).unwrap().body, pattern(20));
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_head_that_comes_late_counts_as_progress_for_a_whole_body() {
    // the head comes 300 ms after the request, the body 300 ms after the head: never 400 ms of silence
    let server = H2Server::start(|_| {
        vec![
            Step::later(Duration::from_millis(300), Action::Head { status: 200, headers: vec![], end: false }),
            Step::later(Duration::from_millis(300), Action::Data(b"late".to_vec())),
            Step::now(Action::End),
        ]
    });
    let client = server.client().timeout(Duration::from_millis(400));
    let r = client.get(&server.url("/")).unwrap();
    assert_eq!(r.body, b"late");
}

#[test]
fn a_reset_in_the_middle_of_a_whole_body_is_an_error_and_the_connection_goes_on() {
    let server = H2Server::start(|s| match s.path() {
        "/reset" => vec![Step::now(Action::Head { status: 200, headers: vec![], end: false }), Step::now(Action::Data(pattern(100_000))), Step::now(Action::Reset(2))],
        _ => hello(s),
    });
    let client = server.client();
    let err = client.get(&server.url("/reset")).unwrap_err();
    assert!(matches!(err, Error::Http(_)) && err.to_string().contains("INTERNAL_ERROR"), "{err:?}");
    assert_eq!(client.get(&server.url("/ok")).unwrap().text(), "hello /ok");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_connection_cut_in_the_middle_of_a_whole_body_is_an_error() {
    let server = H2Server::start(|s| match s.path() {
        "/cut" => vec![Step::now(Action::Head { status: 200, headers: vec![], end: false }), Step::now(Action::Data(pattern(100_000))), Step::later(Duration::from_millis(100), Action::Cut)],
        _ => hello(s),
    });
    let client = server.client();
    let err = client.get(&server.url("/cut")).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err:?}");
    // the next request is on a new connection
    assert_eq!(client.get(&server.url("/ok")).unwrap().text(), "hello /ok");
    assert_eq!(server.connections(), 2);
}

#[test]
fn whole_bodies_and_streamed_ones_share_a_connection() {
    let big = pattern(6_000_000);
    let b = big.clone();
    let server = H2Server::start(move |s| if s.path() == "/big" { response(200, &[], &b) } else { hello(s) });
    let client = server.client();
    let mut streamed = client.get_stream(&server.url("/big")).unwrap();
    let mut first = [0u8; 100];
    streamed.read_exact(&mut first).unwrap();
    // while one is being read piece by piece, whole ones come, each its own way
    let c2 = client.clone();
    let url = server.url("/big");
    let whole = thread::spawn(move || c2.get(&url).unwrap().body);
    assert_eq!(client.get(&server.url("/small")).unwrap().text(), "hello /small");
    let mut rest = Vec::new();
    streamed.read_to_end(&mut rest).unwrap();
    assert_eq!(rest.len() + 100, big.len());
    assert!(whole.join().unwrap() == big);
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_body_that_was_partly_read_is_collected_from_where_it_was() {
    let big = pattern(300_000);
    let b = big.clone();
    let server = H2Server::start(move |_| response(200, &[("content-length", &b.len().to_string())], &b));
    let client = server.client();
    let mut stream = client.get_stream(&server.url("/")).unwrap();
    let mut first = [0u8; 1000];
    stream.read_exact(&mut first).unwrap();
    assert_eq!(&first[..], &big[..1000]);
    let rest = stream.into_response().unwrap();
    assert!(rest.body == big[1000..]);
}

// ------------------------------------------------------------------------------------------------ other servers

#[test]
fn a_server_that_chooses_http1_is_spoken_to_in_http1() {
    // the HTTP/1.1 test server, with ALPN http/1.1 selected
    let server = TestServer::start_tls_with(|s| ok(&format!("hello {}", s.path())), |c| c.with_alpn(&["http/1.1"]));
    let client = server.client().http2(true);
    for i in 0..4 {
        assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().text(), format!("hello /{i}"));
    }
    assert_eq!(server.connections(), 1, "HTTP/1.1 keep-alive as ever");
    assert_eq!(client.idle_connections(), 1);
    // a server with no ALPN at all is an HTTP/1.1 server too
    let server = TestServer::start_tls(|s| ok(&format!("hello {}", s.path())));
    let client = server.client().http2(true);
    assert_eq!(client.get(&server.url("/a")).unwrap().text(), "hello /a");
    assert_eq!(client.get(&server.url("/b")).unwrap().text(), "hello /b");
    assert_eq!(server.connections(), 1);
}

#[test]
fn concurrent_requests_to_an_http1_origin_are_not_held_up_by_the_probe() {
    let server = TestServer::start_tls_with(|s| ok(&format!("hello {}", s.path())), |c| c.with_alpn(&["http/1.1"]));
    let client = server.client().http2(true);
    thread::scope(|scope| {
        for i in 0..6 {
            let (client, server) = (&client, &server);
            scope.spawn(move || assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().text(), format!("hello /{i}")));
        }
    });
    // the first request found out; the others each made a connection of their own, as HTTP/1.1 clients do
    assert!(server.connections() >= 1 && server.connections() <= 6);
}

#[test]
fn without_keep_alive_the_client_speaks_http1() {
    let server = TestServer::start_tls(|s| ok(&format!("hello {}", s.path())));
    let client = server.client().http2(true).keep_alive(false);
    assert_eq!(client.get(&server.url("/")).unwrap().text(), "hello /");
    assert!(server.requests()[0].has_header("Connection: close"));
}

#[test]
fn a_server_that_picks_h2_for_a_client_that_did_not_ask_for_it_is_an_error() {
    // a client whose own TLS settings offer h2 but that has not switched HTTP/2 on must not speak HTTP/1.1 into an h2 connection
    let server = H2Server::start(hello);
    let mut config = crate::tls::ClientConfig::new(server.client_trust());
    config.alpn_protocols = vec![b"h2".to_vec()];
    let client = crate::Client::with_tls_config(config).timeout(Duration::from_secs(5));
    let err = client.get(&server.url("/")).unwrap_err();
    assert!(err.to_string().contains("HTTP/2"), "{err}");
}

#[test]
fn the_registry_remembers_what_it_must_and_forgets_dead_connections() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let server = H2Server::start(move |s| {
        s2.lock().unwrap().push(s.conn);
        hello(s)
    });
    let client = server.client();
    client.get(&server.url("/1")).unwrap();
    server.close_all();
    wait_until("the dead connection to be noticed", || client.idle_connections() == 0);
    client.get(&server.url("/2")).unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![0, 1]);
}

// ------------------------------------------------------------------------------------------------ who reads the socket

/// A server whose answers are `/n/<size>` (that many bytes), `/slow/<ms>` (an answer after that long) and `hello` for
/// the rest.
fn sizes_and_delays(s: &Seen) -> Vec<Step> {
    let path = s.path().to_string();
    if let Some(n) = path.strip_prefix("/n/") {
        let n: usize = n.parse().unwrap();
        response(200, &[("content-length", &n.to_string())], &pattern(n))
    } else if let Some(ms) = path.strip_prefix("/slow/") {
        after(Duration::from_millis(ms.parse().unwrap()), b"late")
    } else if let Some(ms) = path.strip_prefix("/trickle/") {
        // "first", and "second" after the time given
        vec![
            Step::now(Action::Head { status: 200, headers: vec![("content-length".into(), "11".into())], end: false }),
            Step::now(Action::Data(b"first".to_vec())),
            Step::later(Duration::from_millis(ms.parse().unwrap()), Action::Data(b"second".to_vec())),
            Step::now(Action::End),
        ]
    } else if path == "/hang" {
        // three bytes of a hundred, and then nothing for a long time
        vec![
            Step::now(Action::Head { status: 200, headers: vec![("content-length".into(), "100".into())], end: false }),
            Step::now(Action::Data(b"abc".to_vec())),
            Step::later(Duration::from_secs(4), Action::End),
        ]
    } else if path == "/cutstream" {
        vec![
            Step::now(Action::Head { status: 200, headers: vec![("content-length".into(), "1000000".into())], end: false }),
            Step::now(Action::Data(pattern(10_000))),
            Step::later(Duration::from_millis(100), Action::Cut),
        ]
    } else {
        hello(s)
    }
}

#[test]
fn a_run_of_requests_is_read_by_the_callers_who_make_them() {
    let server = H2Server::start(hello);
    let client = server.client();
    for i in 0..200 {
        assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().text(), format!("hello /{i}"));
    }
    let (callers, reader) = client.h2_reads();
    // (a request that came when the connection had been left alone for a while is read by the reader thread, which then
    // steps aside again: a loaded machine may cost a few)
    assert!(callers >= 100, "callers read {callers} times, the reader thread {reader}");
    assert!(reader < callers, "callers read {callers} times, the reader thread {reader}");
    assert_eq!(server.connections(), 1);
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn after_a_pause_the_reader_thread_takes_over_and_then_steps_aside_again() {
    let server = H2Server::start(hello);
    let client = server.client();
    for i in 0..5 {
        client.get(&server.url(&format!("/{i}"))).unwrap();
    }
    // the connection is left alone: its reader thread is reading (so that a server that closes it, or says GOAWAY, is noticed)
    let mut taken_over = false;
    for _ in 0..20 {
        let before = client.h2_reads().1;
        thread::sleep(Duration::from_millis(150));
        assert_eq!(client.get(&server.url("/after-a-pause")).unwrap().status, 200);
        if client.h2_reads().1 > before {
            taken_over = true;
            break;
        }
    }
    assert!(taken_over, "the reader thread did not read the response of a request that came after a pause");
    // and the requests that follow it, each other's, are read by their callers again
    let before = client.h2_reads().0;
    for i in 0..40 {
        client.get(&server.url(&format!("/{i}"))).unwrap();
    }
    let led = client.h2_reads().0 - before;
    assert!(led >= 20, "only {led} of 40 requests were read by their callers");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_stream_that_is_read_in_pieces_does_not_wait_for_the_reader_thread_to_wake() {
    // the reader thread stays out of the way for a short while after a request; a request whose response is not read by
    // its own caller (a streamed one) wakes it, instead of waiting for that while to pass
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let started = Instant::now();
    for _ in 0..40 {
        let mut s = client.get_stream(&server.url("/n/3000")).unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 3000);
        drop(s);
        // the whole of a run of requests is inside the while, if each waits for it
    }
    assert!(started.elapsed() < Duration::from_millis(600), "forty streamed requests took {:?}", started.elapsed());
    assert_eq!(server.connections(), 1);
}

#[test]
fn callers_who_read_and_callers_who_wait_share_a_busy_connection() {
    // eight threads, each making requests of all kinds: whole bodies and streamed ones, small, large and late. Whoever
    // finds nobody reading reads; the others are served by that caller, and then by the reader thread when it leaves
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    thread::scope(|scope| {
        for t in 0..8usize {
            let (client, server) = (&client, &server);
            scope.spawn(move || {
                for i in 0..60usize {
                    let (path, len) = match (t + i) % 5 {
                        0 => ("/n/100".to_string(), 100),
                        1 => ("/n/70000".to_string(), 70_000),
                        2 => ("/n/900000".to_string(), 900_000),
                        3 => (format!("/slow/{}", 1 + i % 7), 4),
                        _ => ("/n/5".to_string(), 5),
                    };
                    let body = if (t + i) % 3 == 0 {
                        let mut s = client.get_stream(&server.url(&path)).unwrap();
                        let mut out = Vec::new();
                        s.read_to_end(&mut out).unwrap();
                        out
                    } else {
                        client.get(&server.url(&path)).unwrap().body
                    };
                    assert_eq!(body.len(), len, "{path}");
                    if path.starts_with("/n/") {
                        assert!(body == pattern(len), "{path}");
                    }
                }
            });
        }
    });
    assert_eq!(server.connections(), 1);
    drop(client);
    assert!(server.end_and_complaints().is_empty());
}

#[test]
fn a_request_that_is_read_by_its_caller_times_out_on_time_and_the_connection_goes_on() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client().timeout(Duration::from_millis(400));
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let before = client.h2_reads().0;
    let started = Instant::now();
    let err = client.get(&server.url("/slow/3000")).unwrap_err();
    let took = started.elapsed();
    assert!(matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut), "{err:?}");
    assert!(took >= Duration::from_millis(390) && took < Duration::from_millis(900), "took {took:?}");
    // the caller read it (it did, if the connection was quiet for a moment only): the connection is not held up
    let _ = before;
    assert_eq!(client.get(&server.url("/quick")).unwrap().text(), "hello /quick");
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_time_limit_for_the_whole_request_holds_for_a_caller_who_reads() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let limited = client.clone().total_timeout(Duration::from_millis(300));
    let started = Instant::now();
    let err = limited.get(&server.url("/slow/3000")).unwrap_err();
    assert!(err.to_string().contains("total time limit"), "{err}");
    assert!(started.elapsed() < Duration::from_millis(800), "took {:?}", started.elapsed());
    assert_eq!(client.get(&server.url("/quick")).unwrap().text(), "hello /quick");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_connection_that_is_cut_under_callers_who_read_fails_them_all_and_is_replaced() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let started = Instant::now();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let (client, server) = (&client, &server);
                // POSTs, which are not sent again: the failure is the answer
                scope.spawn(move || client.post(&server.url("/slow/5000"), "x").unwrap_err())
            })
            .collect();
        thread::sleep(Duration::from_millis(200));
        server.close_all();
        for h in handles {
            let err = h.join().unwrap();
            assert!(matches!(err, Error::Io(_)), "{err:?}");
        }
    });
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
    assert_eq!(server.connections(), 2);
}

#[test]
fn a_cut_after_a_run_of_requests_is_found_by_the_request_that_follows() {
    // the server answers five requests and drops the connection when the sixth arrives (which the client's caller finds out
    // reading: the reader thread is out of the way)
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let server = H2Server::start(move |s| if s.conn == 0 && c.fetch_add(1, Ordering::SeqCst) >= 5 { vec![Step::now(Action::Cut)] } else { hello(s) });
    let client = server.client();
    for i in 0..5 {
        assert_eq!(client.get(&server.url(&format!("/{i}"))).unwrap().status, 200);
    }
    // a GET is sent again on a new connection
    assert_eq!(client.get(&server.url("/6")).unwrap().text(), "hello /6");
    assert_eq!(server.connections(), 2);
    assert!(client.h2_reads().0 > 0);
}

#[test]
fn a_goaway_that_comes_with_the_answer_to_a_request_that_is_read_by_its_caller_retires_the_connection() {
    let server = H2Server::start(|s| {
        if s.path() == "/bye" {
            let mut steps = hello(s);
            steps.push(Step::now(Action::GoAway { code: 0, last_stream: None }));
            steps
        } else {
            hello(s)
        }
    });
    let client = server.client();
    for i in 0..5 {
        client.get(&server.url(&format!("/{i}"))).unwrap();
    }
    assert_eq!(client.get(&server.url("/bye")).unwrap().text(), "hello /bye");
    wait_until("the connection to be retired", || client.idle_connections() == 0);
    assert_eq!(client.get(&server.url("/next")).unwrap().text(), "hello /next");
    assert_eq!(server.connections(), 2);
}

#[test]
fn a_connection_that_a_run_of_requests_used_is_closed_when_it_has_been_idle_long_enough() {
    let server = H2Server::start(hello);
    let client = server.client().pool_idle_timeout(Duration::from_millis(400));
    for i in 0..10 {
        client.get(&server.url(&format!("/{i}"))).unwrap();
    }
    assert!(client.h2_reads().0 > 0, "the requests were not read by their callers");
    assert_eq!(client.idle_connections(), 1);
    wait_until("the idle connection to be closed", || client.idle_connections() == 0);
    wait_until("the server to see it close", || server.ended_connections() == 1);
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_server_that_closes_an_idle_connection_that_was_used_in_a_run_is_noticed_when_the_reader_thread_is_back() {
    let server = H2Server::start(hello);
    let client = server.client();
    for i in 0..10 {
        client.get(&server.url(&format!("/{i}"))).unwrap();
    }
    server.close_all();
    wait_until("the client to notice", || client.idle_connections() == 0);
    assert_eq!(client.get(&server.url("/next")).unwrap().text(), "hello /next");
    assert_eq!(server.connections(), 2);
}

#[test]
fn a_whole_body_over_the_limit_is_cut_off_for_a_caller_who_reads_and_the_connection_survives() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client().max_body_bytes(100_000);
    for _ in 0..5 {
        client.get(&server.url("/n/10")).unwrap();
    }
    let err = client.get(&server.url("/n/3000000")).unwrap_err();
    assert!(err.to_string().contains("size limit"), "{err}");
    assert_eq!(client.get(&server.url("/n/10")).unwrap().body.len(), 10);
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_caller_who_reads_hands_the_socket_to_the_reader_thread_when_its_own_response_is_in() {
    // A's response comes at 50 ms, B's at 300 ms. A, whom nobody was reading for, reads; when A is done B, who has been
    // waiting for the reader thread, must be read for: B is answered at 300 ms, and not at whenever the reader thread
    // looks again by itself (a second, if it had to)
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let started = Instant::now();
    thread::scope(|scope| {
        let a = {
            let (client, server) = (&client, &server);
            scope.spawn(move || client.get(&server.url("/slow/50")).unwrap().text())
        };
        thread::sleep(Duration::from_millis(20));
        assert_eq!(client.get(&server.url("/slow/300")).unwrap().text(), "late");
        assert_eq!(a.join().unwrap(), "late");
    });
    let took = started.elapsed();
    assert!(took < Duration::from_millis(700), "took {took:?}");
}

/// Starts requests on `conn` until one has been given the right to read the socket (when nothing is in flight the reader thread
/// stays out of the way for a moment after the last request, see `PARK_WINDOW`; a loaded machine can make that moment pass, and
/// then the request that was started is finished and another is tried).
fn start_with_the_right_to_read(conn: &Arc<Shared>, request: &Request<'_>, waits: Waits) -> H2Stream {
    for _ in 0..200 {
        let mut s = conn.start(request, &[], waits).unwrap();
        if s.leads() {
            return s;
        }
        s.response(1000, waits).unwrap_or_else(|f| panic!("{f:?}"));
        thread::sleep(Duration::from_millis(1));
    }
    panic!("no request was given the right to read the socket when it started");
}

#[test]
fn the_right_to_read_goes_back_when_the_stream_that_took_it_is_answered_or_dropped() {
    let server = H2Server::start(hello);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    assert_eq!(conn.reading_caller(), None, "a caller kept the right after its request was answered");
    let authority = format!("127.0.0.1:{}", server.port);
    let request = Request { method: "GET", scheme: "https", authority: &authority, path: "/x", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    // a request takes the right when it starts, if nobody has it
    let stream = start_with_the_right_to_read(&conn, &request, waits);
    assert_eq!(conn.reading_caller(), Some((stream.id(), false)));
    // one that is given up unanswered gives the right back
    drop(stream);
    assert_eq!(conn.reading_caller(), None);

    // and one that is answered whole gives it back when it is
    let mut whole = start_with_the_right_to_read(&conn, &request, waits);
    let (head, body) = whole.response(1000, waits).unwrap();
    assert_eq!((head.status, body.as_slice()), (200, &b"hello /x"[..]));
    assert_eq!(conn.reading_caller(), None);
    drop(whole);
    assert_eq!(conn.reading_caller(), None);

    // a response that is read in pieces, by the only caller on the connection, keeps the right between the reads, paused
    let mut piecewise = start_with_the_right_to_read(&conn, &request, waits);
    let id = piecewise.id();
    assert_eq!(piecewise.head(waits).unwrap().status, 200);
    assert_eq!(conn.reading_caller(), Some((id, true)), "the right was not kept after the head");
    let mut out = [0u8; 64];
    let mut got = Vec::new();
    loop {
        let n = piecewise.read(&mut out, waits).unwrap();
        if n == 0 {
            break;
        }
        got.extend_from_slice(&out[..n]);
        // (kept while the body is not over, whether this read had to wait for the socket or not)
        if got.len() < 8 {
            assert_eq!(conn.reading_caller(), Some((id, true)));
        }
    }
    assert_eq!(got, b"hello /x");
    // the end of the body gives it back
    assert_eq!(conn.reading_caller(), None);
    drop(piecewise);

    // dropped half way, it gives it back too
    let mut half = start_with_the_right_to_read(&conn, &request, waits);
    half.head(waits).unwrap();
    assert_eq!(conn.reading_caller(), Some((half.id(), true)));
    drop(half);
    assert_eq!(conn.reading_caller(), None);
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
}

#[test]
fn a_caller_who_has_stopped_reading_loses_the_right_to_a_new_request() {
    let server = H2Server::start(hello);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let request = Request { method: "GET", scheme: "https", authority: &authority, path: "/y", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    let mut first = start_with_the_right_to_read(&conn, &request, waits);
    first.head(waits).unwrap();
    assert_eq!(conn.reading_caller(), Some((first.id(), true)));
    // a second request, on a connection whose right is a paused caller's, takes it: it has to wait for the network
    let mut second = conn.start(&request, &[], waits).unwrap();
    assert_eq!(conn.reading_caller(), Some((second.id(), false)));
    let (head, body) = second.response(1000, waits).unwrap();
    assert_eq!((head.status, body.as_slice()), (200, &b"hello /y"[..]));
    // the first, whose stream is not the only one in flight any more when it asks, is read for all the same
    let mut all = Vec::new();
    let mut out = [0u8; 64];
    loop {
        let n = first.read(&mut out, waits).unwrap();
        if n == 0 {
            break;
        }
        all.extend_from_slice(&out[..n]);
    }
    assert_eq!(all, b"hello /y");
    assert_eq!(conn.reading_caller(), None);
}

fn read_all(stream: &mut H2Stream, waits: Waits) -> Vec<u8> {
    let mut all = Vec::new();
    let mut out = [0u8; 4096];
    loop {
        let n = stream.read(&mut out, waits).unwrap_or_else(|f| panic!("{f:?}"));
        if n == 0 {
            return all;
        }
        all.extend_from_slice(&out[..n]);
    }
}

#[test]
fn a_download_read_in_pieces_is_read_by_its_caller() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let (before_callers, before_reader) = client.h2_reads();
    let mut s = client.get_stream(&server.url("/n/4000000")).unwrap();
    let mut body = Vec::new();
    s.read_to_end(&mut body).unwrap();
    assert!(body == pattern(4_000_000));
    drop(s);
    let (callers, reader) = client.h2_reads();
    let (callers, reader) = (callers - before_callers, reader - before_reader);
    // (the reader thread may have started the download, if the connection had been left alone for a moment)
    assert!(callers >= 5 && callers > 3 * reader, "callers read {callers} times, the reader thread {reader}");
    assert_eq!(server.connections(), 1);
}

/// Reads a download of `size` bytes in pieces of `piece`, checks it, and says how many of its bytes went straight into
/// the caller's buffer and how many through the stream's (B-87).
fn read_in_pieces(client: &crate::Client, server: &H2Server, size: usize, piece: usize) -> (usize, usize) {
    let (before_straight, before_kept) = client.h2_body_bytes();
    let mut s = client.get_stream(&server.url(&format!("/n/{size}"))).unwrap();
    let mut body = Vec::with_capacity(size);
    let mut buf = vec![0u8; piece];
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    assert!(body == pattern(size), "the body read in pieces of {piece}");
    drop(s);
    let (straight, kept) = client.h2_body_bytes();
    (straight - before_straight, kept - before_kept)
}

#[test]
fn a_download_read_in_pieces_goes_straight_into_the_callers_buffer() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    for piece in [1 << 20, 64 << 10, 4096, 100] {
        let (straight, kept) = read_in_pieces(&client, &server, 4_000_000, piece);
        assert_eq!(straight + kept, 4_000_000, "every byte is handed out once, one way or the other");
        assert!(straight > 0, "pieces of {piece}: nothing went straight to the caller");
        if piece >= 64 << 10 {
            // (the reader thread may have read the first piece)
            assert!(straight > kept, "pieces of {piece}: {straight} bytes went straight to the caller, {kept} through the stream");
        }
        eprintln!("pieces of {piece}: {straight} bytes straight, {kept} through the stream");
    }
    assert_eq!(server.connections(), 1);
}

#[test]
fn what_a_full_buffer_leaves_undecrypted_is_taken_in_by_whoever_reads_next() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let big = Request { method: "GET", scheme: "https", authority: &authority, path: "/n/4000000", headers: &[], secret: &[] };
    let small = Request { method: "GET", scheme: "https", authority: &authority, path: "/n/1000", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    // a download read in pieces smaller than a record, until a read leaves records it did not need in the receive buffer
    let mut download = start_with_the_right_to_read(&conn, &big, waits);
    download.head(waits).unwrap();
    let mut got = Vec::new();
    let mut out = [0u8; 1000];
    while conn.undigested() != Some(true) {
        let n = download.read(&mut out, waits).unwrap();
        assert!(n > 0 && got.len() < 4_000_000, "no read left anything in the receive buffer");
        got.extend_from_slice(&out[..n]);
    }
    // its caller stops for a while: another request on the connection takes the right to read, takes in what was left first,
    // and is answered as soon as its response comes after it (not when the reader thread takes over from the caller)
    let started = Instant::now();
    let before = conn.leftovers();
    let mut second = conn.start(&small, &[], waits).unwrap();
    let (head, body) = second.response(1 << 20, waits).unwrap();
    assert!(head.status == 200 && body == pattern(1000));
    assert!(started.elapsed() < Duration::from_millis(150), "the second request took {:?}", started.elapsed());
    assert!(conn.leftovers().0 > before.0, "the second request did not take in what was left");
    // and the download goes on where it was, whole and in order
    got.extend(read_all(&mut download, waits));
    assert!(got == pattern(4_000_000));
    // the same, with nobody else on the connection: the reader thread takes the right after a while, and in what was left
    let mut download = start_with_the_right_to_read(&conn, &big, waits);
    download.head(waits).unwrap();
    let mut got = Vec::new();
    while conn.undigested() != Some(true) {
        let n = download.read(&mut out, waits).unwrap();
        assert!(n > 0 && got.len() < 4_000_000, "no read left anything in the receive buffer");
        got.extend_from_slice(&out[..n]);
    }
    let before = conn.leftovers().1;
    wait_until("the reader thread to take in what was left", || conn.leftovers().1 > before);
    got.extend(read_all(&mut download, waits));
    assert!(got == pattern(4_000_000));
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_credit_for_bytes_read_straight_is_sent_at_once() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let big = Request { method: "GET", scheme: "https", authority: &authority, path: "/n/4000000", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };
    let mut download = start_with_the_right_to_read(&conn, &big, waits);
    download.head(waits).unwrap();
    let (straight, _) = client.h2_body_bytes();
    let mut got = 0;
    let mut out = vec![0u8; 64 << 10];
    loop {
        let n = download.read(&mut out, waits).unwrap();
        if n == 0 {
            break;
        }
        got += n;
        // the caller who read them sends what the read queued (the credit, every megabyte) before it returns, or has it sent:
        // nothing waits for something else to send it (the reader thread would, after a caller who stopped reading for
        // STALL, 200 ms)
        let since = Instant::now();
        while conn.output_queued() {
            assert!(since.elapsed() < Duration::from_millis(100), "the credit was not sent");
            thread::sleep(Duration::from_millis(1));
        }
    }
    assert_eq!(got, 4_000_000);
    assert!(client.h2_body_bytes().0 - straight > 2_000_000, "the download did not go straight to the caller");
}

#[test]
fn a_download_whose_caller_stops_reading_is_read_for_by_the_reader_thread_after_a_while() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let request = Request { method: "GET", scheme: "https", authority: &authority, path: "/trickle/100", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    let mut s = start_with_the_right_to_read(&conn, &request, waits);
    s.head(waits).unwrap();
    let mut first = [0u8; 5];
    let mut have = 0;
    while have < 5 {
        have += s.read(&mut first[have..], waits).unwrap();
    }
    assert_eq!(&first, b"first");
    assert_eq!(conn.reading_caller(), Some((s.id(), true)), "the caller did not keep the right between two reads");
    // the caller does something else for a while: the connection is read meanwhile, by the reader thread (the rest of the
    // body comes at 100 ms)
    // (the reader thread looks at it when it wakes up next: within a second)
    let before = client.h2_reads().1;
    let away = Instant::now();
    wait_until("the right to read to be taken from a caller who had stopped reading", || conn.reading_caller().is_none());
    assert!(away.elapsed() >= Duration::from_millis(150), "the right was taken from the caller after {:?}", away.elapsed());
    wait_until("the reader thread to read what the server sent meanwhile", || client.h2_reads().1 > before);
    // and the caller finds what came
    assert_eq!(read_all(&mut s, waits), b"second");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_request_that_waits_for_window_credit_takes_the_right_to_read_from_a_caller_who_stopped_reading() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let get = Request { method: "GET", scheme: "https", authority: &authority, path: "/trickle/250", headers: &[], secret: &[] };
    let post = Request { method: "POST", scheme: "https", authority: &authority, path: "/up", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    // a download whose caller is not reading for the moment
    let mut download = start_with_the_right_to_read(&conn, &get, waits);
    download.head(waits).unwrap();
    assert_eq!(conn.reading_caller(), Some((download.id(), true)));
    // an upload that is larger than the window the server gives has to wait for the server's WINDOW_UPDATEs, which somebody
    // has to read: it asks the reader thread to, at once, and not when the caller of the download is given up on
    let body = vec![7u8; 3_000_000];
    let started = Instant::now();
    let mut upload = conn.start(&post, &body, waits).unwrap();
    let took = started.elapsed();
    // (if it waited for the reader thread to take the right by itself, it would be a second, or two hundred milliseconds at best)
    assert!(took < Duration::from_millis(150), "the upload was held up for a caller who was not reading: {took:?}");
    let (head, text) = upload.response(1000, waits).unwrap();
    assert_eq!((head.status, text.as_slice()), (200, &b"hello /up"[..]));
    assert_eq!(read_all(&mut download, waits), b"firstsecond");
}

#[test]
fn a_streamed_read_that_the_server_leaves_hanging_times_out_on_time() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client().timeout(Duration::from_millis(400));
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let mut s = client.get_stream(&server.url("/hang")).unwrap();
    let mut buf = [0u8; 3];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"abc");
    let started = Instant::now();
    let err = s.read(&mut buf).unwrap_err();
    let took = started.elapsed();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err:?}");
    assert!(took >= Duration::from_millis(390) && took < Duration::from_millis(1200), "took {took:?}");
    drop(s);
    // the connection is not held up by it
    assert_eq!(client.get(&server.url("/quick")).unwrap().text(), "hello /quick");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_connection_cut_under_a_caller_who_reads_a_download_fails_the_read_and_is_replaced() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    let started = Instant::now();
    let mut s = client.get_stream(&server.url("/cutstream")).unwrap();
    let mut buf = [0u8; 4096];
    let mut got = 0usize;
    let err = loop {
        match s.read(&mut buf) {
            Ok(0) => panic!("the body ended after {got} bytes"),
            Ok(n) => got += n,
            Err(e) => break e,
        }
    };
    assert!(got <= 10_000, "{got}");
    assert!(matches!(err.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::Other | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    drop(s);
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
    assert_eq!(server.connections(), 2);
}

#[test]
fn a_download_that_pauses_does_not_hold_up_a_request_that_waits_for_the_reader_thread() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let download = Request { method: "GET", scheme: "https", authority: &authority, path: "/trickle/150", headers: &[], secret: &[] };
    let slow = Request { method: "GET", scheme: "https", authority: &authority, path: "/slow/100", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    let mut a = start_with_the_right_to_read(&conn, &download, waits);
    // a request that comes when a caller is reading does not take the right from it; it waits for whoever reads
    let mut b = conn.start(&slow, &[], waits).unwrap();
    assert_eq!(conn.reading_caller(), Some((a.id(), false)));
    let b_id = b.id();
    let started = Instant::now();
    let b = thread::spawn(move || {
        let (head, body) = b.response(1000, waits).unwrap();
        assert_eq!((head.status, body.as_slice()), (200, &b"late"[..]));
        started.elapsed()
    });
    thread::sleep(Duration::from_millis(20));
    // the download has its head and a first piece, and its caller stops reading: with another request in flight, which
    // somebody has to read for, it does not keep the right, but gives it to the caller who waits for that one (B-89)
    a.head(waits).unwrap();
    let mut first = [0u8; 5];
    let mut have = 0;
    while have < 5 {
        have += a.read(&mut first[have..], waits).unwrap();
    }
    assert_eq!(conn.reading_caller(), Some((b_id, false)), "a caller kept the right to read with another request waiting for the socket to be read");
    let took = b.join().unwrap();
    assert!(took < Duration::from_millis(600), "the other request took {took:?}");
    assert_eq!(read_all(&mut a, waits), b"second");
}

/// How many reads of the socket the callers made and how many the reader thread did while a download of `size` bytes was read
/// in pieces (after the pause, if the caller made one).
fn reads_for(client: &crate::Client, server: &H2Server, size: usize, pause_after: Option<(usize, Duration)>) -> (usize, usize) {
    let (mut before_callers, mut before_reader) = client.h2_reads();
    let mut s = client.get_stream(&server.url(&format!("/n/{size}"))).unwrap();
    let mut got = 0usize;
    let mut paused = false;
    let mut buf = vec![0u8; 8192];
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got += n;
        if let Some((at, pause)) = pause_after {
            if !paused && got >= at {
                paused = true;
                thread::sleep(pause);
                (before_callers, before_reader) = client.h2_reads();
            }
        }
    }
    assert_eq!(got, size);
    drop(s);
    let (callers, reader) = client.h2_reads();
    (callers - before_callers, reader - before_reader)
}

#[test]
fn a_download_that_starts_on_a_connection_left_alone_is_taken_over_by_its_caller() {
    // the reader thread is reading (the connection has been left alone for longer than it stays out of the way): it reads the
    // head and the first piece, tells the caller, and steps aside for it
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..3 {
        client.get(&server.url("/warm")).unwrap();
        thread::sleep(Duration::from_millis(80));
    }
    let (callers, reader) = reads_for(&client, &server, 4_000_000, None);
    assert!(callers >= 5 && callers > 5 * reader, "callers read {callers} times, the reader thread {reader}");
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_download_whose_caller_was_away_for_a_while_is_taken_over_by_its_caller_again() {
    // the caller stops for longer than the reader thread waits for it: the reader thread reads meanwhile, and when the
    // caller comes back and asks for more it is led again, and does not stay with the reader thread to the end
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    for _ in 0..5 {
        client.get(&server.url("/warm")).unwrap();
    }
    // (what the reader thread reads while the caller is away is the window's worth, which is not counted: only what comes after)
    let (callers, reader) = reads_for(&client, &server, 30_000_000, Some((1_000_000, Duration::from_millis(1500))));
    assert!(callers >= 5 && callers > 3 * reader, "callers read {callers} times, the reader thread {reader}");
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_reader_thread_does_not_step_aside_for_a_download_when_something_else_is_in_flight() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    // a download that is read in pieces, and a request that waits for its answer: the one who reads is the reader thread
    // (or the caller who leads), who must not stay out of the way for the download's caller
    let started = Instant::now();
    thread::scope(|scope| {
        let (client, server) = (&client, &server);
        let slow = scope.spawn(move || client.get(&server.url("/slow/150")).unwrap().text());
        for _ in 0..20 {
            let mut s = client.get_stream(&server.url("/trickle/5")).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            assert_eq!(out, b"firstsecond");
        }
        assert_eq!(slow.join().unwrap(), "late");
    });
    assert!(started.elapsed() < Duration::from_secs(2), "took {:?}", started.elapsed());
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_whole_download_on_a_connection_that_was_left_alone_is_not_held_up_by_the_reader_thread() {
    // the reader thread reads the first of it (the connection had been left alone), and must go on reading it: it does not
    // step aside for a caller who is not going to read, which a caller who sleeps until the response is whole is not
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    // (the first big transfer of a server is slow, whoever reads: it is not what is looked at)
    assert_eq!(client.get(&server.url("/n/12000000")).unwrap().body.len(), 12_000_000);
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let r = client.get(&server.url("/n/12000000")).unwrap();
    let took = started.elapsed();
    assert_eq!(r.body.len(), 12_000_000);
    // (a pause of the reader thread after each of its reads, which are of 256 KiB, would make it a second at least)
    assert!(took < Duration::from_millis(800), "took {took:?}");
}

#[test]
fn an_upload_that_waits_for_window_credit_on_a_connection_that_was_left_alone_is_not_held_up() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    assert_eq!(client.get(&server.url("/n/12000000")).unwrap().body.len(), 12_000_000);
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    let r = client.post(&server.url("/up"), vec![5u8; 30_000_000]).unwrap();
    let took = started.elapsed();
    assert_eq!(r.text(), "hello /up");
    assert!(took < Duration::from_millis(800), "took {took:?}");
}

#[test]
fn a_stream_that_is_dropped_does_not_take_the_right_to_read_from_another() {
    let server = H2Server::start(sizes_and_delays);
    let client = server.client();
    client.get(&server.url("/warm")).unwrap();
    let conn = client.h2.as_ref().unwrap().registry.any_connection().unwrap();
    let authority = format!("127.0.0.1:{}", server.port);
    let slow = Request { method: "GET", scheme: "https", authority: &authority, path: "/slow/200", headers: &[], secret: &[] };
    let other = Request { method: "GET", scheme: "https", authority: &authority, path: "/x", headers: &[], secret: &[] };
    let waits = Waits { timeout: Duration::from_secs(5), deadline: None };

    let a = start_with_the_right_to_read(&conn, &slow, waits);
    let b = conn.start(&other, &[], waits).unwrap();
    assert_eq!(conn.reading_caller(), Some((a.id(), false)));
    drop(b);
    assert_eq!(conn.reading_caller(), Some((a.id(), false)), "a stream that was given up took the right from the one that reads");
    let mut a = a;
    let (head, body) = a.response(1000, waits).unwrap();
    assert_eq!((head.status, body.as_slice()), (200, &b"late"[..]));
    assert_eq!(conn.reading_caller(), None);
}
