//! The per-host connection limit (BACKLOG B-48, `Client::max_connections_per_host`) through the clients, against the
//! crate's own servers: that no more connections are open to a host than the limit, that a request waits for one to
//! come back (and uses it) or to close, that it closes an idle one it cannot use to make room, that it gives up at its
//! time and says why, and that an HTTP/2 connection holds one slot and gives it back when it ends. (Name resolution and
//! the racing of addresses are tested in `connect`.)

use super::h2_server::{Action, Step};
use super::h2_testserver::H2Server;
use super::testserver::*;
use crate::asyncio::block_on;
use crate::tls::TlsVersion;
use std::io::Read;
use std::thread;
use std::time::{Duration, Instant};

fn slow_hello(seen: &Seen) -> Reply {
    thread::sleep(Duration::from_millis(30));
    ok(&format!("hello {}", seen.path()))
}

fn big_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A response with a body large enough that its end is not read along with its head.
fn big(_: &Seen) -> Reply {
    Reply::Send(response(200, &[], &big_body(2_000_000)))
}

#[test]
fn no_more_connections_to_a_host_than_the_limit_and_the_others_wait_for_one_to_come_back() {
    for tls in [false, true] {
        let server = if tls { TestServer::start_tls(slow_hello) } else { TestServer::start(slow_hello) };
        let client = server.client().max_connections_per_host(2);
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let (client, url) = (client.clone(), server.url(&format!("/{t}")));
                thread::spawn(move || {
                    for _ in 0..3 {
                        assert_eq!(client.get(&url).unwrap().status, 200);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(server.requests().len(), 24);
        assert_eq!(server.connections(), 2, "tls {tls}: two connections, each used again and again");
        assert_eq!(client.idle_connections(), 2);
        // a client without the limit opens more for the same burst
        let free = server.client();
        let threads: Vec<_> = (0..8).map(|t| {
            let (client, url) = (free.clone(), server.url(&format!("/{t}")));
            thread::spawn(move || client.get(&url).unwrap().status)
        }).collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(server.connections() > 4, "tls {tls}: {}", server.connections());
    }
}

#[test]
fn a_request_that_cannot_get_a_connection_in_time_says_why_and_a_closed_one_gives_its_slot_back() {
    let server = TestServer::start(big);
    let client = server.client().max_connections_per_host(1).timeout(Duration::from_millis(300));
    let held = client.get_stream(&server.url("/held")).unwrap();
    let t = Instant::now();
    let e = client.get(&server.url("/waits")).unwrap_err().to_string();
    assert!(e.contains("no connection to 127.0.0.1:") && e.contains("max_connections_per_host"), "{e}");
    assert!(t.elapsed() >= Duration::from_millis(300) && t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    // the stream is dropped half read: its connection closes, and its slot is free
    drop(held);
    assert_eq!(client.get(&server.url("/next")).unwrap().body.len(), 2_000_000);
    assert_eq!(server.connections(), 2);
    // with a total timeout, the wait ends with it
    let client = client.total_timeout(Duration::from_millis(200)).timeout(Duration::from_secs(5));
    let _held = client.get_stream(&server.url("/held")).unwrap();
    let e = client.get(&server.url("/waits")).unwrap_err().to_string();
    assert!(e.contains("total time limit"), "{e}");
}

#[test]
fn a_connection_that_comes_back_to_the_pool_is_used_by_the_request_that_waited() {
    for tls in [false, true] {
        let server = if tls { TestServer::start_tls(big) } else { TestServer::start(big) };
        let client = server.client().max_connections_per_host(1);
        let mut held = client.get_stream(&server.url("/first")).unwrap();
        let reader = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let mut body = Vec::new();
            held.read_to_end(&mut body).unwrap();
            body.len()
        });
        let t = Instant::now();
        assert_eq!(client.get(&server.url("/second")).unwrap().body.len(), 2_000_000);
        assert!(t.elapsed() >= Duration::from_millis(100), "tls {tls}: it waited");
        assert_eq!(reader.join().unwrap(), 2_000_000);
        assert_eq!(server.connections(), 1, "tls {tls}: the waiting request took the connection that came back");
    }
}

#[test]
fn an_idle_connection_the_request_cannot_use_is_closed_to_make_room() {
    let server = TestServer::start_tls(slow_hello);
    let client = server.client().max_connections_per_host(1);
    assert_eq!(client.get(&server.url("/a")).unwrap().status, 200);
    assert_eq!(client.idle_connections(), 1);
    // a request that requires TLS 1.3 cannot use a connection made for one that allows 1.2 (it might be a TLS 1.2 one)
    let r = client.request("GET", &server.url("/b")).min_tls_version(TlsVersion::Tls13).send().unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(server.connections(), 2, "the idle connection was closed and a new one made");
    assert_eq!(client.idle_connections(), 1);
    // another host (another port) is counted apart
    let (one, two) = (TestServer::start(slow_hello), TestServer::start(slow_hello));
    let client = one.client().max_connections_per_host(1);
    client.get(&one.url("/c")).unwrap();
    client.get(&two.url("/d")).unwrap();
    assert_eq!(client.idle_connections(), 2);
}

#[test]
fn the_async_client_keeps_the_limit_too() {
    let server = TestServer::start(slow_hello);
    let client = server.client().max_connections_per_host(2).into_async();
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let (client, url) = (client.clone(), server.url(&format!("/{t}")));
            thread::spawn(move || {
                for _ in 0..3 {
                    assert_eq!(block_on(client.get(&url)).unwrap().status, 200);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(server.requests().len(), 24);
    assert_eq!(server.connections(), 2);
    // and gives up in time, saying why
    let server = TestServer::start(big);
    let client = server.client().max_connections_per_host(1).timeout(Duration::from_millis(300)).into_async();
    let _held = block_on(client.request("GET", &server.url("/held")).send_stream()).unwrap();
    let e = block_on(client.get(&server.url("/waits"))).unwrap_err().to_string();
    assert!(e.contains("max_connections_per_host"), "{e}");
}

#[test]
fn an_http2_connection_holds_one_slot_and_gives_it_back_when_it_ends() {
    let server = H2Server::start(|s| {
        if s.path() == "/hang" {
            // a head, and then nothing
            return vec![Step::now(Action::Head { status: 200, headers: vec![], end: false })];
        }
        // each answer comes a little later, so that the requests overlap
        let body = s.path().as_bytes().to_vec();
        let mut steps = vec![
            Step::later(Duration::from_millis(20), Action::Head { status: 200, headers: vec![("content-length".into(), body.len().to_string())], end: false }),
            Step::now(Action::Data(body)),
            Step::now(Action::End),
        ];
        if s.path() == "/goaway" {
            steps.push(Step::now(Action::GoAway { code: 0, last_stream: None }));
        }
        steps
    });
    let client = server.client().max_connections_per_host(1);
    let threads: Vec<_> = (0..6)
        .map(|t| {
            let (client, url) = (client.clone(), server.url(&format!("/{t}")));
            thread::spawn(move || client.get(&url).unwrap().text())
        })
        .collect();
    for (t, h) in threads.into_iter().enumerate() {
        assert_eq!(h.join().unwrap(), format!("/{t}"));
    }
    assert_eq!(server.connections(), 1, "one connection carried them all");
    // the server retires the connection: the next request gets a new one, the slot having been given back
    assert_eq!(client.get(&server.url("/goaway")).unwrap().text(), "/goaway");
    let t = Instant::now();
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "/after");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(server.connections(), 2);
    // a connection that ends while a caller still holds one of its streams gives its slot back when it ends, not when the
    // stream is dropped
    let held = client.get_stream(&server.url("/hang")).unwrap();
    server.close_all();
    let t = Instant::now();
    assert_eq!(client.get(&server.url("/last")).unwrap().text(), "/last");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(server.connections(), 3);
    drop(held);
}

#[test]
fn a_host_whose_first_address_does_not_answer_is_reached_through_the_next_in_a_quarter_of_a_second() {
    use std::net::{IpAddr, Ipv4Addr};
    let server = TestServer::start(slow_hello);
    let hole_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let Some((_hole, _queued)) = super::connect::tests::black_hole(hole_ip, server.port) else {
        eprintln!("no black hole can be made on this system: skipped");
        return;
    };
    // the name gives the address that does not answer first, as a broken IPv6 route would be
    let lookup: std::sync::Arc<dyn Fn(&str) -> std::io::Result<Vec<IpAddr>> + Send + Sync> =
        std::sync::Arc::new(move |_: &str| Ok(vec![hole_ip, IpAddr::V4(Ipv4Addr::LOCALHOST)]));
    let mut client = server.client().keep_alive(false).connect_timeout(Duration::from_secs(10));
    client.establish.resolver = std::sync::Arc::new(super::connect::Resolver::with_lookup(Duration::from_secs(30), lookup));
    let url = format!("http://dual.test:{}/x", server.port);
    let t = Instant::now();
    assert_eq!(client.get(&url).unwrap().text(), "hello /x");
    let took = t.elapsed();
    assert!(took >= Duration::from_millis(250) && took < Duration::from_secs(2), "{took:?}");
    // the address that answered is tried first from now on
    let t = Instant::now();
    assert_eq!(client.get(&url).unwrap().text(), "hello /x");
    assert!(t.elapsed() < Duration::from_millis(250), "{:?}", t.elapsed());
    // and the async client, through its connector, shares the resolver
    let t = Instant::now();
    assert_eq!(block_on(client.clone().into_async().get(&url)).unwrap().text(), "hello /x");
    assert!(t.elapsed() < Duration::from_millis(250), "{:?}", t.elapsed());
}
