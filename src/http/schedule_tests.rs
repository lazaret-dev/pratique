//! The scheduler and batches (BACKLOG B-74) through the clients, against the crate's own servers: the limits on requests
//! in flight hold for the blocking client, the `*_async` methods and the async client alike; hosts take turns; a request
//! is in flight until its response is over; the byte budget holds new requests back; a redirect moves to the other host;
//! a batch's deadline ends its requests; and a cancel stops them, waiting or under way, over HTTP/1.1 and HTTP/2.

use super::h2_server::{Action, Step};
use super::h2_testserver::H2Server;
use super::testserver::*;
use super::{Batch, Scheduler};
use crate::asyncio::block_on;
use crate::error::Error;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// A handler that counts the requests it is answering at once (the most at any time in `peak`), taking `ms` for each.
fn counting(now: Arc<AtomicUsize>, peak: Arc<AtomicUsize>, ms: u64) -> impl Fn(&Seen) -> Reply + Send + Sync + 'static {
    move |seen| {
        let n = now.fetch_add(1, Ordering::SeqCst) + 1;
        peak.fetch_max(n, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(ms));
        now.fetch_sub(1, Ordering::SeqCst);
        ok(&format!("hello {}", seen.path()))
    }
}

fn big_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A handler that answers `/big` with 200 KB and anything else at once, after `ms`, with "slow" for `/slow`.
fn shapes(seen: &Seen) -> Reply {
    match seen.path() {
        "/big" => Reply::Send(response(200, &[], &big_body(200_000))),
        "/slow" => {
            thread::sleep(Duration::from_millis(1500));
            ok("slow")
        }
        p => ok(&format!("hello {p}")),
    }
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < give_up, "waited too long for {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn at_most_the_limit_in_flight_from_threads_the_pool_and_the_async_client_together() {
    let (now, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let server = TestServer::start(counting(now.clone(), peak.clone(), 30));
    let sched = Scheduler::new().max_in_flight(3);
    let client = server.client().scheduler(&sched);
    let asynchronous = client.clone().into_async();
    let mut threads = Vec::new();
    for t in 0..4 {
        let (c, url) = (client.clone(), server.url(&format!("/t{t}")));
        threads.push(thread::spawn(move || (0..3).for_each(|_| assert_eq!(c.get(&url).unwrap().status, 200))));
        let (c, url) = (asynchronous.clone(), server.url(&format!("/a{t}")));
        threads.push(thread::spawn(move || (0..3).for_each(|_| assert_eq!(block_on(c.get(&url)).unwrap().status, 200))));
    }
    // and the thread pool's futures
    let futures: Vec<_> = (0..6).map(|i| client.get_async(&server.url(&format!("/p{i}")))).collect();
    for f in futures {
        assert_eq!(block_on(f).unwrap().status, 200);
    }
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(server.requests().len(), 30);
    assert_eq!(peak.load(Ordering::SeqCst), 3, "never more than three at the server, and three at times");
    assert_eq!((sched.in_flight(), sched.waiting(), sched.bytes_in_flight()), (0, 0, 0));
}

#[test]
fn hosts_take_turns_so_a_long_queue_does_not_hold_up_another_host() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let logged = |name: &'static str, log: &Arc<Mutex<Vec<String>>>| {
        let log = log.clone();
        move |seen: &Seen| {
            log.lock().unwrap().push(format!("{name}{}", seen.path()));
            if seen.path() == "/big" {
                return Reply::Send(response(200, &[], &big_body(200_000)));
            }
            thread::sleep(Duration::from_millis(10));
            ok("x")
        }
    };
    let (a, b) = (TestServer::start(logged("a", &log)), TestServer::start(logged("b", &log)));
    let sched = Scheduler::new().max_in_flight(1);
    let client = a.client().scheduler(&sched);
    // one request holds the only place while the others queue: four for a, then one for b
    let held = client.get_stream(&a.url("/big")).unwrap();
    let mut threads = Vec::new();
    for (server, path) in [(&a, "/1"), (&a, "/2"), (&a, "/3"), (&a, "/4"), (&b, "/1")] {
        let (c, url) = (client.clone(), server.url(path));
        threads.push(thread::spawn(move || c.get(&url).unwrap().status));
        let queued = threads.len();
        wait_until("the request to queue", || sched.waiting() == queued);
    }
    drop(held);
    for t in threads {
        assert_eq!(t.join().unwrap(), 200);
    }
    assert_eq!(*log.lock().unwrap(), ["a/big", "a/1", "b/1", "a/2", "a/3", "a/4"], "b's turn came after a's first, not after all of a's");
}

#[test]
fn a_request_is_in_flight_until_its_response_is_over_and_no_longer() {
    let server = TestServer::start(shapes);
    let sched = Scheduler::new().max_in_flight(1).max_in_flight_per_host(1);
    let client = server.client().scheduler(&sched);
    let mut stream = client.get_stream(&server.url("/big")).unwrap();
    assert_eq!(sched.in_flight(), 1);
    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    assert_eq!(body.len(), 200_000);
    assert_eq!(sched.in_flight(), 0, "read to its end: over, though the stream is still there");
    drop(stream);
    // a stream dropped half read gives its place back too
    let mut stream = client.get_stream(&server.url("/big")).unwrap();
    stream.read_exact(&mut [0u8; 1000]).unwrap();
    assert_eq!(sched.in_flight(), 1);
    drop(stream);
    assert_eq!(sched.in_flight(), 0);
    // a whole response is over when the call returns, and a failed request gives its place back
    client.get(&server.url("/small")).unwrap();
    assert_eq!(sched.in_flight(), 0);
    let e = client.request("GET", &server.url("/big")).max_body_bytes(10).send().unwrap_err();
    assert!(e.to_string().contains("limit"), "{e}");
    assert_eq!(sched.in_flight(), 0);
}

#[test]
fn the_byte_budget_holds_new_requests_back_while_a_large_body_is_coming() {
    let server = TestServer::start(shapes);
    let sched = Scheduler::new().byte_budget(100_000);
    let client = server.client().scheduler(&sched);
    let mut big = client.get_stream(&server.url("/big")).unwrap();
    assert_eq!(sched.bytes_in_flight(), 200_000, "the head said how long the body is");
    let (c, url) = (client.clone(), server.url("/small"));
    let small = thread::spawn(move || c.request("GET", &url).expected_bytes(10).send().unwrap().status);
    wait_until("the small request to wait", || sched.waiting() == 1);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(server.requests().len(), 1, "the small request has not gone out");
    let mut body = Vec::new();
    big.read_to_end(&mut body).unwrap();
    assert_eq!(small.join().unwrap(), 200);
    assert_eq!(sched.bytes_in_flight(), 0);
    // an estimate is held until the head says how long the body is
    let held = client.request("GET", &server.url("/small")).expected_bytes(80_000).send_stream().unwrap();
    assert_eq!(sched.bytes_in_flight(), 0, "a body that was read with its head is over at once");
    drop(held);
}

#[test]
fn a_redirect_moves_to_the_other_hosts_place() {
    let target = TestServer::start(shapes);
    let to = target.url("/big");
    let origin = TestServer::start(move |seen| match seen.path() {
        "/go" => Reply::Send(response(302, &[&format!("Location: {to}")], b"")),
        _ => ok("origin"),
    });
    let sched = Scheduler::new().max_in_flight(10).max_in_flight_per_host(1);
    let client = origin.client().scheduler(&sched);
    let stream = client.get_stream(&origin.url("/go")).unwrap();
    assert_eq!(stream.url.port, target.port);
    assert_eq!(sched.in_flight(), 1);
    // the origin's place was given back: another request to it goes at once
    assert_eq!(client.get(&origin.url("/again")).unwrap().text(), "origin");
    // the target's is held by the redirected request until its body is over
    let (c, url) = (client.clone(), target.url("/x"));
    let other = thread::spawn(move || c.get(&url).unwrap().text());
    wait_until("the request to the target to wait", || sched.waiting() == 1);
    drop(stream);
    assert_eq!(other.join().unwrap(), "hello /x");
}

#[test]
fn a_batch_deadline_ends_the_wait_and_the_requests_under_way() {
    let server = TestServer::start(shapes);
    let sched = Scheduler::new().max_in_flight(1);
    let client = server.client().scheduler(&sched);
    let held = client.get_stream(&server.url("/big")).unwrap();
    let batch = Batch::with_timeout(Duration::from_millis(200));
    let t = Instant::now();
    let e = client.in_batch(&batch).get(&server.url("/small")).unwrap_err();
    assert!(e.to_string().contains("total time limit"), "{e}");
    assert!(t.elapsed() >= Duration::from_millis(150) && t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(sched.waiting(), 0);
    drop(held);
    // under way: the slow answer takes 1.5 s, the batch gives it 200 ms
    let batch = Batch::with_timeout(Duration::from_millis(200));
    let t = Instant::now();
    let e = client.request("GET", &server.url("/slow")).batch(&batch).send().unwrap_err();
    assert!(e.to_string().contains("total time limit"), "{e}");
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
}

#[test]
fn a_cancel_stops_waiting_and_running_requests_and_fails_new_ones() {
    let server = TestServer::start(shapes);
    let sched = Scheduler::new().max_in_flight(2);
    let client = server.client().scheduler(&sched);
    let batch = Batch::new();
    let in_batch = client.in_batch(&batch);
    // one under way, waiting for a slow answer; one under way, reading a body; one waiting for a place
    let (c, url) = (in_batch.clone(), server.url("/slow"));
    let slow = thread::spawn(move || c.get(&url).unwrap_err());
    let mut reading = in_batch.get_stream(&server.url("/big")).unwrap();
    reading.read_exact(&mut [0u8; 100]).unwrap();
    let (c, url) = (in_batch.clone(), server.url("/small"));
    let waiting = thread::spawn(move || c.get(&url).unwrap_err());
    wait_until("one to wait", || sched.waiting() == 1);
    wait_until("the slow one to reach the server", || server.requests().iter().any(|s| s.path() == "/slow"));
    let t = Instant::now();
    batch.cancel();
    assert!(matches!(slow.join().unwrap(), Error::Cancelled));
    assert!(matches!(waiting.join().unwrap(), Error::Cancelled));
    assert!(t.elapsed() < Duration::from_millis(1000), "{:?}", t.elapsed());
    let e = reading.read_to_end(&mut Vec::new()).unwrap_err();
    assert!(e.to_string().contains("cancelled"), "{e}");
    assert!(matches!(in_batch.get(&server.url("/small")).unwrap_err(), Error::Cancelled), "a request made after the cancel");
    assert_eq!((sched.in_flight(), sched.waiting()), (0, 0));
    // the client itself, and another batch, go on
    assert_eq!(client.get(&server.url("/after")).unwrap().text(), "hello /after");
    assert_eq!(client.request("GET", &server.url("/other")).batch(&Batch::new()).send().unwrap().status, 200);
}

#[test]
fn a_cancel_stops_the_async_client_and_the_pools_futures() {
    let server = TestServer::start(shapes);
    let client = server.client();
    let batch = Batch::new();
    let asynchronous = client.clone().into_async();
    let (c, url, b) = (asynchronous.clone(), server.url("/slow"), batch.clone());
    let task = thread::spawn(move || block_on(c.request("GET", &url).batch(&b).send()).unwrap_err());
    let pooled = client.in_batch(&batch).get_async(&server.url("/slow"));
    wait_until("both to reach the server", || server.requests().iter().filter(|s| s.path() == "/slow").count() == 2);
    let t = Instant::now();
    batch.cancel();
    assert!(matches!(task.join().unwrap(), Error::Cancelled));
    assert!(matches!(block_on(pooled).unwrap_err(), Error::Cancelled));
    assert!(t.elapsed() < Duration::from_millis(1000), "{:?}", t.elapsed());
    // a streamed async body
    let batch = Batch::new();
    let mut stream = block_on(asynchronous.request("GET", &server.url("/big")).batch(&batch).send_stream()).unwrap();
    batch.cancel();
    let e = block_on(stream.copy_to(&mut Vec::new())).unwrap_err();
    assert!(matches!(e, Error::Cancelled), "{e}");
}

#[test]
fn a_cancel_stops_an_http2_request_and_leaves_the_connection_to_the_others() {
    let server = H2Server::start(|s| {
        let delay = if s.path() == "/slow" { Duration::from_secs(5) } else { Duration::ZERO };
        let body = s.path().as_bytes().to_vec();
        vec![
            Step::later(delay, Action::Head { status: 200, headers: vec![("content-length".into(), body.len().to_string())], end: false }),
            Step::now(Action::Data(body)),
            Step::now(Action::End),
        ]
    });
    let client = server.client();
    assert_eq!(client.get(&server.url("/first")).unwrap().text(), "/first");
    let batch = Batch::new();
    let (c, url, b) = (client.clone(), server.url("/slow"), batch.clone());
    let slow = thread::spawn(move || c.request("GET", &url).batch(&b).send().unwrap_err());
    wait_until("the slow one to reach the server", || server.requests().iter().any(|s| s.path() == "/slow"));
    thread::sleep(Duration::from_millis(50));
    let t = Instant::now();
    batch.cancel();
    assert!(matches!(slow.join().unwrap(), Error::Cancelled));
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    // the connection carries on
    assert_eq!(client.get(&server.url("/next")).unwrap().text(), "/next");
    assert_eq!(server.connections(), 1);
}
