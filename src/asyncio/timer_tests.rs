//! The timers: `sleep` is never early and not much late, many at once fire in order, a dropped one never fires, `timeout`
//! gives the future's output or `Elapsed`, and `Timed` puts read and write timeouts and a deadline on a stream that would
//! otherwise wait for ever, while a stream that keeps moving runs on.

use super::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use super::{block_on, join_all, sleep, sleep_until, timeout, timeout_at, Elapsed, Timed};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

/// How late a timer may be on a loaded test machine before the test says so.
const SLACK: Duration = Duration::from_millis(400);

#[test]
fn a_sleep_is_never_early_and_not_much_late() {
    for ms in [0u64, 1, 20, 120] {
        let d = Duration::from_millis(ms);
        let t0 = Instant::now();
        block_on(sleep(d));
        let took = t0.elapsed();
        assert!(took >= d, "{ms} ms took {took:?}");
        assert!(took < d + SLACK, "{ms} ms took {took:?}");
    }
    // a time that has passed is due at once
    let t0 = Instant::now();
    block_on(sleep_until(Instant::now() - Duration::from_secs(1)));
    assert!(t0.elapsed() < SLACK);
}

#[test]
fn many_sleeps_at_once_fire_in_the_order_of_their_deadlines() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let t0 = Instant::now();
    // registered in an order unlike their deadlines
    let futs: Vec<Pin<Box<dyn Future<Output = ()>>>> = [7u64, 2, 9, 0, 5, 1, 8, 3, 6, 4]
        .into_iter()
        .map(|k| {
            let order = order.clone();
            Box::pin(async move {
                sleep(Duration::from_millis(30 + 25 * k)).await;
                order.lock().unwrap().push(k);
            }) as Pin<Box<dyn Future<Output = ()>>>
        })
        .collect();
    block_on(join_all(futs));
    assert_eq!(*order.lock().unwrap(), (0..10).collect::<Vec<_>>());
    assert!(t0.elapsed() >= Duration::from_millis(255));
}

/// A waker that counts its wake-ups.
struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_dropped_sleep_never_wakes_anyone_and_a_kept_one_wakes_once() {
    let dropped = Arc::new(Counter(AtomicUsize::new(0)));
    let kept = Arc::new(Counter(AtomicUsize::new(0)));
    {
        let mut s = Box::pin(sleep(Duration::from_millis(50)));
        let w = Waker::from(dropped.clone());
        assert!(s.as_mut().poll(&mut Context::from_waker(&w)).is_pending());
    }
    let mut s = Box::pin(sleep(Duration::from_millis(50)));
    let w = Waker::from(kept.clone());
    assert!(s.as_mut().poll(&mut Context::from_waker(&w)).is_pending());
    thread::sleep(Duration::from_millis(50) + SLACK);
    assert_eq!(dropped.0.load(Ordering::SeqCst), 0);
    assert_eq!(kept.0.load(Ordering::SeqCst), 1);
    assert!(s.as_mut().poll(&mut Context::from_waker(&w)).is_ready());
}

#[test]
fn a_sleep_polled_with_a_new_waker_wakes_the_new_one_and_can_be_moved() {
    let first = Arc::new(Counter(AtomicUsize::new(0)));
    let second = Arc::new(Counter(AtomicUsize::new(0)));
    let mut s = Box::pin(sleep(Duration::from_millis(40)));
    assert!(s.as_mut().poll(&mut Context::from_waker(&Waker::from(first.clone()))).is_pending());
    assert!(s.as_mut().poll(&mut Context::from_waker(&Waker::from(second.clone()))).is_pending());
    thread::sleep(Duration::from_millis(40) + SLACK);
    assert_eq!((first.0.load(Ordering::SeqCst), second.0.load(Ordering::SeqCst)), (0, 1));
    // moved later, then sooner
    let mut s = Box::pin(sleep(Duration::from_secs(60)));
    let w = Waker::from(first.clone());
    assert!(s.as_mut().poll(&mut Context::from_waker(&w)).is_pending());
    s.reset(Instant::now() + Duration::from_millis(30));
    let t0 = Instant::now();
    block_on(s);
    assert!(t0.elapsed() < SLACK, "{:?}", t0.elapsed());
}

#[test]
fn timeout_gives_the_output_or_elapsed() {
    assert_eq!(block_on(timeout(Duration::from_secs(5), async { 7 })), Ok(7));
    let t0 = Instant::now();
    assert_eq!(block_on(timeout(Duration::from_millis(60), std::future::pending::<()>())), Err(Elapsed(())));
    let took = t0.elapsed();
    assert!(took >= Duration::from_millis(60) && took < Duration::from_millis(60) + SLACK, "{took:?}");
    // a future that finishes before the limit wins, even a slow one
    let r = block_on(timeout(Duration::from_millis(500), async {
        sleep(Duration::from_millis(50)).await;
        "done"
    }));
    assert_eq!(r, Ok("done"));
    assert_eq!(block_on(timeout_at(Instant::now() + Duration::from_millis(30), sleep(Duration::from_secs(60)))), Err(Elapsed(())));
    let e: io::Error = Elapsed(()).into();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
}

#[test]
fn timers_from_many_threads_at_once() {
    let handles: Vec<_> = (0..16)
        .map(|i| {
            thread::spawn(move || {
                for j in 0..20u64 {
                    let d = Duration::from_millis((i * 7 + j * 3) % 25);
                    let t0 = Instant::now();
                    block_on(sleep(d));
                    assert!(t0.elapsed() >= d);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// ------------------------------------------------------------------------------------------------ Timed

/// A stream whose reads hand out one byte every `every` (by its own timer), writes take everything after `every`, and
/// which waits for ever when `stuck` says so.
struct Slow {
    every: Duration,
    stuck: bool,
    timer: Option<super::Sleep>,
    written: usize,
}

impl Slow {
    fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.stuck {
            return Poll::Pending;
        }
        let t = self.timer.get_or_insert_with(|| sleep(self.every));
        match Pin::new(t).poll(cx) {
            Poll::Ready(()) => {
                self.timer = None;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for Slow {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.poll_tick(cx) {
            Poll::Ready(()) => {
                buf[0] = b'x';
                Poll::Ready(Ok(1))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Slow {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.poll_tick(cx) {
            Poll::Ready(()) => {
                self.written += buf.len();
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn slow(every_ms: u64, stuck: bool) -> Slow {
    Slow { every: Duration::from_millis(every_ms), stuck, timer: None, written: 0 }
}

#[test]
fn a_read_that_waits_too_long_times_out_and_one_that_keeps_moving_does_not() {
    let mut s = Timed::new(slow(0, true)).with_read_timeout(Duration::from_millis(80));
    let t0 = Instant::now();
    let e = block_on(s.read(&mut [0u8; 4])).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(e.to_string().contains("read"), "{e}");
    assert!(t0.elapsed() >= Duration::from_millis(80) && t0.elapsed() < Duration::from_millis(80) + SLACK);
    // a byte every 20 ms for 400 ms: each read waits far less than the limit, so the whole goes through
    let mut s = Timed::new(slow(20, false)).with_read_timeout(Duration::from_millis(150));
    let mut got = Vec::new();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(400) {
        let mut b = [0u8; 1];
        assert_eq!(block_on(s.read(&mut b)).unwrap(), 1);
        got.push(b[0]);
    }
    assert!(got.len() >= 10);
}

#[test]
fn the_deadline_ends_a_stream_that_keeps_moving() {
    let mut s = Timed::new(slow(20, false)).with_read_timeout(Duration::from_secs(10)).with_deadline(Instant::now() + Duration::from_millis(200));
    let t0 = Instant::now();
    let e = block_on(async {
        let mut b = [0u8; 1];
        loop {
            s.read(&mut b).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    })
    .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(e.to_string().contains("total time limit"), "{e}");
    assert!(t0.elapsed() >= Duration::from_millis(180) && t0.elapsed() < Duration::from_millis(200) + SLACK, "{:?}", t0.elapsed());
    // and past it nothing starts
    assert_eq!(block_on(s.read(&mut [0u8; 1])).unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn writes_flushes_and_closes_have_their_own_limit() {
    let mut s = Timed::new(slow(0, true)).with_write_timeout(Duration::from_millis(60)).with_read_timeout(Duration::from_secs(60));
    let e = block_on(s.write_all(b"hello")).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(e.to_string().contains("write"), "{e}");
    let mut s = Timed::new(slow(5, false)).with_write_timeout(Duration::from_millis(500));
    block_on(async {
        s.write_all(b"one").await?;
        s.write_all(b"two").await?;
        s.flush().await?;
        s.close().await
    })
    .unwrap();
    assert_eq!(s.get_ref().written, 6);
}

#[test]
fn without_limits_it_is_the_stream_as_it_is_and_limits_can_be_changed() {
    let mut s = Timed::new(slow(10, false));
    let mut b = [0u8; 1];
    assert_eq!(block_on(s.read(&mut b)).unwrap(), 1);
    // a stuck stream with no limit is still waiting after a while; with a limit set, it fails
    let mut s = Timed::new(slow(0, true));
    assert!(block_on(timeout(Duration::from_millis(100), s.read(&mut b))).is_err(), "no limit, no error: the outer timeout ends it");
    s.set_limits(Some(Duration::from_millis(50)), None, None);
    assert_eq!(block_on(s.read(&mut b)).unwrap_err().kind(), io::ErrorKind::TimedOut);
}
