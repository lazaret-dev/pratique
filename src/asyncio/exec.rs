//! A minimal single-future executor.

use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

struct Unpark {
    thread: Thread,
    woken: AtomicBool,
}

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

/// Runs `fut` to completion on the current thread, parking it between polls.
///
/// This is enough for tests, examples and small programs. It runs one future at a time; to run
/// many at once use a real executor, which can drive the futures from this crate as well.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let signal = Arc::new(Unpark { thread: thread::current(), woken: AtomicBool::new(false) });
    let waker = Waker::from(signal.clone());
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        // `park` may return spuriously, and a wake-up may have come in during the poll
        while !signal.woken.swap(false, Ordering::Acquire) {
            thread::park();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ready_and_chained_futures() {
        assert_eq!(block_on(async { 1 + 1 }), 2);
        assert_eq!(block_on(async { async { 5 }.await * 2 }), 10);
    }

    #[test]
    fn a_wake_from_another_thread_resumes_the_future() {
        // pending until a helper thread flips a flag and wakes the task
        let shared = Arc::new((std::sync::Mutex::new((false, None::<Waker>)), ()));
        let s2 = shared.clone();
        let helper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            let waker = {
                let mut g = s2.0.lock().unwrap();
                g.0 = true;
                g.1.take()
            };
            if let Some(w) = waker {
                w.wake();
            }
        });
        let out = block_on(std::future::poll_fn(move |cx| {
            let mut g = shared.0.lock().unwrap();
            if g.0 {
                Poll::Ready("done")
            } else {
                g.1 = Some(cx.waker().clone());
                Poll::Pending
            }
        }));
        assert_eq!(out, "done");
        helper.join().unwrap();
    }

    #[test]
    fn a_wake_that_arrives_during_the_poll_is_not_lost() {
        // the future wakes itself and then returns Pending: block_on must poll again, not park
        let mut first = true;
        let n = block_on(std::future::poll_fn(move |cx| {
            if first {
                first = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(7)
            }
        }));
        assert_eq!(n, 7);
    }
}
