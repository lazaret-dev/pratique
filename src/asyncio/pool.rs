//! A small pool of worker threads that turns blocking work into a [`Future`].
//!
//! The standard library has no asynchronous sockets, so the simplest way to use the blocking
//! client from async code without blocking the executor is to run each call on a worker thread
//! and wake the awaiting task when it finishes. The future works with any executor: it only uses
//! `std::task::Waker`.
//!
//! The pool starts threads on demand up to a limit, lets idle ones exit after a timeout, and
//! never runs a job whose future was dropped before a worker picked it up.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

/// Worker threads started at most, for [`Pool::global`].
const GLOBAL_MAX_THREADS: usize = 16;
/// How long an idle worker waits for work before it exits.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Why a task produced no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskError {
    /// The closure panicked; the payload's message, when it had one.
    Panicked(String),
    /// The job was discarded without running (its worker thread could not be started).
    Lost,
}

impl fmt::Display for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaskError::Panicked(m) => write!(f, "task panicked: {}", m),
            TaskError::Lost => write!(f, "task was discarded before it ran"),
        }
    }
}

impl std::error::Error for TaskError {}

impl From<TaskError> for crate::error::Error {
    fn from(e: TaskError) -> Self {
        crate::error::Error::Http(e.to_string())
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

struct State {
    queue: VecDeque<Job>,
    /// Worker threads alive.
    threads: usize,
    /// Of those, the ones waiting for work.
    idle: usize,
}

struct Inner {
    max_threads: usize,
    idle_timeout: Duration,
    state: Mutex<State>,
    work: Condvar,
}

/// A pool of worker threads for blocking work. Cheap to clone; clones share the threads.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool").field("max_threads", &self.inner.max_threads).finish()
    }
}

impl Pool {
    /// A pool that runs at most `max_threads` jobs at a time (at least one); further jobs wait
    /// in a queue. No thread is started until the first job.
    pub fn new(max_threads: usize) -> Pool {
        Pool::with_idle_timeout(max_threads, IDLE_TIMEOUT)
    }

    fn with_idle_timeout(max_threads: usize, idle_timeout: Duration) -> Pool {
        Pool {
            inner: Arc::new(Inner {
                max_threads: max_threads.max(1),
                idle_timeout,
                state: Mutex::new(State { queue: VecDeque::new(), threads: 0, idle: 0 }),
                work: Condvar::new(),
            }),
        }
    }

    /// The process-wide pool the async client methods use unless given another with
    /// `Client::pool` (up to 16 threads).
    pub fn global() -> Pool {
        static GLOBAL: OnceLock<Pool> = OnceLock::new();
        GLOBAL.get_or_init(|| Pool::new(GLOBAL_MAX_THREADS)).clone()
    }

    /// Worker threads currently alive (for tests and diagnostics).
    pub fn threads(&self) -> usize {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner()).threads
    }

    /// Runs `f` on a worker thread. The returned future is ready when `f` has returned (or
    /// panicked). Dropping the future before then abandons the task: if no worker has started it
    /// yet it is never run, otherwise it finishes in the background and its result is discarded.
    pub fn spawn_blocking<T, F>(&self, f: F) -> BlockingTask<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let shared = Arc::new(Shared { slot: Mutex::new(Slot { result: None, waker: None }), cancelled: AtomicBool::new(false) });
        let completer = Completer { shared: Some(shared.clone()) };
        let job: Job = Box::new(move || {
            let mut completer = completer;
            let shared = completer.shared.take().expect("completer is armed once");
            if shared.cancelled.load(Ordering::Acquire) {
                return;
            }
            let result = catch_unwind(AssertUnwindSafe(f)).map_err(|p| TaskError::Panicked(panic_message(&*p)));
            shared.finish(result);
        });
        self.submit(job);
        BlockingTask { shared }
    }

    fn submit(&self, job: Job) {
        let inner = &self.inner;
        let mut st = inner.state.lock().unwrap_or_else(|e| e.into_inner());
        st.queue.push_back(job);
        if st.idle >= st.queue.len() {
            // an idle worker is free for every queued job
            inner.work.notify_one();
        } else if st.threads < inner.max_threads {
            st.threads += 1;
            let worker = self.inner.clone();
            if thread::Builder::new().name("pratique-worker".into()).spawn(move || worker.run()).is_err() {
                st.threads -= 1;
                if st.threads == 0 {
                    // nothing will ever pick the jobs up: drop them, which completes their
                    // futures with TaskError::Lost
                    let lost: Vec<Job> = st.queue.drain(..).collect();
                    drop(st);
                    drop(lost);
                }
            }
        } else {
            inner.work.notify_one();
        }
    }
}

impl Inner {
    fn run(self: Arc<Self>) {
        loop {
            let job = {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if let Some(job) = st.queue.pop_front() {
                        break job;
                    }
                    st.idle += 1;
                    let (guard, timeout) = self.work.wait_timeout(st, self.idle_timeout).unwrap_or_else(|e| e.into_inner());
                    st = guard;
                    st.idle -= 1;
                    if timeout.timed_out() && st.queue.is_empty() {
                        st.threads -= 1;
                        return;
                    }
                }
            };
            job();
        }
    }
}

struct Slot<T> {
    result: Option<Result<T, TaskError>>,
    waker: Option<Waker>,
}

struct Shared<T> {
    slot: Mutex<Slot<T>>,
    cancelled: AtomicBool,
}

impl<T> Shared<T> {
    fn finish(&self, result: Result<T, TaskError>) {
        let waker = {
            let mut slot = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            slot.result = Some(result);
            slot.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

/// Completes the task with `Lost` if the job is dropped without having run.
struct Completer<T> {
    shared: Option<Arc<Shared<T>>>,
}

impl<T> Drop for Completer<T> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            shared.finish(Err(TaskError::Lost));
        }
    }
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "(no message)".to_string()
    }
}

/// The result of [`Pool::spawn_blocking`]: a future that is ready when the closure has returned.
///
/// It is `Send`, `'static` and woken through its `Waker`, so it works with any executor.
pub struct BlockingTask<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Future for BlockingTask<T> {
    type Output = Result<T, TaskError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut slot = self.shared.slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(result) = slot.result.take() {
            return Poll::Ready(result);
        }
        // Registered under the lock the worker takes before it sets the result, so a wake-up
        // cannot be lost between this check and the registration.
        match &slot.waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => slot.waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl<T> Drop for BlockingTask<T> {
    fn drop(&mut self) {
        self.shared.cancelled.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{block_on, join_all};
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn runs_a_closure_and_returns_its_value() {
        let pool = Pool::new(2);
        assert_eq!(block_on(pool.spawn_blocking(|| 6 * 7)), Ok(42));
    }

    #[test]
    fn a_panic_becomes_an_error_and_the_pool_keeps_working() {
        let pool = Pool::new(1);
        let r = block_on(pool.spawn_blocking(|| -> u8 { panic!("boom {}", 7) }));
        assert_eq!(r, Err(TaskError::Panicked("boom 7".into())));
        let r = block_on(pool.spawn_blocking(|| -> u8 { std::panic::panic_any(5u8) }));
        assert_eq!(r, Err(TaskError::Panicked("(no message)".into())));
        // the single worker survived both panics
        assert_eq!(block_on(pool.spawn_blocking(|| 1)), Ok(1));
        assert_eq!(pool.threads(), 1);
    }

    #[test]
    fn jobs_overlap_up_to_the_thread_limit() {
        // Four jobs each wait until all four are running: this only finishes if they really run
        // concurrently, so a pool that serialized them would hit the timeout.
        let pool = Pool::new(4);
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let tasks: Vec<_> = (0..4)
            .map(|i| {
                let b = barrier.clone();
                pool.spawn_blocking(move || {
                    b.wait();
                    i
                })
            })
            .collect();
        let started = Instant::now();
        let done = block_on(join_all(tasks));
        assert_eq!(done.into_iter().map(|r| r.unwrap()).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(pool.threads(), 4);
    }

    #[test]
    fn the_limit_is_respected_and_the_queue_drains() {
        let pool = Pool::new(2);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..12)
            .map(|_| {
                let (running, peak) = (running.clone(), peak.clone());
                pool.spawn_blocking(move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(5));
                    running.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for r in block_on(join_all(tasks)) {
            r.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert!(pool.threads() <= 2);
    }

    #[test]
    fn a_dropped_future_cancels_a_job_that_has_not_started() {
        let pool = Pool::new(1);
        let (release, wait) = mpsc::channel::<()>();
        let blocker = pool.spawn_blocking(move || {
            wait.recv().ok();
        });
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = ran.clone();
        let queued = pool.spawn_blocking(move || ran2.store(true, Ordering::SeqCst));
        drop(queued); // the only worker is busy, so this job is still in the queue
        release.send(()).unwrap();
        block_on(blocker).unwrap();
        // a job queued behind it has now certainly been looked at by the worker
        block_on(pool.spawn_blocking(|| ())).unwrap();
        assert!(!ran.load(Ordering::SeqCst), "a cancelled job still ran");
    }

    #[test]
    fn a_dropped_future_does_not_stop_a_running_job() {
        let pool = Pool::new(1);
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let (release, wait) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<u8>();
        let task = pool.spawn_blocking(move || {
            started_tx.send(()).unwrap();
            wait.recv().ok();
            done_tx.send(9).unwrap();
        });
        started_rx.recv().unwrap();
        drop(task);
        release.send(()).unwrap();
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(10)), Ok(9));
    }

    #[test]
    fn idle_workers_exit() {
        let pool = Pool::with_idle_timeout(3, Duration::from_millis(50));
        block_on(pool.spawn_blocking(|| ())).unwrap();
        assert_eq!(pool.threads(), 1);
        let deadline = Instant::now() + Duration::from_secs(10);
        while pool.threads() > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(pool.threads(), 0, "the idle worker did not exit");
        // and a new job starts a new worker
        assert_eq!(block_on(pool.spawn_blocking(|| 5)), Ok(5));
    }

    #[test]
    fn the_waker_is_called_from_the_worker() {
        // poll once by hand: Pending, then woken exactly when the job finishes
        use std::task::Wake;
        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let pool = Pool::new(1);
        let (release, wait) = mpsc::channel::<()>();
        let mut task = Box::pin(pool.spawn_blocking(move || {
            wait.recv().ok();
            3
        }));
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(task.as_mut().poll(&mut cx).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while count.0.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(task.as_mut().poll(&mut cx), Poll::Ready(Ok(3)));
    }
}
