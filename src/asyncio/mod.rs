//! Asynchronous use of the client.
//!
//! The standard library has no asynchronous sockets, DNS or timers, and this crate has no
//! dependencies, so there is no event loop in here. What this module offers:
//!
//! * [`Pool`] and [`BlockingTask`]: run blocking work on worker threads and await it. The
//!   futures only use `std::task::Waker`, so they work with any executor (tokio, async-std,
//!   smol, a hand-written one, or [`block_on`]).
//! * The `*_async` methods on [`Client`](crate::Client) and
//!   [`RequestBuilder::send_async`](crate::http::RequestBuilder::send_async), which run the
//!   whole blocking request (DNS, proxy CONNECT, TLS, redirects, every timeout) on that pool.
//! * [`AsyncRead`] and [`AsyncWrite`] (poll-based, shaped like the `futures-io` traits) and
//!   [`AsyncTlsStream`], TLS 1.3 over any such transport, built on the sans-IO
//!   [`ClientConnection`](crate::tls::ClientConnection).
//! * [`sleep`], [`timeout`] and [`Timed`] (read and write timeouts and a deadline on any stream): timers on one thread of
//!   their own, for any executor.
//! * [`block_on`]: a tiny executor for tests, examples and simple programs.
//!
//! ```no_run
//! use pratique::{asyncio::block_on, Client};
//! let client = Client::new()?.proxy_from_env();
//! let resp = block_on(client.get_async("https://example.com/"))?;
//! println!("{}", resp.status);
//! # Ok::<(), pratique::error::Error>(())
//! ```

mod exec;
mod io;
pub(crate) mod net;
mod pool;
pub(crate) mod slots;
mod timer;
#[cfg(test)]
mod timer_tests;
mod tls;

pub use exec::block_on;
pub use io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub use net::ThreadedStream;
pub use pool::{BlockingTask, Pool, TaskError};
pub use timer::{sleep, sleep_until, timeout, timeout_at, Elapsed, Sleep, Timed, Timeout};
pub use tls::AsyncTlsStream;

/// Minimal join of several futures, for the tests: polls every pending one on each wake-up.
#[cfg(test)]
pub(crate) async fn join_all<F: std::future::Future + Unpin>(futs: Vec<F>) -> Vec<F::Output> {
    use std::pin::Pin;
    use std::task::Poll;
    let mut futs: Vec<_> = futs.into_iter().map(Some).collect();
    let mut out: Vec<Option<F::Output>> = futs.iter().map(|_| None).collect();
    std::future::poll_fn(move |cx| {
        let mut pending = false;
        for (i, slot) in futs.iter_mut().enumerate() {
            if let Some(f) = slot {
                match std::future::Future::poll(Pin::new(f), cx) {
                    Poll::Ready(v) => {
                        out[i] = Some(v);
                        *slot = None;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(out.iter_mut().map(|o| o.take().unwrap()).collect())
        }
    })
    .await
}
