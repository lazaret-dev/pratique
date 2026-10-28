//! Cancellable, bounded UDP/TCP client sockets using nonblocking operating-system I/O.
//!
//! Literal addresses only: no hidden blocking hostname resolution. The existing timer
//! wakes a stalled operation after 2 ms; no worker, queue or detached socket operation
//! survives dropping its owner. Every successful operation yields once before its next
//! syscall, allowing enclosing deadlines to run even under continuous traffic.
//! TCP connection initiation is supported on Linux and macOS; other targets return
//! `Unsupported`. UDP and already-connected TCP wrapping use the standard library.
use super::{sleep, yield_now, AsyncRead, AsyncWrite, Sleep};
use std::future::{poll_fn, Future};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;

mod connect;
const RETRY_DELAY: Duration = Duration::from_millis(2);

#[derive(Debug)]
struct Budget {
    limit: usize,
    used: AtomicUsize,
}

/// Shared hard cap on live sockets, including in-progress TCP connections.
/// Capacity exhaustion fails immediately with `WouldBlock`; there is no wait queue.
/// Clones share the cap. A permit is returned when its socket is dropped.
#[derive(Clone, Debug)]
pub struct SocketBudget(Arc<Budget>);
impl SocketBudget {
    pub fn new(limit: usize) -> io::Result<Self> {
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket budget must be nonzero",
            ));
        }
        Ok(Self(Arc::new(Budget {
            limit,
            used: AtomicUsize::new(0),
        })))
    }
    pub fn in_use(&self) -> usize {
        self.0.used.load(Ordering::Acquire)
    }
    pub fn limit(&self) -> usize {
        self.0.limit
    }
    fn reserve(&self) -> io::Result<Permit> {
        let mut used = self.0.used.load(Ordering::Acquire);
        loop {
            if used >= self.0.limit {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "socket budget exhausted",
                ));
            }
            match self.0.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Ok(Permit(self.0.clone()))
    }
    /// Bind a nonblocking UDP socket without resolving a hostname.
    pub fn udp_bind(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let permit = self.reserve()?;
        let socket = std::net::UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(UdpSocket {
            socket,
            _permit: permit,
        })
    }
    /// Initiate a nonblocking connection. Wrap this future in `timeout`/`timeout_at`.
    /// Dropping the future closes its pending connection and releases its permit.
    pub async fn tcp_connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        yield_now().await;
        let permit = self.reserve()?;
        let socket = connect::start(address)?;
        let mut wait = Wait::default();
        poll_fn(|cx| {
            wait.poll(cx, || {
                if connect::ready(&socket)? {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            })
        })
        .await?;
        Ok(TcpStream {
            socket,
            reading: Wait::default(),
            writing: Wait::default(),
            _permit: permit,
        })
    }
    /// Wrap an owned, connected socket. It is put into nonblocking mode.
    pub fn tcp_from_std(&self, socket: std::net::TcpStream) -> io::Result<TcpStream> {
        let permit = self.reserve()?;
        socket.peer_addr()?;
        socket.set_nonblocking(true)?;
        Ok(TcpStream {
            socket,
            reading: Wait::default(),
            writing: Wait::default(),
            _permit: permit,
        })
    }
}
struct Permit(Arc<Budget>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Wait {
    timer: Option<Sleep>,
    yield_due: bool,
}
impl Default for Wait {
    fn default() -> Self {
        Self {
            timer: None,
            yield_due: true,
        }
    }
}
impl Wait {
    fn poll<T>(
        &mut self,
        cx: &mut Context<'_>,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if let Some(timer) = &mut self.timer {
            if Pin::new(timer).poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.timer = None;
        }
        match operation() {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                let mut timer = sleep(RETRY_DELAY);
                // Timer startup failure must still yield to the caller's deadline.
                if Pin::new(&mut timer).poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
                self.timer = Some(timer);
                Poll::Pending
            }
            result => {
                self.yield_due = true;
                Poll::Ready(result)
            }
        }
    }
}

/// Owned nonblocking UDP socket. Connected receives accept only the chosen peer.
pub struct UdpSocket {
    socket: std::net::UdpSocket,
    _permit: Permit,
}
impl UdpSocket {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
    pub fn connect(&self, peer: SocketAddr) -> io::Result<()> {
        self.socket.connect(peer)
    }
    pub async fn send(&self, bytes: &[u8]) -> io::Result<usize> {
        let mut wait = Wait::default();
        poll_fn(|cx| wait.poll(cx, || self.socket.send(bytes))).await
    }
    pub async fn recv(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut wait = Wait::default();
        poll_fn(|cx| wait.poll(cx, || self.socket.recv(bytes))).await
    }
    pub async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let mut wait = Wait::default();
        poll_fn(|cx| wait.poll(cx, || self.socket.send_to(bytes, peer))).await
    }
    pub async fn recv_from(&self, bytes: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wait = Wait::default();
        poll_fn(|cx| wait.poll(cx, || self.socket.recv_from(bytes))).await
    }
}

/// Owned nonblocking TCP socket implementing Pratique's async I/O traits.
/// Writes go directly to the socket; no background buffered write remains on drop.
pub struct TcpStream {
    socket: std::net::TcpStream,
    reading: Wait,
    writing: Wait,
    _permit: Permit,
}
impl TcpStream {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}
impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.reading.poll(cx, || (&this.socket).read(bytes))
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.writing.poll(cx, || (&this.socket).write(bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(match self.socket.shutdown(Shutdown::Write) {
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(()),
            result => result,
        })
    }
}
