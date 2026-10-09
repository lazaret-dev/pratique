//! Poll-based `AsyncRead` and `AsyncWrite`, with the same shape as the traits of the `futures-io`
//! crate (the standard library has no async I/O traits), and small helpers to use them.
//!
//! An adapter for another runtime's stream is a few lines: forward each `poll_*` call to the
//! stream's own method.

use std::future::Future;
use std::io;
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Reads bytes without blocking the thread.
pub trait AsyncRead {
    /// Reads into `buf`. `Ready(Ok(0))` means end of stream (or an empty `buf`); `Pending`
    /// means the task will be woken when a retry can make progress.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>>;
}

/// Writes bytes without blocking the thread.
pub trait AsyncWrite {
    /// Writes some of `buf`; returns how many bytes were taken.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;
    /// Completes when everything written so far has been handed on to the transport.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    /// Flushes and closes the write side.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for &mut T {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for Box<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_read(cx, buf)
    }
}

impl<P> AsyncRead for Pin<P>
where
    P: DerefMut + Unpin,
    P::Target: AsyncRead,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for &mut T {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_close(cx)
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for Box<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self).poll_close(cx)
    }
}

impl<P> AsyncWrite for Pin<P>
where
    P: DerefMut + Unpin,
    P::Target: AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().as_mut().poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().as_mut().poll_close(cx)
    }
}

/// In-memory sources are always ready.
impl AsyncRead for &[u8] {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let n = <&[u8] as io::Read>::read(&mut *self, buf)?;
        Poll::Ready(Ok(n))
    }
}

impl<T: AsRef<[u8]> + Unpin> AsyncRead for io::Cursor<T> {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let n = io::Read::read(&mut *self, buf)?;
        Poll::Ready(Ok(n))
    }
}

/// In-memory sinks are always ready.
impl AsyncWrite for Vec<u8> {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// `.await`-able helpers for every [`AsyncRead`] that is `Unpin`.
pub trait AsyncReadExt: AsyncRead + Unpin {
    /// Reads some bytes; 0 means end of stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Read<'a, Self> {
        Read { reader: self, buf }
    }

    /// Fills `buf` completely, or fails with `UnexpectedEof`.
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadExact<'a, Self> {
        ReadExact { reader: self, buf, filled: 0 }
    }

    /// Appends everything up to the end of the stream to `out`; returns how many bytes.
    fn read_to_end<'a>(&'a mut self, out: &'a mut Vec<u8>) -> ReadToEnd<'a, Self> {
        ReadToEnd { reader: self, out, total: 0 }
    }
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncReadExt for T {}

/// `.await`-able helpers for every [`AsyncWrite`] that is `Unpin`.
pub trait AsyncWriteExt: AsyncWrite + Unpin {
    /// Writes some of `buf`; returns how many bytes were taken.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Write<'a, Self> {
        Write { writer: self, buf }
    }

    /// Writes all of `buf`.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> WriteAll<'a, Self> {
        WriteAll { writer: self, buf }
    }

    fn flush(&mut self) -> Flush<'_, Self> {
        Flush { writer: self }
    }

    /// Flushes and closes the write side (for a TLS stream: sends close_notify).
    fn close(&mut self) -> Close<'_, Self> {
        Close { writer: self }
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWriteExt for T {}

/// Future for [`AsyncReadExt::read`].
pub struct Read<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut [u8],
}

impl<R: AsyncRead + Unpin + ?Sized> Future for Read<'_, R> {
    type Output = io::Result<usize>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.reader).poll_read(cx, this.buf)
    }
}

/// Future for [`AsyncReadExt::read_exact`].
pub struct ReadExact<'a, R: ?Sized> {
    reader: &'a mut R,
    buf: &'a mut [u8],
    filled: usize,
}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadExact<'_, R> {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        while this.filled < this.buf.len() {
            let n = match Pin::new(&mut *this.reader).poll_read(cx, &mut this.buf[this.filled..]) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream ended before the buffer was full")));
            }
            this.filled += n;
        }
        Poll::Ready(Ok(()))
    }
}

/// Future for [`AsyncReadExt::read_to_end`].
pub struct ReadToEnd<'a, R: ?Sized> {
    reader: &'a mut R,
    out: &'a mut Vec<u8>,
    total: usize,
}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadToEnd<'_, R> {
    type Output = io::Result<usize>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut chunk = [0u8; 8192];
        loop {
            match Pin::new(&mut *this.reader).poll_read(cx, &mut chunk) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(this.total)),
                Poll::Ready(Ok(n)) => {
                    this.out.extend_from_slice(&chunk[..n]);
                    this.total += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Future for [`AsyncWriteExt::write`].
pub struct Write<'a, W: ?Sized> {
    writer: &'a mut W,
    buf: &'a [u8],
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for Write<'_, W> {
    type Output = io::Result<usize>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        Pin::new(&mut *this.writer).poll_write(cx, this.buf)
    }
}

/// Future for [`AsyncWriteExt::write_all`].
pub struct WriteAll<'a, W: ?Sized> {
    writer: &'a mut W,
    buf: &'a [u8],
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for WriteAll<'_, W> {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        while !this.buf.is_empty() {
            match Pin::new(&mut *this.writer).poll_write(cx, this.buf) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "the transport accepted no bytes"))),
                Poll::Ready(Ok(n)) => this.buf = &this.buf[n..],
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Future for [`AsyncWriteExt::flush`].
pub struct Flush<'a, W: ?Sized> {
    writer: &'a mut W,
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for Flush<'_, W> {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.writer).poll_flush(cx)
    }
}

/// Future for [`AsyncWriteExt::close`].
pub struct Close<'a, W: ?Sized> {
    writer: &'a mut W,
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for Close<'_, W> {
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.writer).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::block_on;
    use super::*;

    #[test]
    fn in_memory_reads_and_writes() {
        let mut src: &[u8] = b"hello world";
        let mut first = [0u8; 5];
        block_on(src.read_exact(&mut first)).unwrap();
        assert_eq!(&first, b"hello");
        let mut rest = Vec::new();
        assert_eq!(block_on(src.read_to_end(&mut rest)).unwrap(), 6);
        assert_eq!(rest, b" world");
        let mut short: &[u8] = b"ab";
        let mut four = [0u8; 4];
        assert_eq!(block_on(short.read_exact(&mut four)).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);

        let mut sink: Vec<u8> = Vec::new();
        block_on(async {
            sink.write_all(b"abc").await?;
            sink.write_all(b"def").await?;
            sink.flush().await?;
            sink.close().await
        })
        .unwrap();
        assert_eq!(sink, b"abcdef");
    }

    #[test]
    fn write_all_loops_over_partial_writes_and_stops_on_zero() {
        struct Dribble(Vec<u8>, usize);
        impl AsyncWrite for Dribble {
            fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                let n = buf.len().min(self.1);
                let me = &mut *self;
                me.0.extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let mut d = Dribble(Vec::new(), 3);
        block_on(d.write_all(b"0123456789")).unwrap();
        assert_eq!(d.0, b"0123456789");
        let mut z = Dribble(Vec::new(), 0);
        assert_eq!(block_on(z.write_all(b"x")).unwrap_err().kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn mutable_references_and_boxes_are_streams_too() {
        let mut src = io::Cursor::new(b"xyz".to_vec());
        let mut by_ref = &mut src;
        let mut one = [0u8; 1];
        // Self = &mut Cursor, through the blanket impl for mutable references
        block_on(AsyncReadExt::read_exact(&mut by_ref, &mut one)).unwrap();
        let mut boxed: Box<dyn AsyncRead + Unpin> = Box::new(&mut src);
        let mut rest = Vec::new();
        block_on(boxed.read_to_end(&mut rest)).unwrap();
        assert_eq!((one[0], rest.as_slice()), (b'x', &b"yz"[..]));
    }
}
