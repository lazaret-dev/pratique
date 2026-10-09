//! TLS 1.3 over an asynchronous transport.

use super::io::{AsyncRead, AsyncWrite};
use crate::error::{Error, Result};
use crate::tls::{ClientConfig, ClientConnection, Suite};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

/// Ciphertext queued beyond this many bytes is sent before more plaintext is accepted, so a
/// slow transport pushes back on the writer instead of memory growing.
const WRITE_BACKLOG: usize = 64 * 1024;

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// An established TLS 1.3 connection over an [`AsyncRead`] + [`AsyncWrite`] transport.
///
/// An asynchronous driver around [`ClientConnection`], the counterpart of the blocking
/// [`TlsStream`](crate::tls::TlsStream). As there, the client's Finished message is sent together
/// with the first data written (or on `flush`, `close`, or before the first wait for data).
///
/// Call [`close`](super::AsyncWriteExt::close) when done writing: it sends close_notify, which
/// lets the peer tell a finished stream from a truncated one. Dropping the stream cannot do that,
/// because sending needs the executor.
pub struct AsyncTlsStream<S> {
    io: S,
    conn: ClientConnection,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncTlsStream<S> {
    /// Performs the TLS 1.3 handshake over `io`, verifying the server against `server_name`
    /// (a DNS name or IP literal).
    pub async fn connect(io: S, server_name: &str, config: &ClientConfig) -> Result<AsyncTlsStream<S>> {
        let conn = ClientConnection::new(server_name, config)?;
        let mut s = AsyncTlsStream { io, conn };
        poll_fn(|cx| s.poll_handshake(cx)).await?;
        Ok(s)
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            // the ClientHello first; later, the fatal alert if the handshake failed
            ready!(self.poll_drain(cx))?;
            if !self.conn.is_handshaking() {
                // Finished stays queued; it goes out with the first write
                return Poll::Ready(Ok(()));
            }
            ready!(self.poll_receive(cx))?;
            if let Err(e) = self.conn.process() {
                let _ = self.poll_drain(cx); // best effort: the fatal alert
                return Poll::Ready(Err(e));
            }
        }
    }

    /// Sends the queued ciphertext to the transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            match Pin::new(&mut self.io).poll_write(cx, self.conn.output()) {
                Poll::Ready(Ok(0)) => {
                    let n = self.conn.output().len();
                    self.conn.consume_output(n);
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "the transport accepted no bytes")));
                }
                Poll::Ready(Ok(n)) => self.conn.consume_output(n),
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Poll::Ready(Err(e)) => {
                    // never resend half a record later
                    let n = self.conn.output().len();
                    self.conn.consume_output(n);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Reads once from the transport into the connection. An end of stream is an error unless
    /// the peer said close_notify first.
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            let space = self.conn.recv_buf();
            match Pin::new(&mut self.io).poll_read(cx, space) {
                Poll::Ready(Ok(0)) => return Poll::Ready(self.conn.recv_eof()),
                Poll::Ready(Ok(n)) => {
                    self.conn.recv_filled(n);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// The TLS 1.3 cipher suite negotiated with the server; `None` for a TLS 1.2 connection.
    pub fn cipher_suite(&self) -> Option<Suite> {
        self.conn.cipher_suite()
    }

    /// The name of the negotiated cipher suite, in either version.
    pub fn cipher_suite_name(&self) -> Option<&'static str> {
        self.conn.cipher_suite_name()
    }

    /// The verified chain whose revocation sources were left for later, taken out (once); see
    /// [`ClientConnection::take_unchecked`](crate::tls::ClientConnection::take_unchecked).
    pub fn take_unchecked(&mut self) -> Option<Box<crate::revocation::Unchecked>> {
        self.conn.take_unchecked()
    }

    /// The version of TLS spoken.
    pub fn protocol_version(&self) -> Option<crate::tls::TlsVersion> {
        self.conn.protocol_version()
    }

    /// Whether the handshake resumed a session.
    pub fn is_resumed(&self) -> bool {
        self.conn.is_resumed()
    }

    /// The ALPN protocol the server selected, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    /// The server's end-entity certificate (DER).
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.conn.peer_certificate()
    }

    /// Every certificate the server sent, DER encoded, leaf first.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.conn.peer_certificates()
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.io
    }

    /// The asynchronous counterpart of [`TlsStream::settle`](crate::tls::TlsStream::settle): digests
    /// what arrived with the end of the last response (session tickets, a KeyUpdate), sends what that
    /// calls for, and says whether the connection is now quiet, fit to wait for another request.
    pub fn poll_settle(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.conn.process().is_err() {
            return Poll::Ready(false);
        }
        if self.conn.wants_write() {
            match self.poll_drain(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(false),
                Poll::Ready(Ok(())) => {}
            }
        }
        // Even with nothing left to hand to the transport, what was handed over earlier (the answer to a
        // KeyUpdate, queued by the last read) may still be on its way: a connection is not at rest until
        // that has gone out.
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(false),
            Poll::Ready(Ok(())) => {}
        }
        Poll::Ready(self.conn.is_quiet())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncTlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let n = this.conn.read_plaintext(buf);
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
            if this.conn.peer_closed() {
                return Poll::Ready(Ok(0));
            }
            if let Err(e) = this.conn.process() {
                let _ = this.poll_drain(cx); // best effort: the fatal alert
                return Poll::Ready(Err(to_io(e)));
            }
            if this.conn.has_plaintext() || this.conn.peer_closed() {
                continue;
            }
            // About to wait for the peer: make sure it has what we queued first (our Finished, or
            // the answer to a KeyUpdate).
            if this.conn.wants_write() {
                ready!(this.poll_drain(cx))?;
                ready!(Pin::new(&mut this.io).poll_flush(cx))?;
            }
            ready!(this.poll_receive(cx)).map_err(to_io)?;
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncTlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.conn.output().len() >= WRITE_BACKLOG {
            ready!(this.poll_drain(cx))?;
        }
        let n = this.conn.write_plaintext(buf).map_err(to_io)?;
        // Push it out now if the transport is ready; otherwise it stays queued (the transport has
        // our waker) and the next write or flush finishes the job.
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.send_close_notify();
        ready!(this.poll_drain(cx))?;
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Pin::new(&mut this.io).poll_close(cx)
    }
}
