//! An established [`TlsStream`] split into a reading half and a writing half that two threads can use at once
//! ([`TlsStream::split`]): one thread waits for what the peer sends while another sends, which a single blocking stream cannot
//! do (a protocol where both sides send a great deal at once, such as an echo, would otherwise stop with both waiting to write).
//!
//! How it works. The TLS state is shared under a lock that is never held across I/O: the reading half takes the connection's
//! receive buffer out, reads the transport into it with no lock held, and puts it back to be decrypted; the writing half
//! encrypts under the lock and takes the records out to send them. Sending goes through a second lock that also holds the
//! writing handle, so records reach the transport in the order the connection made them. The reading half also has things to
//! send (the client's Finished, the answer to a KeyUpdate, an alert): it sends them itself only if nobody is sending, and
//! otherwise leaves them for whoever is, who looks again for more after letting go. So the reading half never waits for a
//! write the writing half is blocked in, and the peer is always read.

use super::conn::ClientConnection;
use super::{to_io, TlsVersion};
use crate::error::Error;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

/// A transport that can hand out a second handle to itself (a duplicate of a socket), so that one handle reads while the
/// other writes: what [`TlsStream::split`](super::TlsStream::split) needs. Implemented for `TcpStream` and, on Unix, for
/// `UnixStream`.
pub trait Duplex: Read + Write + Sized {
    /// Another handle to the same transport.
    fn duplicate(&self) -> io::Result<Self>;
}

impl Duplex for std::net::TcpStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

#[cfg(unix)]
impl Duplex for std::os::unix::net::UnixStream {
    fn duplicate(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

struct Shared<S> {
    conn: Mutex<ClientConnection>,
    /// The writing handle and a buffer for the records being sent. Holding it is the right to send.
    out: Mutex<Sender<S>>,
}

struct Sender<S> {
    io: S,
    buf: Vec<u8>,
}

impl<S: Write> Shared<S> {
    fn conn(&self) -> MutexGuard<'_, ClientConnection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sends what the connection has queued. With `wait`, waits for the right to send; without, sends only if nobody is
    /// sending (whoever is will send this too: see below), so that the reading half never waits for a blocked write.
    fn send_queued(&self, wait: bool) -> io::Result<()> {
        let mut wait = wait;
        loop {
            let mut guard = if wait {
                self.out.lock().unwrap_or_else(|e| e.into_inner())
            } else {
                match self.out.try_lock() {
                    Ok(g) => g,
                    Err(TryLockError::Poisoned(e)) => e.into_inner(),
                    Err(TryLockError::WouldBlock) => return Ok(()),
                }
            };
            let sender = &mut *guard;
            loop {
                {
                    let mut conn = self.conn();
                    if !conn.wants_write() {
                        break;
                    }
                    conn.take_output(&mut sender.buf);
                }
                // what is taken is gone from the connection even if this fails, so that no half record is ever sent later
                sender.io.write_all(&sender.buf)?;
            }
            sender.io.flush()?;
            drop(guard);
            // Something queued by the other half while we held the right to send, which it could not send itself, is still
            // waiting: it was queued before its try failed, and so before we let go, so this look sees it.
            if !self.conn().wants_write() {
                return Ok(());
            }
            wait = false;
        }
    }
}

/// What both halves can say about the connection.
macro_rules! connection_info {
    () => {
        /// The version of TLS spoken.
        pub fn protocol_version(&self) -> Option<TlsVersion> {
            self.shared.conn().protocol_version()
        }

        /// Whether the handshake resumed a session.
        pub fn is_resumed(&self) -> bool {
            self.shared.conn().is_resumed()
        }

        /// The name of the negotiated cipher suite, in either version.
        pub fn cipher_suite_name(&self) -> Option<&'static str> {
            self.shared.conn().cipher_suite_name()
        }

        /// The ALPN protocol the server selected, if any.
        pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
            self.shared.conn().alpn_protocol().map(|p| p.to_vec())
        }

        /// The certificates the server sent, leaf first, as DER.
        pub fn peer_certificates(&self) -> Vec<Vec<u8>> {
            self.shared.conn().peer_certificates().to_vec()
        }
    };
}

/// The reading half of a split [`TlsStream`](super::TlsStream): implements [`Read`]. Reading never waits for the writing
/// half; dropping it closes nothing (the writing half sends close_notify).
pub struct TlsReadHalf<S: Duplex> {
    shared: Arc<Shared<S>>,
    io: S,
}

/// The writing half of a split [`TlsStream`](super::TlsStream): implements [`Write`]. [`close`](TlsWriteHalf::close), or
/// dropping it, sends close_notify, which ends what we send; the reading half can go on reading what the peer sends after
/// that.
pub struct TlsWriteHalf<S: Duplex> {
    shared: Arc<Shared<S>>,
}

/// Makes the halves of a connection whose handshake is done, over two handles to one transport.
pub(super) fn halves<S: Duplex>(conn: ClientConnection, reader: S, writer: S) -> (TlsReadHalf<S>, TlsWriteHalf<S>) {
    let shared = Arc::new(Shared { conn: Mutex::new(conn), out: Mutex::new(Sender { io: writer, buf: Vec::new() }) });
    (TlsReadHalf { shared: shared.clone(), io: reader }, TlsWriteHalf { shared })
}

impl<S: Duplex> TlsReadHalf<S> {
    connection_info!();

    /// The reading handle of the transport (with a socket, its options, such as a read timeout, are the socket's and so the
    /// writing handle's too).
    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// One read of the transport into the connection, with no lock held while it waits.
    fn receive(&mut self) -> io::Result<()> {
        let taken = self.shared.conn().take_recv_buf();
        let Some(mut rb) = taken else {
            return Err(to_io(Error::Tls("internal: the TLS receive buffer cannot be taken".into())));
        };
        let got = loop {
            match self.io.read(rb.space()) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                other => break other,
            }
        };
        let mut conn = self.shared.conn();
        match got {
            Ok(0) => {
                conn.restore_recv_buf(rb, 0);
                conn.recv_eof().map_err(to_io)
            }
            Ok(n) => {
                conn.restore_recv_buf(rb, n);
                Ok(())
            }
            Err(e) => {
                // (a read timeout leaves the connection as it was: the next read carries on)
                conn.restore_recv_buf(rb, 0);
                Err(e)
            }
        }
    }
}

impl<S: Duplex> Read for TlsReadHalf<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let queued = {
                let mut conn = self.shared.conn();
                let n = conn.read_plaintext(buf);
                if n > 0 {
                    return Ok(n);
                }
                if conn.peer_closed() {
                    return Ok(0);
                }
                if let Err(e) = conn.process() {
                    drop(conn);
                    // the fatal alert the error called for, if nobody is sending (else whoever is sends it)
                    let _ = self.shared.send_queued(false);
                    return Err(to_io(e));
                }
                if conn.has_plaintext() || conn.peer_closed() {
                    continue;
                }
                conn.wants_write()
            };
            // About to wait for the peer: it should have what we owe it first (our Finished, the answer to a KeyUpdate).
            if queued {
                self.shared.send_queued(false)?;
            }
            self.receive()?;
        }
    }
}

impl<S: Duplex> TlsWriteHalf<S> {
    connection_info!();

    /// Sends a close_notify alert, which ends what we send (the reading half can still read). Further writes fail.
    pub fn close(&mut self) -> io::Result<()> {
        {
            let mut conn = self.shared.conn();
            if conn.write_closed() || conn.is_failed() {
                return Ok(());
            }
            conn.send_close_notify();
        }
        self.shared.send_queued(true)
    }
}

impl<S: Duplex> Write for TlsWriteHalf<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // up to four records per call, encrypted under the lock and sent without it
        let n = self.shared.conn().write_plaintext(buf).map_err(to_io)?;
        self.shared.send_queued(true)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.shared.send_queued(true)
    }
}

impl<S: Duplex> Drop for TlsWriteHalf<S> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
