//! An accepted [`ServerStream`] split into a reading half and a writing half that two threads can use at once
//! ([`ServerStream::split`]): what an HTTP/2 server needs, where one thread reads the client's frames while the handlers of
//! its streams write their responses.
//!
//! It works as the client's split does (`split.rs`): the TLS state is shared under a lock that is never held across I/O.
//! The reading half reads the transport with no lock held and hands what came to the connection under the lock; a writer
//! encrypts under the lock and sends the records under a second lock that also holds the writing handle, so records reach
//! the transport in the order they were made. The reading half has things to send of its own (the answer to a KeyUpdate,
//! an alert): it sends them only if nobody is sending, and otherwise leaves them to whoever is, who looks again before
//! letting go. So the reading half never waits for a write that a slow client has blocked.

use super::server::{ServerConnection, ServerStream};
use super::split::Duplex;
use super::suite::Suite;
use crate::error::Error;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

struct Shared<S> {
    conn: Mutex<ServerConnection>,
    /// The writing handle. Holding it is the right to send.
    out: Mutex<Sender<S>>,
}

struct Sender<S> {
    io: S,
    buf: Vec<u8>,
}

fn to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

impl<S: Write> Shared<S> {
    fn conn(&self) -> MutexGuard<'_, ServerConnection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sends what the connection has queued. With `wait`, waits for the right to send; without, sends only if nobody is
    /// sending (whoever is sends this too), so that the reading half never waits for a blocked write.
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
                    sender.buf.clear();
                    sender.buf.extend_from_slice(conn.output());
                    let n = sender.buf.len();
                    conn.consume_output(n);
                }
                // what is taken is gone from the connection even if this fails, so no half record is ever sent later
                sender.io.write_all(&sender.buf)?;
            }
            sender.io.flush()?;
            drop(guard);
            // something queued by the other half while we held the right to send, which it could not send itself
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
        /// The negotiated cipher suite.
        pub fn cipher_suite(&self) -> Option<Suite> {
            self.shared.conn().cipher_suite()
        }

        /// The ALPN protocol selected, if any.
        pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
            self.shared.conn().alpn_protocol().map(|p| p.to_vec())
        }

        /// The name the client asked for (SNI), if any.
        pub fn server_name(&self) -> Option<String> {
            self.shared.conn().server_name().map(str::to_string)
        }

        /// Whether the handshake resumed a session.
        pub fn is_resumed(&self) -> bool {
            self.shared.conn().is_resumed()
        }

        /// The client's certificate chain (DER, leaf first), if it authenticated with one.
        pub fn peer_certificates(&self) -> Vec<Vec<u8>> {
            self.shared.conn().peer_certificates().to_vec()
        }
    };
}

/// The reading half of a split [`ServerStream`]: implements [`Read`]. Dropping it closes nothing.
pub struct ServerReadHalf<S: Duplex> {
    shared: Arc<Shared<S>>,
    io: S,
    staging: Vec<u8>,
}

/// The writing half of a split [`ServerStream`]: implements [`Write`]. [`close`](ServerWriteHalf::close), or dropping it,
/// sends close_notify.
pub struct ServerWriteHalf<S: Duplex> {
    shared: Arc<Shared<S>>,
}

impl<S: Read + Write> ServerStream<S> {
    /// Splits an accepted stream into a half that reads and a half that writes, for two threads. Anything the stream
    /// has received and not yet handed out stays with the reading half.
    pub fn split(self) -> io::Result<(ServerReadHalf<S>, ServerWriteHalf<S>)>
    where
        S: Duplex,
    {
        let (conn, reader, writer) = self.into_parts()?;
        let shared = Arc::new(Shared { conn: Mutex::new(conn), out: Mutex::new(Sender { io: writer, buf: Vec::new() }) });
        Ok((ServerReadHalf { shared: shared.clone(), io: reader, staging: vec![0u8; 32 * 1024] }, ServerWriteHalf { shared }))
    }
}

impl<S: Duplex> ServerReadHalf<S> {
    connection_info!();

    /// The reading handle of the transport (with a socket, its options, such as a read timeout, are shared with the
    /// writing handle).
    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

impl<S: Duplex> Read for ServerReadHalf<S> {
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
                    let _ = self.shared.send_queued(false);
                    return Err(to_io(e));
                }
                if conn.has_plaintext() || conn.peer_closed() {
                    continue;
                }
                conn.wants_write()
            };
            if queued {
                self.shared.send_queued(false)?;
            }
            let got = loop {
                match self.io.read(&mut self.staging) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    other => break other,
                }
            };
            match got {
                Ok(0) => return self.shared.conn().recv_eof().map(|_| 0).map_err(to_io),
                Ok(n) => self.shared.conn().receive(&self.staging[..n]),
                Err(e) => return Err(e),
            }
        }
    }
}

impl<S: Duplex> ServerWriteHalf<S> {
    connection_info!();

    /// Sends a close_notify, which ends what we send (the reading half can still read). Further writes fail.
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

    /// Bytes the connection has queued and not sent (encrypted records waiting for the right to send).
    pub fn queued(&self) -> usize {
        self.shared.conn().output().len()
    }
}

impl<S: Duplex> Write for ServerWriteHalf<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.shared.conn().write_plaintext(buf).map_err(to_io)?;
        self.shared.send_queued(true)?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.shared.send_queued(true)
    }
}

impl<S: Duplex> Drop for ServerWriteHalf<S> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
