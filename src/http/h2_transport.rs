//! The blocking client's HTTP/2 transport: one TLS connection to an origin, shared by every request to it.
//!
//! HTTP/2 puts many requests on one connection, so unlike HTTP/1.1 the connection cannot belong to the request
//! that is using it. A [`Shared`] connection is the socket, the sans-IO TLS state ([`ClientConnection`]) and the
//! sans-IO HTTP/2 state ([`Connection`]), with two threads that do the socket I/O so that no caller ever blocks on
//! the network while holding a lock: a *reader* that reads, decrypts, feeds HTTP/2 and wakes the callers who wait
//! for their streams, and a *writer* that turns what HTTP/2 queued into TLS records and writes them. The reader
//! never writes and the writer never reads, so a server and a client that are each blocked in a write to the
//! other cannot deadlock.
//!
//! What makes it fast (measured against Go's `net/http` on the same server, see `tools/bench_h2.sh` and BACKLOG B-72):
//!
//! * the reader reads the socket straight into the TLS receive buffer (the buffer is detached from the TLS state
//!   for the read and put back, so there is no copy between them), decrypts in place under the `tls` lock only,
//!   and hands each record's plaintext to HTTP/2 under `state` for as short a time as it takes to account for it;
//! * the body of a DATA frame goes from the decrypted record to where the application will read it in one
//!   copy, even when the frame is longer than the record it began in (HTTP/2 passes the payload on piece by
//!   piece, with the windows accounted for at every boundary), and for a response that the application reads
//!   whole (`send()`, as opposed to a streamed read) into one vector that is handed over at the end with no
//!   further copy: such a stream *collects* ([`H2Stream::response`]), gives the server its credit as the bytes arrive
//!   instead of as they are read (nobody reads them piece by piece), and is not woken for its head or for pieces of
//!   its body but once, when it is done;
//! * a request thread that has queued its request writes it itself when nobody else is writing ([`Shared::send_now`]:
//!   the writer's `outbox` is a baton that one holder at a time has), saving the wake-up and scheduling of the
//!   writer thread; the writer thread does what is left over and anything large;
//! * a request is *read by its own caller* when nobody else is reading ([`Reading`]): the caller that sent the request
//!   reads the socket itself, until the response is whole (one that is answered whole) or for as long as it waits for
//!   news (one that is read in pieces), which is what an HTTP/1.1 request does, and saves the reader thread's wake-up for
//!   the response and the caller's wake-up by it (two thread switches per response, which measured 4 to 13 microseconds
//!   of CPU per small request, depending on the server; and for a download that is read in pieces, a hand-over of every
//!   piece between two threads). Whose turn it is to read (the *right to read*, `State::baton`) is decided under the
//!   `state` lock, together with starting a stream, so there is no moment at which a new request and the reader thread
//!   both think the socket is theirs. The reader thread stays out of the way ([`Parked`]) for [`PARK_WINDOW`] after the
//!   last stream ended, so that the next request of a run of requests finds the right free; and, if it was the one reading
//!   when a download was started (the connection had been left alone), after it has woken the caller of the only stream in
//!   flight with news for it, so that the caller takes over for the rest of the download. It reads again once the connection
//!   has been left alone for longer, so that a server that closes an idle connection or says GOAWAY is noticed without a
//!   request having to find out. Whoever has to wait for the reader thread (a request whose body is still being sent, a
//!   request that came while another caller was reading) wakes it, and takes the right from a caller who has stopped reading
//!   for the moment (the caller of a download who is writing what it has to a file, say: it keeps the right between two
//!   reads only while it is the only one on the connection, and for [`STALL`] at most); a caller who stops reading while
//!   other streams are in flight hands the right back to the reader thread, so a stream is never left without a reader.
//!   Several callers on one connection at once are served as before (the reader thread, or one of the callers for as long as
//!   its own request lasts, reads for all of them);
//! * the reader asks the kernel for a read timeout only when it has to (not around every read).
//!
//! The locks, in order: the registry's table, then `read` (the reading side's buffers, taken only by whoever has the
//! right to read, for a read), then `tls`, then `state`; `outbox` is held only by whoever is writing, and with it held
//! `state` and `tls` are taken briefly, one at a time. Who has the right to read is a field of `state`, not a lock.
//!
//! A caller opens a stream ([`Shared::start`]), sends the request body as the windows allow, waits for the head
//! ([`H2Stream::head`]) and reads the body ([`H2Stream::read`]); dropping the [`H2Stream`] gives the stream up (a
//! response that was not read to its end is cancelled with RST_STREAM, which costs the connection nothing).
//!
//! The [`Registry`] holds a client's connections by origin. The first request to an origin dials; requests that
//! arrive meanwhile wait for the dial instead of dialing too (a burst of requests to a new origin makes one
//! connection, not one each); a server that did not pick `h2` in ALPN is remembered for a while, and its requests
//! go the HTTP/1.1 way without waiting. A connection is closed when it has been idle longer than the client's
//! idle timeout, when the server says GOAWAY and what it took is finished, when the server or the network ends
//! it, and when the client that owned it is dropped (after the streams in flight have finished).
//!
//! What a failed request tells the caller ([`Failure`]): whether it can be sent again whatever the method (the
//! server said it did not act on it: REFUSED_STREAM, or a GOAWAY that did not get as far), and whether the
//! connection was lost under it before any answer (so that a request that may be repeated can be, once, if the
//! connection was an old one).

use super::h2::connection::{Collected, Config, Connection, ConnectionError, Direct, Head, News, OpenError, Request, StreamError, StreamEvent, BODY_TOO_BIG};
use super::idle::Key;
use crate::asyncio::net::deadline_error;
use crate::asyncio::slots::Permit;
use crate::error::Error;
use crate::tls::{ClientConnection, RecvBuf};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// The most TLS output taken for one write to the socket.
const WRITE_CHUNK: usize = 64 * 1024;

/// The size of the TLS receive buffer of a connection that is shared (the socket is read into it directly, as much as
/// there is room for): each read wakes the callers who wait for data, so more per read means fewer wake-ups for a fast
/// transfer; and the less often the buffer is arranged anew (which moves the part of a record at its end), the less
/// that costs.
const RECV_BUF: usize = 256 * 1024;

/// How long after the last stream of a connection ended its reader thread stays out of the way, so that the caller of the
/// next request reads that request's response itself (see [`Reading`]). A connection that is left alone for longer
/// than this is read by the reader thread again, which notices what the server does to an idle connection (closes it,
/// says GOAWAY) without a request having to find out.
const PARK_WINDOW: Duration = Duration::from_millis(25);

/// The longest the reader thread waits for a caller who reads in its place to be done, if that caller does not tell it (a
/// bound on the damage a missed wake-up could do; the caller always tells it).
const PARK_SAFETY: Duration = Duration::from_secs(1);

/// How long the right to read the socket stays with the caller of a streamed response who has stopped reading (it is
/// writing what it has read to a file, say), so that it can go on at once when it asks for more. After that the reader
/// thread takes it (when it next wakes up, which is within [`PARK_SAFETY`] of the end of this time at most), so that a
/// connection whose streams are read slowly is still looked after (a server that pings it, or says GOAWAY, is answered).
const STALL: Duration = Duration::from_millis(200);

/// How long an origin that did not choose HTTP/2 is believed to speak HTTP/1.1 only.
const HTTP1_MEMORY: Duration = Duration::from_secs(300);

/// What bounds a wait: the time without progress that is allowed, and the moment the whole request is due.
#[derive(Clone, Copy, Debug)]
pub(super) struct Waits {
    pub(super) timeout: Duration,
    pub(super) deadline: Option<Instant>,
}

impl Waits {
    /// The moment a wait that starts now has to be over.
    pub(super) fn until(&self) -> Instant {
        let now = Instant::now();
        let op = now.checked_add(self.timeout).unwrap_or_else(|| now + Duration::from_secs(365 * 24 * 3600));
        match self.deadline {
            Some(d) => op.min(d),
            None => op,
        }
    }

    /// The error for a wait that ran out.
    pub(super) fn expired(&self) -> Error {
        self.expired_in("HTTP/2")
    }

    /// The error for a wait that ran out, saying which protocol it was waiting in.
    pub(super) fn expired_in(&self, protocol: &str) -> Error {
        match self.deadline {
            Some(d) if Instant::now() >= d => Error::Io(deadline_error()),
            _ => Error::Io(io::Error::new(io::ErrorKind::TimedOut, format!("timed out waiting for the server ({protocol})"))),
        }
    }
}

/// Why a request failed, and what may be done about it.
#[derive(Debug)]
pub(super) struct Failure {
    pub(super) error: Error,
    /// The request cannot have been acted on: it may be sent again on another connection whatever its method.
    pub(super) retry_safe: bool,
    /// The connection was lost (the server closed it, or the network broke it) before any of the response came.
    pub(super) peer_closed: bool,
}

/// Why a request could not be started on a connection.
#[derive(Debug)]
pub(super) enum StartError {
    /// The connection has as many streams as the server allows: take another connection.
    Full,
    /// The connection is going away or is lost: take another.
    Unavailable,
    Failed(Failure),
}

/// Why the transport ended, when it did not end because this endpoint closed it.
#[derive(Clone, Debug)]
struct Lost {
    /// The peer closed the connection or it was reset (as opposed to a protocol error, ours or the server's).
    peer_closed: bool,
    kind: io::ErrorKind,
    message: String,
}

/// Where the thread that waits for news about one stream sleeps (see [`Shared::wait_on`]): each stream has its own, so
/// that what arrives for one stream does not wake the threads of the others.
struct Slot {
    cv: Condvar,
    /// A thread is asleep, or about to be, on `cv`: only then is a notification needed. Written only with the state
    /// lock held.
    waiting: AtomicBool,
    /// ... and it waits for its response, and would read the socket itself if it had the right to (see
    /// [`State::rest_baton`]). Written only with the state lock held.
    can_lead: AtomicBool,
}

impl Slot {
    fn new() -> Arc<Slot> {
        Arc::new(Slot { cv: Condvar::new(), waiting: AtomicBool::new(false), can_lead: AtomicBool::new(false) })
    }
}

/// Who is to be woken when a caller lets go of the right to read the socket (see [`State::rest_baton`]).
#[must_use]
enum Handoff {
    Nobody,
    /// The reader thread, which waits for the right.
    Reader,
    /// A caller who waits for its response, and has been given the right.
    Caller(Arc<Slot>),
}

impl Handoff {
    fn wake(self, shared: &Shared) {
        match self {
            Handoff::Nobody => {}
            Handoff::Reader => shared.park.notify_one(),
            Handoff::Caller(slot) => slot.cv.notify_all(),
        }
    }
}

struct State {
    h2: Connection,
    /// The transport is being closed or is gone: the threads are leaving, nothing new may start.
    closing: bool,
    /// Before the socket is closed, what is queued is written (a GOAWAY, an alert).
    flush_first: bool,
    /// ... and then a TLS close_notify.
    say_goodbye: bool,
    lost: Option<Lost>,
    /// Since when there has been no stream in flight.
    idle_since: Option<Instant>,
    /// The client that owned the connection is gone: it closes when the last stream is done.
    retired: bool,
    /// The slot of every stream a caller holds.
    slots: HashMap<u32, Arc<Slot>>,
    /// Streams whose requests were cancelled (their batch was): their callers' waits end with `Error::Cancelled`.
    cancelled: Vec<u32>,
    /// How many callers wait in [`Shared::start`] for room to send a request body (the writer makes room).
    senders: usize,
    /// Whether the reader thread is asleep, and why (see [`Parked`]). Written with this lock held.
    parked: Parked,
    /// Who has the right to read the socket (see [`Reading`]).
    baton: Baton,
    /// When the reader of the socket last woke the caller of the one stream that was in flight, with news for it (see
    /// [`State::park_for`]).
    handover: Option<Instant>,
}

/// Who has the right to read the socket (see [`Reading`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Baton {
    Nobody,
    /// The connection's reader thread, for one read.
    Reader,
    /// The caller of the stream `stream`, who waits for its head or its body, or, if `paused_since` is a time, who is the
    /// only one on the connection and has stopped reading for the moment (a streamed response: its caller has the
    /// bytes it asked for and will ask for more). The right is kept for such a caller so that it can go on without
    /// another thread's help, but anyone who needs the socket read may take it away (see [`State::claim_baton`] and
    /// [`Shared::wait_on`]), and the reader thread does when it has not been used for [`STALL`].
    Caller { stream: u32, paused_since: Option<Instant> },
}

/// Why the reader thread is not reading the socket.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Parked {
    /// It is reading, or running.
    No,
    /// Nothing is in flight and a request has just been answered (the caller of the next request will read its response
    /// itself), or one response is being read in pieces and its caller has just been given some (it will ask for more, and
    /// read the socket itself). Whoever has to wait for the network instead wakes the reader thread (see
    /// [`Shared::wait_on`]).
    Idle,
    /// A caller who waits for its own response is reading; it wakes the reader thread when it is done.
    Leader,
}

impl State {
    /// The state of a connection that has just been made (and has had nothing to do yet: it is idle).
    fn new(h2: Connection) -> State {
        State {
            h2,
            closing: false,
            flush_first: false,
            say_goodbye: false,
            lost: None,
            idle_since: Some(Instant::now()),
            handover: None,
            retired: false,
            slots: HashMap::new(),
            cancelled: Vec::new(),
            senders: 0,
            parked: Parked::No,
            baton: Baton::Nobody,
        }
    }

    /// If the request on `stream` was cancelled: the failure that ends its caller's wait.
    fn cancelled(&self, stream: u32) -> Option<Failure> {
        self.cancelled.contains(&stream).then(|| Failure { error: Error::Cancelled, retry_safe: false, peer_closed: false })
    }

    /// The caller of `stream` takes the right to read the socket if it can: nobody has it, or it is the caller's own, or
    /// it is another caller's who is not using it. (Never when the transport is going away: there is nothing to read for.)
    fn claim_baton(&mut self, stream: u32) -> bool {
        if self.closing {
            return false;
        }
        match self.baton {
            Baton::Nobody | Baton::Caller { paused_since: Some(_), .. } => {}
            Baton::Caller { stream: owner, paused_since: None } if owner == stream => {}
            Baton::Caller { .. } | Baton::Reader => return false,
        }
        self.baton = Baton::Caller { stream, paused_since: None };
        true
    }

    /// The caller of `stream` is done reading for now. It keeps the right (which may be taken from it) if `keep` and it
    /// is the only stream in flight, and gives it up otherwise: to another caller who is asleep waiting for its response, if
    /// there is one, or else to nobody, and then the reader thread (which waits for the right) is woken. Who is to be woken.
    ///
    /// Giving the right to a caller who waits (BACKLOG B-89) is what keeps a run of requests from several threads on one
    /// connection read by their callers: the one who is given it reads what comes for everyone, as the reader thread would,
    /// and its own response costs nobody else a wake-up; the reader thread would be woken for the right, and would then
    /// wake the caller for its response.
    fn rest_baton(&mut self, stream: u32, keep: bool) -> Handoff {
        if !matches!(self.baton, Baton::Caller { stream: owner, .. } if owner == stream) {
            return Handoff::Nobody;
        }
        if keep && self.h2.active_streams() <= 1 {
            self.baton = Baton::Caller { stream, paused_since: Some(Instant::now()) };
            return Handoff::Nobody;
        }
        if !self.closing {
            let next = self.slots.iter().find(|(&id, slot)| id != stream && slot.waiting.load(Ordering::Relaxed) && slot.can_lead.load(Ordering::Relaxed));
            if let Some((&id, slot)) = next {
                // (claimed for this wake-up, as `claim_wakeups` does)
                slot.waiting.store(false, Ordering::Relaxed);
                self.baton = Baton::Caller { stream: id, paused_since: None };
                return Handoff::Caller(slot.clone());
            }
        }
        self.baton = Baton::Nobody;
        if self.parked == Parked::Leader {
            self.parked = Parked::No;
            return Handoff::Reader;
        }
        Handoff::Nobody
    }

    /// Starts closing the transport. `polite`: say GOAWAY and close_notify first.
    fn begin_close(&mut self, polite: bool) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.flush_first = true;
        self.say_goodbye = polite;
        if polite {
            self.h2.close();
        }
    }

    /// How much longer the reader thread is to stay out of the way, if it is to: after the last stream of the connection
    /// ended, and after it woke the caller of the one stream that is in flight with news for it (a response that is read
    /// in pieces: that caller reads on, and reads the socket itself if nobody else does; see [`Reading`]).
    fn park_for(&self) -> Option<Duration> {
        if self.closing {
            return None;
        }
        let since = match self.h2.active_streams() {
            0 => self.idle_since?,
            1 => self.handover?,
            _ => return None,
        };
        PARK_WINDOW.checked_sub(since.elapsed()).filter(|d| !d.is_zero())
    }

    /// Notes whether streams are in flight, and closes a connection that has nothing left to do.
    fn settle(&mut self) {
        if self.h2.active_streams() > 0 {
            self.idle_since = None;
            return;
        }
        self.idle_since.get_or_insert_with(Instant::now);
        // going away (the server said GOAWAY, or ids ran out) with nothing in flight, or the client is gone
        if !self.closing && (!self.h2.usable() || self.retired) {
            self.begin_close(true);
        }
    }

    fn alive(&self) -> bool {
        !self.closing && self.h2.usable()
    }

    /// The transport ended under us.
    fn lose(&mut self, lost: Lost) {
        if self.lost.is_none() && !self.closing {
            self.lost = Some(lost);
        }
        self.h2.peer_closed();
        self.closing = true;
    }

    /// Adds to `out` the slots of the threads that are asleep and have news: those of the streams `news` names, or all
    /// of them. (The flag is cleared as the thread is claimed, so a thread is notified once however much news comes.)
    fn claim_wakeups(&self, news: &News, out: &mut Vec<Arc<Slot>>) {
        if news.is_for_everyone() {
            self.claim_all(out);
        } else {
            for id in news.streams() {
                if let Some(slot) = self.slots.get(id) {
                    if slot.waiting.swap(false, Ordering::Relaxed) {
                        out.push(slot.clone());
                    }
                }
            }
        }
    }

    fn claim_all(&self, out: &mut Vec<Arc<Slot>>) {
        for slot in self.slots.values() {
            if slot.waiting.swap(false, Ordering::Relaxed) {
                out.push(slot.clone());
            }
        }
    }
}

/// Wakes the threads claimed with [`State::claim_wakeups`], after the lock was let go.
fn wake(slots: &mut Vec<Arc<Slot>>) {
    for slot in slots.drain(..) {
        slot.cv.notify_all();
    }
}

/// How a connection looks to a request that is choosing one.
enum Probe {
    /// Lost, closing or going away: to be forgotten.
    Dead,
    /// Alive and has all the streams the server allows.
    Full,
    /// Alive and can take a stream; this many are in flight.
    Open(usize),
}

/// What the writing thread works on.
struct Outbox {
    /// What HTTP/2 queued, taken a bounded amount at a time and waiting to be encrypted: `plain[plain_pos..]` is left.
    plain: Vec<u8>,
    plain_pos: usize,
    /// TLS records waiting for the socket.
    chunk: Vec<u8>,
}

/// How a round of writing went.
enum Round {
    /// There was nothing to do.
    Idle,
    /// Something was written; there may be more.
    Wrote,
    /// The transport is closed or lost: no more writing.
    Over,
}

/// One connection, shared by the threads that make requests on it. See the module documentation.
///
/// Four things are locked: the HTTP/2 state and the bookkeeping around it (`state`), the TLS state (`tls`), the
/// reading side's buffers (`read`, by whoever has the right to read) and, in the registry, the table of connections.
/// Order: registry, then `read`, then `tls`, then `state`; `state` is never held while waiting for `tls` or `read`. The
/// reader holds `tls` while it decrypts and takes `state` only to hand each record's bytes to HTTP/2, so callers who take
/// what has arrived (a swap of buffers) are not kept waiting for decryption.
pub(super) struct Shared {
    /// The version of TLS the connection speaks.
    tls_version: Option<crate::tls::TlsVersion>,
    state: Mutex<State>,
    tls: Mutex<ClientConnection>,
    /// TLS has bytes for the peer that the writer has not taken. Written with `tls` held; the writer reads it holding
    /// `state` only, to decide whether to sleep (and whoever sets it takes `state` afterwards, so that the writer cannot
    /// miss it: see `ingest`).
    tls_pending: AtomicBool,
    /// The writer has something to do: output was queued, or the connection is to close.
    to_writer: Condvar,
    /// The writer thread is asleep on `to_writer` (set and cleared with `state` held): only then is a notification needed,
    /// which is a system call (see [`Shared::notify_writer`]).
    writer_asleep: AtomicBool,
    /// A thread that queued output to send found the outbox taken: whoever has it sends that too before it lets go (see
    /// [`Shared::send_now`]).
    write_wanted: AtomicBool,
    /// What is being written, which whoever is writing holds: the writer thread, or a request thread that sends its own
    /// request at once instead of waking the writer (see [`Shared::send_now`]). One at a time, so that TLS records go
    /// to the socket in the order they were made.
    outbox: Mutex<Outbox>,
    /// For shutting the socket down, which ends the reader's `read`.
    tcp: TcpStream,
    /// The connection's slot under a per-host connection limit, given back when the connection is over.
    permit: Mutex<Option<Permit>>,
    idle_timeout: Duration,
    /// What whoever reads the socket works with. The right to read, which `State::baton` says who has, is one at a time: the
    /// reader thread's, or that of a caller who waits for the response to its own request (see [`Reading`]), which saves
    /// the wake-ups of the reader thread for the response, and of the caller by it. Who has it is decided with `state`
    /// held, so a request that is started and its caller's right to read are made together (and the reader thread is not
    /// between them); the lock here is taken by the holder alone, for each read.
    read: Mutex<ReadSide>,
    /// Where the reader thread sleeps (waiting on `state`) when it is [`Parked`].
    park: Condvar,
    /// How many reads of the socket callers did, and how many the reader thread did (with the times they took in what an
    /// earlier read had left: see [`ReadSide::undigested`]).
    #[cfg(test)]
    reads: [AtomicUsize; 2],
    /// How many bytes of bodies read in pieces went straight into the caller's buffer, and how many through the stream's.
    #[cfg(test)]
    body_bytes: [AtomicUsize; 2],
    /// How many times callers, and the reader thread, took in what a read had left in the receive buffer.
    #[cfg(test)]
    leftovers: [AtomicUsize; 2],
    /// How many times the writer thread was woken.
    #[cfg(test)]
    writer_wakes: AtomicUsize,
    /// A test can hold a caller that sends its own output at the moment it has found nothing more to send and is about to let
    /// go of the outbox (see [`Shared::send_now`]).
    #[cfg(test)]
    pause: (Mutex<Pause>, Condvar),
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Pause {
    Off,
    Armed,
    Held,
}

/// What whoever reads the socket works with.
struct ReadSide {
    /// The reading end of the socket (a clone: the same socket).
    tcp: TcpStream,
    /// TLS's receive buffer while it is out of the connection for reading into; `None` if the connection is over.
    rb: Option<RecvBuf>,
    /// The read timeout that is set on the socket.
    armed: Option<Duration>,
    /// Records were left in the receive buffer without being taken in, because the caller who read them had all it asked
    /// for (see [`Shared::ingest`]): the next read takes them in before it reads the socket.
    undigested: bool,
    /// The read was a caller's, and left output for HTTP/2 to send (a credit, an answer to a PING): the caller sends it,
    /// right after (see [`Shared::lead_step`]), and the writer thread is not woken for it.
    send_after: bool,
    news: News,
    wakeups: Vec<Arc<Slot>>,
}

/// How a step of reading ended.
enum Step {
    /// Look again.
    Again,
    /// The transport is over.
    Over,
}

/// Starts the connection's two threads over a socket whose TLS handshake is done and whose server chose `h2`.
pub(super) fn spawn(tcp: TcpStream, permit: Option<Permit>, mut tls: ClientConnection, idle_timeout: Duration, io_timeout: Duration) -> io::Result<Arc<Shared>> {
    tls.grow_recv_buf(RECV_BUF);
    let _ = tcp.set_read_timeout(None);
    let _ = tcp.set_write_timeout(Some(io_timeout));
    let _ = tcp.set_nodelay(true);
    let reader_tcp = tcp.try_clone()?;
    let shared = Arc::new(Shared {
        tls_version: tls.protocol_version(),
        state: Mutex::new(State::new(Connection::new(Config::default()))),
        tls_pending: AtomicBool::new(tls.wants_write()),
        writer_asleep: AtomicBool::new(false),
        write_wanted: AtomicBool::new(false),
        tls: Mutex::new(tls),
        to_writer: Condvar::new(),
        outbox: Mutex::new(Outbox { plain: Vec::with_capacity(WRITE_CHUNK), plain_pos: 0, chunk: Vec::with_capacity(WRITE_CHUNK) }),
        tcp,
        permit: Mutex::new(permit),
        idle_timeout,
        read: Mutex::new(ReadSide { tcp: reader_tcp, rb: None, armed: None, undigested: false, send_after: false, news: News::default(), wakeups: Vec::new() }),
        park: Condvar::new(),
        #[cfg(test)]
        reads: [AtomicUsize::new(0), AtomicUsize::new(0)],
        #[cfg(test)]
        body_bytes: [AtomicUsize::new(0), AtomicUsize::new(0)],
        #[cfg(test)]
        leftovers: [AtomicUsize::new(0), AtomicUsize::new(0)],
        #[cfg(test)]
        writer_wakes: AtomicUsize::new(0),
        #[cfg(test)]
        pause: (Mutex::new(Pause::Off), Condvar::new()),
    });
    {
        // The socket is read into TLS's own receive buffer, which is out of the connection while that goes on (so that the
        // writer is not kept waiting for the lock), and goes back with what was read. What the handshake left in it
        // (records that came along with its end) is digested first. (If that ends the connection there is no buffer, and
        // the reader thread, which starts next, finds the connection over.)
        let mut guard = shared.read.lock().unwrap_or_else(|e| e.into_inner());
        shared.ingest(&mut guard, None, 0, None, false);
    }
    let r = shared.clone();
    thread::Builder::new().name("pratique h2 reader".into()).spawn(move || r.read_loop())?;
    let w = shared.clone();
    if let Err(e) = thread::Builder::new().name("pratique h2 writer".into()).spawn(move || w.write_loop()) {
        shared.end(Lost { peer_closed: false, kind: io::ErrorKind::Other, message: "could not start a thread".into() });
        return Err(e);
    }
    Ok(shared)
}

/// Marks the connection as lost if the thread that holds it ends in any way, a panic included, so that no
/// caller waits for a connection that nobody serves.
struct Leaving<'a> {
    shared: &'a Shared,
    what: &'static str,
}

impl Drop for Leaving<'_> {
    fn drop(&mut self) {
        self.shared.end(Lost { peer_closed: false, kind: io::ErrorKind::Other, message: format!("the HTTP/2 {} thread ended", self.what) });
    }
}

fn tls_lost(e: &Error) -> Lost {
    Lost { peer_closed: false, kind: io::ErrorKind::InvalidData, message: e.to_string() }
}

impl Shared {
    /// The version of TLS the connection speaks.
    pub(super) fn tls_version(&self) -> Option<crate::tls::TlsVersion> {
        self.tls_version
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn tls_lock(&self) -> MutexGuard<'_, ClientConnection> {
        self.tls.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wakes every thread that waits on a stream, whatever it waits for.
    fn wake_all(&self) {
        let mut slots: Vec<Arc<Slot>> = {
            let mut g = self.lock();
            g.parked = Parked::No;
            g.slots.values().cloned().collect()
        };
        self.park.notify_all();
        for slot in slots.drain(..) {
            slot.cv.notify_all();
        }
    }

    /// Records that the transport is over (if it was not already), fails the streams, and wakes everyone.
    fn end(&self, lost: Lost) {
        {
            let mut g = self.lock();
            g.lose(lost);
        }
        self.wake_all();
        self.notify_writer();
        let _ = self.tcp.shutdown(Shutdown::Both);
        self.give_back_slot();
    }

    /// Gives back the connection's slot under a per-host limit: it is over.
    fn give_back_slot(&self) {
        let permit = self.permit.lock().unwrap_or_else(|e| e.into_inner()).take();
        drop(permit);
    }

    // ------------------------------------------------------------------------------------------------ reader

    /// How long the reader may sleep in `read`: until the connection is due to expire if nothing is in flight; a
    /// connection with streams in flight has no such date, and sleeps as long as one that has just become idle would
    /// (the callers have their own deadlines), so that the timeout need not be set again when the streams are done.
    fn read_timeout(&self, g: &State) -> Duration {
        let longest = self.idle_timeout.clamp(Duration::from_millis(5), Duration::from_secs(3600));
        match g.idle_since {
            Some(since) => (since + self.idle_timeout).saturating_duration_since(Instant::now()).clamp(Duration::from_millis(5), longest),
            None => longest,
        }
    }

    /// The reader thread: reads the socket whenever nobody else does, and when the connection has been left alone for
    /// longer than [`PARK_WINDOW`]; see [`Reading`].
    fn read_loop(&self) {
        let _leaving = Leaving { shared: self, what: "reader" };
        loop {
            let mut g = self.lock();
            if g.closing {
                return;
            }
            // Just after a request was answered, with nothing else in flight, the caller of the next one is likely to read
            // its response itself: staying out of the way saves a wake-up of this thread for each response and another
            // of the caller by it.
            if let Some(d) = g.park_for() {
                g.parked = Parked::Idle;
                let (mut g, _) = self.park.wait_timeout(g, d).unwrap_or_else(|e| e.into_inner());
                g.parked = Parked::No;
                continue;
            }
            // (a caller who has not read for a while is not going to: its right is taken)
            if let Baton::Caller { paused_since: Some(t), .. } = g.baton {
                if t.elapsed() >= STALL {
                    g.baton = Baton::Nobody;
                }
            }
            if g.baton != Baton::Nobody {
                // A caller reads for now, and tells this thread when it is done (the time limit is for the case that it
                // could not).
                let wait = match g.baton {
                    Baton::Caller { paused_since: Some(t), .. } => STALL.saturating_sub(t.elapsed()).max(Duration::from_millis(1)),
                    _ => PARK_SAFETY,
                };
                g.parked = Parked::Leader;
                let (mut g, _) = self.park.wait_timeout(g, wait).unwrap_or_else(|e| e.into_inner());
                g.parked = Parked::No;
                continue;
            }
            g.baton = Baton::Reader;
            drop(g);
            let step = {
                let mut side = self.read.lock().unwrap_or_else(|e| e.into_inner());
                self.read_step(&mut side, None, None)
            };
            self.lock().baton = Baton::Nobody;
            if let Step::Over = step {
                return;
            }
        }
    }


    /// The caller who has the right to read the socket reads once, but not past `until`; the body of its stream goes
    /// straight into `direct`'s buffer as far as it can (see [`Connection::feed_direct`]). `false` if the time was up before
    /// there was a read to make.
    fn lead_step(&self, until: Instant, direct: Option<&mut Direct<'_>>) -> bool {
        if Instant::now() >= until {
            return false;
        }
        let mut side = self.read.lock().unwrap_or_else(|e| e.into_inner());
        // (if this ended the transport, the callers find that out by looking at their streams)
        let _ = self.read_step(&mut side, Some(until), direct);
        let send = std::mem::take(&mut side.send_after);
        drop(side);
        if send {
            // what the read left HTTP/2 to say: this thread says it (BACKLOG B-89)
            self.send_now();
        }
        true
    }

    /// One read of the socket, and what follows from it: the plaintext goes to HTTP/2 and the callers whose streams have
    /// news are woken. By the reader thread (`bound` is `None`: it may wait as long as the connection may sit idle), or by
    /// a caller who leads (`bound` is the moment that caller must be heard from again).
    fn read_step(&self, side: &mut ReadSide, bound: Option<Instant>, direct: Option<&mut Direct<'_>>) -> Step {
        let mut wait = {
            let g = self.lock();
            if g.closing {
                return Step::Over;
            }
            self.read_timeout(&g)
        };
        if side.undigested {
            // what the last read left is taken in first (and the socket is not read: what is left may be all the server sends
            // until it hears from us)
            let Some(rb) = side.rb.take() else { return Step::Over };
            // (counted as a read too: what was left is what a read brought, and a caller who takes it in reads for itself)
            #[cfg(test)]
            {
                self.leftovers[bound.is_none() as usize].fetch_add(1, Ordering::Relaxed);
                self.reads[bound.is_none() as usize].fetch_add(1, Ordering::Relaxed);
            }
            return if self.ingest(side, Some(rb), 0, direct, bound.is_some()) { Step::Again } else { Step::Over };
        }
        // (setting the timeout is a system call: it is set again only when what is wanted is noticeably different. For the
        // reader thread that lets a connection that is idle be kept as much as a sixteenth longer than its idle timeout; a
        // caller's wait is cut at 10 ms after its time, which for a caller who is led from one request to the next is no
        // call at all)
        let slack = match bound {
            Some(b) => {
                wait = wait.min(b.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)));
                Duration::from_millis(10)
            }
            None => (wait / 16).max(Duration::from_millis(10)),
        };
        if side.armed.map_or(true, |a| a.abs_diff(wait) > slack) {
            let _ = side.tcp.set_read_timeout(Some(wait));
            side.armed = Some(wait);
        }
        let Some(mut rb) = side.rb.take() else {
            self.end(Lost { peer_closed: false, kind: io::ErrorKind::InvalidData, message: "internal: no receive buffer".into() });
            return Step::Over;
        };
        if rb.space().is_empty() {
            self.end(Lost { peer_closed: false, kind: io::ErrorKind::InvalidData, message: "internal: no room to receive".into() });
            return Step::Over;
        }
        match (&side.tcp).read(rb.space()) {
            Ok(0) => {
                self.eof();
                Step::Over
            }
            Ok(n) => {
                #[cfg(test)]
                self.reads[bound.is_none() as usize].fetch_add(1, Ordering::Relaxed);
                if self.ingest(side, Some(rb), n, direct, bound.is_some()) {
                    Step::Again
                } else {
                    Step::Over
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                side.rb = Some(rb);
                // nothing came: if nothing is in flight either and it has been so for the idle timeout, leave
                let mut g = self.lock();
                if g.h2.active_streams() == 0 && g.idle_since.is_some_and(|t| t.elapsed() >= self.idle_timeout) {
                    g.begin_close(true);
                    drop(g);
                    self.notify_writer();
                    self.wake_all();
                }
                Step::Again
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                side.rb = Some(rb);
                Step::Again
            }
            Err(e) => {
                let peer_closed = matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected | io::ErrorKind::UnexpectedEof);
                self.end(Lost { peer_closed, kind: e.kind(), message: e.to_string() });
                Step::Over
            }
        }
    }

    /// The socket reached end of file.
    fn eof(&self) {
        let closed_properly = self.tls_lock().peer_closed();
        let lost = {
            let g = self.lock();
            if g.closing {
                // we were closing it ourselves
                Lost { peer_closed: false, kind: io::ErrorKind::UnexpectedEof, message: "closed".into() }
            } else if closed_properly {
                Lost { peer_closed: true, kind: io::ErrorKind::UnexpectedEof, message: "the server closed the connection".into() }
            } else {
                Lost { peer_closed: true, kind: io::ErrorKind::UnexpectedEof, message: "the connection was closed without a TLS close_notify".into() }
            }
        };
        self.end(lost);
    }

    /// Hands `n` bytes read from the socket into `rb` (if the buffer is out) through TLS to HTTP/2, and wakes the callers
    /// whose streams have news. Puts the buffer back in `side`, to read into again; false (and no buffer) if the connection
    /// is over.
    ///
    /// The ciphertext is decrypted with `tls` held and `state` free; `state` is taken for each record's plaintext, just
    /// long enough for HTTP/2 to take it in (which is a frame parse and a copy into the stream's buffer, or into the buffer
    /// of the caller who reads, `direct`). A `caller` who reads sends what HTTP/2 has to say itself, at once (the credit for
    /// bytes it read, an answer to a PING, with anything else that was queued): the writer thread is not woken for it. Once
    /// the buffer of a caller who reads its own stream is full, the records that are left are not decrypted now (they would
    /// only be kept in the stream's buffer, and copied out of it later): they stay in the receive buffer, `side.undigested`
    /// says so, and the next read, the caller's next one as a rule, takes them in first, into its buffer.
    fn ingest(&self, side: &mut ReadSide, rb: Option<RecvBuf>, n: usize, mut direct: Option<&mut Direct<'_>>, caller: bool) -> bool {
        let (news, wakeups) = (&mut side.news, &mut side.wakeups);
        side.undigested = false;
        let mut t = self.tls_lock();
        if let Some(rb) = rb {
            t.restore_recv_buf(rb, n);
        }
        let mut over: Option<Lost> = None;
        loop {
            if direct.as_ref().is_some_and(|d| d.full()) {
                side.undigested = true;
                break;
            }
            if let Err(e) = t.process() {
                over = Some(tls_lost(&e));
                break;
            }
            if t.has_plaintext() {
                let n = t.plaintext().len();
                let handled = {
                    let mut g = self.lock();
                    if g.closing {
                        return false;
                    }
                    g.h2.feed_direct(t.plaintext(), direct.as_deref_mut())
                };
                t.consume_plaintext(n);
                if let Err(e) = handled {
                    over = Some(h2_lost(&e));
                    break;
                }
                continue;
            }
            break;
        }
        // all there was is digested (or left for the next read): the buffer goes out again
        let next = if over.is_none() { t.take_recv_buf() } else { None };
        if over.is_none() && next.is_none() {
            over = Some(tls_lost(&Error::Tls("internal: the TLS receive buffer cannot be taken".into())));
        }
        let tls_failed = t.is_failed();
        let tls_output = t.wants_write();
        self.tls_pending.store(tls_output, Ordering::Release);
        drop(t);

        // Taking `state` after `tls_pending` was set is what makes the writer see it: the writer decides to sleep
        // holding `state`, so it either saw the flag, or is asleep by the time this lock is had and is woken below.
        let mut g = self.lock();
        if let Some(lost) = over {
            // what is queued (a fatal alert, a GOAWAY) is sent before the socket is closed
            g.lost = Some(lost);
            g.h2.peer_closed();
            g.closing = true;
            g.flush_first = true;
            g.say_goodbye = !tls_failed;
        }
        g.settle();
        let alive = !g.closing;
        let output = g.h2.wants_write() || tls_output;
        g.h2.take_news(news);
        g.claim_wakeups(news, wakeups);
        if !wakeups.is_empty() && g.h2.active_streams() == 1 {
            g.handover = Some(Instant::now());
        }
        if !alive {
            g.claim_all(wakeups);
        }
        drop(g);
        wake(wakeups);
        // (a caller who read sends what is queued itself, right after: see `lead_step`)
        side.send_after = caller && output && alive && !tls_output;
        if (output && !side.send_after) || !alive {
            self.notify_writer();
        }
        side.rb = if alive { next } else { None };
        side.rb.is_some()
    }

    // ------------------------------------------------------------------------------------------------ writer

    /// Ends the writer's work with the transport lost.
    fn writer_lost(&self, lost: Lost) {
        self.lock().lose(lost);
    }

    fn write_loop(&self) {
        let _leaving = Leaving { shared: self, what: "writer" };
        let mut wakeups: Vec<Arc<Slot>> = Vec::new();
        loop {
            // sleep until there is something to do
            {
                let mut g = self.lock();
                while !(g.closing || g.h2.wants_write() || self.tls_pending.load(Ordering::Acquire)) {
                    self.writer_asleep.store(true, Ordering::SeqCst);
                    g = self.to_writer.wait(g).unwrap_or_else(|e| e.into_inner());
                    self.writer_asleep.store(false, Ordering::SeqCst);
                    #[cfg(test)]
                    self.writer_wakes.fetch_add(1, Ordering::Relaxed);
                }
            }
            let mut outbox = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                match self.write_round(&mut outbox, &mut wakeups) {
                    Round::Wrote => {}
                    Round::Idle => break,
                    Round::Over => {
                        drop(outbox);
                        self.wake_all();
                        let _ = self.tcp.shutdown(Shutdown::Both);
                        self.give_back_slot();
                        return;
                    }
                }
            }
        }
    }

    /// Sends what HTTP/2 and TLS have queued on this thread, which saves waking the writer thread (and the wait for it to be
    /// scheduled) for the one request a caller makes. If another thread is writing, that one sends it too: it looks at
    /// `write_wanted` when it lets go of the outbox, and goes on if it is set (so eight callers that start requests at once
    /// do not wake the writer thread for the seven that find the outbox taken: BACKLOG B-89). If there is more than a few
    /// rounds' worth to write, the writer thread is woken instead, and does it.
    fn send_now(&self) {
        if self.lock().h2.output().len() > WRITE_CHUNK {
            self.notify_writer();
            return;
        }
        // (the fences pair with the holder's: either the holder sees the flag, or this thread finds the outbox free)
        self.write_wanted.store(true, Ordering::SeqCst);
        std::sync::atomic::fence(Ordering::SeqCst);
        let mut wakeups: Vec<Arc<Slot>> = Vec::new();
        loop {
            let Ok(mut outbox) = self.outbox.try_lock() else { return };
            self.write_wanted.store(false, Ordering::SeqCst);
            let mut idle = false;
            for _ in 0..4 {
                match self.write_round(&mut outbox, &mut wakeups) {
                    Round::Wrote => {}
                    Round::Idle => {
                        idle = true;
                        break;
                    }
                    Round::Over => break,
                }
            }
            #[cfg(test)]
            if idle {
                self.pause_point();
            }
            drop(outbox);
            if !idle {
                // what is left, and a transport that is over, are for the writer thread
                self.notify_writer();
                return;
            }
            std::sync::atomic::fence(Ordering::SeqCst);
            if !self.write_wanted.load(Ordering::SeqCst) {
                return;
            }
            // somebody queued output while this thread wrote, and found the outbox taken: it is this thread's to send
        }
    }

    /// Wakes the writer thread if it is asleep. Whoever calls this has queued what there is to do (output, or the end of the
    /// connection) with `state` held, after which the writer either sees it before it goes to sleep, or is asleep (it says
    /// so with `state` held) and is woken here.
    fn notify_writer(&self) {
        if self.writer_asleep.load(Ordering::SeqCst) {
            self.to_writer.notify_all();
        }
    }

    /// One round of writing, by whoever holds the outbox: take what HTTP/2 has queued (a bounded amount) under `state`,
    /// encrypt it and take a piece of what TLS has to send under `tls`, and write that to the socket with nothing held.
    fn write_round(&self, ob: &mut Outbox, wakeups: &mut Vec<Arc<Slot>>) -> Round {
        // 1. under `state`: take what HTTP/2 has queued
        let (closing, goodbye, more) = {
            let mut g = self.lock();
            if g.closing && !g.flush_first {
                drop(g);
                wake(wakeups);
                return Round::Over;
            }
            if ob.plain_pos == ob.plain.len() {
                ob.plain.clear();
                ob.plain_pos = 0;
                if g.h2.wants_write() {
                    let out = g.h2.output();
                    let n = out.len().min(WRITE_CHUNK);
                    ob.plain.extend_from_slice(&out[..n]);
                    g.h2.consume_output(n);
                    // room in the output: a caller that waited to send a body may go on
                    if g.senders > 0 {
                        g.claim_all(wakeups);
                    }
                }
            }
            if !(ob.plain_pos < ob.plain.len() || self.tls_pending.load(Ordering::Acquire) || g.closing) {
                return Round::Idle;
            }
            (g.closing, g.say_goodbye, g.h2.wants_write())
        };
        wake(wakeups);

        // 2. under `tls`: encrypt it, and take a piece of what TLS has to send
        let mut finished = false;
        ob.chunk.clear();
        {
            let mut t = self.tls_lock();
            if ob.plain_pos < ob.plain.len() {
                if t.write_closed() {
                    // nothing more can be sent
                    ob.plain.clear();
                    ob.plain_pos = 0;
                } else {
                    match t.write_plaintext(&ob.plain[ob.plain_pos..]) {
                        Ok(n) => ob.plain_pos += n,
                        Err(e) => {
                            drop(t);
                            self.writer_lost(tls_lost(&e));
                            return Round::Over;
                        }
                    }
                }
            }
            if closing && ob.plain_pos >= ob.plain.len() && !more && !t.wants_write() {
                // all that was queued is out: say goodbye, or be done
                if goodbye && !t.write_closed() {
                    t.send_close_notify();
                }
                finished = !t.wants_write();
            }
            if t.wants_write() {
                let n = t.output().len().min(WRITE_CHUNK);
                ob.chunk.extend_from_slice(&t.output()[..n]);
                t.consume_output(n);
            }
            self.tls_pending.store(t.wants_write(), Ordering::Release);
        }

        // 3. the socket, with nothing held
        if !ob.chunk.is_empty() {
            if let Err(e) = (&self.tcp).write_all(&ob.chunk) {
                let peer_closed = matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe);
                self.writer_lost(Lost { peer_closed, kind: e.kind(), message: e.to_string() });
                return Round::Over;
            }
        }
        if finished {
            return Round::Over;
        }
        Round::Wrote
    }

    // ------------------------------------------------------------------------------------------------ callers

    /// How the connection looks to a request choosing one.
    fn probe(&self) -> Probe {
        let g = self.lock();
        if !g.alive() {
            Probe::Dead
        } else if !g.h2.can_open_stream() {
            Probe::Full
        } else {
            Probe::Open(g.h2.active_streams())
        }
    }

    fn is_alive(&self) -> bool {
        self.lock().alive()
    }

    /// The caller who has the right to read the socket at this moment, if one has: its stream, and whether it has stopped
    /// reading for the moment (tests of the transport).
    #[cfg(test)]
    pub(super) fn reading_caller(&self) -> Option<(u32, bool)> {
        match self.lock().baton {
            Baton::Caller { stream, paused_since } => Some((stream, paused_since.is_some())),
            Baton::Nobody | Baton::Reader => None,
        }
    }

    /// Whether the last read left records in the receive buffer for the next one (see [`Shared::ingest`]); `None` if somebody
    /// is reading (tests of the transport).
    #[cfg(test)]
    pub(super) fn undigested(&self) -> Option<bool> {
        self.read.try_lock().ok().map(|side| side.undigested)
    }

    /// Whether HTTP/2 has output queued that nobody has taken to send (tests of the transport).
    #[cfg(test)]
    pub(super) fn output_queued(&self) -> bool {
        self.lock().h2.wants_write()
    }

    /// Where a caller that sends is held, if a test armed the pause (tests of the transport).
    #[cfg(test)]
    fn pause_point(&self) {
        let (m, cv) = &self.pause;
        let mut p = m.lock().unwrap_or_else(|e| e.into_inner());
        if *p == Pause::Armed {
            *p = Pause::Held;
            cv.notify_all();
            while *p == Pause::Held {
                p = cv.wait(p).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    /// Arms the pause, waits until a caller is held in it, and lets it go (tests of the transport).
    #[cfg(test)]
    pub(super) fn set_pause(&self, to: Pause) {
        let (m, cv) = &self.pause;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = to;
        cv.notify_all();
    }

    #[cfg(test)]
    pub(super) fn wait_for_pause(&self, held: Pause) {
        let (m, cv) = &self.pause;
        let mut p = m.lock().unwrap_or_else(|e| e.into_inner());
        while *p != held {
            p = cv.wait(p).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// How many times the writer thread was woken (tests of the transport).
    #[cfg(test)]
    pub(super) fn writer_wakes(&self) -> usize {
        self.writer_wakes.load(Ordering::Relaxed)
    }

    /// How many times callers, and the reader thread, took in what a read had left (tests of the transport).
    #[cfg(test)]
    pub(super) fn leftovers(&self) -> (usize, usize) {
        (self.leftovers[0].load(Ordering::Relaxed), self.leftovers[1].load(Ordering::Relaxed))
    }

    /// True if no stream is in flight (so that a client that is closing its idle connections may close this one).
    fn is_idle(&self) -> bool {
        let g = self.lock();
        g.alive() && g.h2.active_streams() == 0
    }

    /// Closes the connection if nothing is in flight.
    fn close_if_idle(&self) {
        let closed = {
            let mut g = self.lock();
            let idle = g.h2.active_streams() == 0;
            if idle {
                g.begin_close(true);
            }
            idle
        };
        if closed {
            self.notify_writer();
            self.wake_all();
        }
    }

    /// The client that owns the connection is gone: it closes when its streams are done.
    fn retire(&self) {
        let mut g = self.lock();
        g.retired = true;
        g.settle();
        let closing = g.closing;
        if closing {
            g.parked = Parked::No;
        }
        drop(g);
        if closing {
            self.notify_writer();
            self.park.notify_all();
        }
    }

    /// Waits for news about the stream whose slot this is, but not past `until`. `Err(())` if the time is up. (Spurious
    /// returns happen: the caller looks again.) The news comes from whoever reads the socket: the reader thread, which
    /// this wakes if it is out of the way, or a caller who leads (see [`Reading`]).
    fn wait_on<'a>(&'a self, mut g: MutexGuard<'a, State>, slot: &Slot, until: Instant, can_lead: bool) -> Result<MutexGuard<'a, State>, ()> {
        let now = Instant::now();
        if now >= until {
            return Err(());
        }
        // whoever sleeps here needs the socket read: by the reader thread, which is woken if it is out of the way because the
        // connection was idle, or is given the right of a caller who has stopped reading
        let mut taken = false;
        if let Baton::Caller { paused_since: Some(_), .. } = g.baton {
            g.baton = Baton::Nobody;
            taken = true;
        }
        if g.parked == Parked::Idle || (taken && g.parked == Parked::Leader) {
            g.parked = Parked::No;
            g.handover = None;
            self.park.notify_one();
        }
        slot.waiting.store(true, Ordering::Relaxed);
        slot.can_lead.store(can_lead, Ordering::Relaxed);
        let (g, _) = slot.cv.wait_timeout(g, until - now).unwrap_or_else(|e| e.into_inner());
        slot.waiting.store(false, Ordering::Relaxed);
        Ok(g)
    }

    /// Stops the request on stream `id` (its batch was cancelled): its caller's wait ends with `Error::Cancelled` (the
    /// stream is reset when the caller drops it), and the server is pinged, so that a caller who is reading the socket
    /// for the others hears something within a round trip.
    pub(super) fn cancel_stream(&self, id: u32) {
        let slot = {
            let mut g = self.lock();
            let Some(slot) = g.slots.get(&id).cloned() else { return };
            if !g.cancelled.contains(&id) {
                g.cancelled.push(id);
            }
            if !g.closing {
                g.h2.ping(*b"tinycncl");
            }
            slot
        };
        self.notify_writer();
        slot.cv.notify_all();
    }

    /// Turns what went wrong with a stream into what the caller needs to know.
    fn failure(g: &State, e: StreamError, got_head: bool) -> Failure {
        match &g.lost {
            Some(l) => {
                let what = if got_head { "while the response was coming" } else { "before the response came" };
                Failure {
                    error: Error::Io(io::Error::new(l.kind, format!("{} ({what})", l.message))),
                    retry_safe: e.retry_safe && !got_head,
                    peer_closed: l.peer_closed && !got_head,
                }
            }
            None => Failure { error: Error::Http(e.to_string()), retry_safe: e.retry_safe && !got_head, peer_closed: false },
        }
    }

    /// Opens a stream for the request and sends its body. Returns once the body is on its way (not once it has
    /// been answered); see [`H2Stream::head`].
    ///
    /// If nobody is reading the socket (or the one who does is not using the right to), the caller reads it itself while it
    /// waits for the answer (see [`Reading`]), and takes the right to at once, here, with the lock that opened the stream
    /// held, so that the reader thread cannot take it between the request and the wait.
    pub(super) fn start(self: &Arc<Self>, request: &Request<'_>, body: &[u8], waits: Waits) -> Result<H2Stream, StartError> {
        let mut g = self.lock();
        if !g.alive() {
            return Err(StartError::Unavailable);
        }
        let id = match g.h2.open_stream(request, body.is_empty()) {
            Ok(id) => id,
            Err(OpenError::Full) => return Err(StartError::Full),
            Err(OpenError::Unavailable) => return Err(StartError::Unavailable),
            Err(OpenError::Invalid(why)) => {
                return Err(StartError::Failed(Failure { error: Error::Http(format!("the request cannot be sent over HTTP/2: {why}")), retry_safe: false, peer_closed: false }))
            }
        };
        g.idle_since = None;
        let slot = Slot::new();
        g.slots.insert(id, slot.clone());
        let stream = H2Stream { shared: self.clone(), id, slot, ended: false, got_head: false, carry: Vec::new(), carry_pos: 0 };
        // the body, as the windows and the output allow; a stream that fails meanwhile is found out when the head is waited for
        let mut sent = 0;
        while !body.is_empty() && sent < body.len() {
            self.notify_writer();
            match g.h2.send_data(id, &body[sent..], true) {
                Ok(n) => sent += n,
                Err(_) => break,
            }
            if sent == body.len() {
                break;
            }
            if g.closing {
                break;
            }
            if let Some(f) = g.cancelled(id) {
                return Err(StartError::Failed(f));
            }
            let until = waits.until();
            g.senders += 1;
            // (a caller who waits to send cannot read the socket meanwhile: it is not given the right)
            let waited = self.wait_on(g, &stream.slot, until, false);
            g = match waited {
                Ok(mut g) => {
                    g.senders -= 1;
                    g
                }
                Err(()) => {
                    // the stream is dropped (and cancelled) as the error goes out
                    self.lock().senders -= 1;
                    return Err(StartError::Failed(Failure { error: waits.expired(), retry_safe: false, peer_closed: false }));
                }
            };
        }
        g.claim_baton(id);
        drop(g);
        self.send_now();
        Ok(stream)
    }
}

/// What a caller does with the right to read the socket (see [`Reading`]) when it is done waiting: it keeps it, for a
/// streamed response that it will ask more of, or gives it back. A caller who sends a request and then sleeps until the
/// reader thread has read the response and woken it costs two thread switches for the response (the reader thread wakes
/// up for the data, and the caller wakes up for the reader thread); one that reads the response itself costs one, as
/// HTTP/1.1 does. A request takes the right when it is started, if nobody has it (the connection has been quiet for a
/// moment: the reader thread is out of the way, see [`PARK_WINDOW`]), and for each request after the first of a run of
/// requests that follow each other; and a response that is read in pieces, by a caller who is the only one on the
/// connection, keeps it between the reads, so that a download is read, decrypted and handed over by one thread, with no
/// hand-off of the data between two (a download that began when the reader thread was reading is taken over by its caller
/// when the reader thread has woken it with news and stepped aside for it, see [`State::park_for`]; so is one whose caller
/// was away for longer than [`STALL`]). Whatever else is in flight on the connection when a caller lets go is read by the
/// reader thread, which is told; and anyone who has to wait for news takes the right from a caller who is not reading.
/// This is made when it is dropped, and so on every way out of a wait, an unwind included.
struct Reading<'a> {
    shared: &'a Shared,
    stream: u32,
    /// Keep the right (if this stream is the only one) instead of giving it back.
    keep: bool,
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        let handoff = self.shared.lock().rest_baton(self.stream, self.keep);
        handoff.wake(self.shared);
    }
}

/// How an HTTP/2 connection error looks to the callers that were on the connection.
fn h2_lost(e: &ConnectionError) -> Lost {
    // the server's own GOAWAY with an error, or our complaint about the server: a protocol matter, not a closed socket
    Lost { peer_closed: false, kind: io::ErrorKind::Other, message: e.to_string() }
}

/// One request on a shared connection: its stream. Dropping it gives the stream up.
pub(super) struct H2Stream {
    shared: Arc<Shared>,
    id: u32,
    slot: Arc<Slot>,
    ended: bool,
    got_head: bool,
    /// Body bytes taken from the connection (by swapping buffers: [`Connection::take_stream_data`]) that the caller has not
    /// read yet: `carry[carry_pos..]`. They are copied out without any lock held.
    carry: Vec<u8>,
    carry_pos: usize,
}

impl H2Stream {
    /// This stream's caller has the right to read the socket (tests of the transport).
    #[cfg(test)]
    pub(super) fn leads(&self) -> bool {
        matches!(self.shared.lock().baton, Baton::Caller { stream, .. } if stream == self.id)
    }

    /// This stream's id (tests of the transport).
    #[cfg(test)]
    pub(super) fn id(&self) -> u32 {
        self.id
    }

    /// What stops this stream's request from another thread (see [`Shared::cancel_stream`]).
    pub(super) fn canceller(&self) -> impl Fn() + Send + Sync + 'static {
        let (shared, id) = (self.shared.clone(), self.id);
        move || shared.cancel_stream(id)
    }

    /// Waits for the head of the response (interim responses are skipped by the HTTP/2 layer).
    pub(super) fn head(&mut self, waits: Waits) -> Result<Head, Failure> {
        let shared = self.shared.clone();
        // (declared before the lock is taken, so that the right to read is let go of, and the reader thread is told, after it)
        let mut reading = Reading { shared: &shared, stream: self.id, keep: false };
        self.head_reading(&shared, &mut reading, waits)
    }

    fn head_reading(&mut self, shared: &Shared, reading: &mut Reading<'_>, waits: Waits) -> Result<Head, Failure> {
        let until = waits.until();
        let mut g = shared.lock();
        loop {
            if let Some(f) = g.cancelled(self.id) {
                return Err(f);
            }
            match g.h2.poll_stream(self.id, &mut []) {
                StreamEvent::Head(h) => {
                    self.got_head = true;
                    // the body is read next, by the same thread
                    reading.keep = true;
                    return Ok(h);
                }
                StreamEvent::Failed(e) => return Err(Shared::failure(&g, e, false)),
                StreamEvent::Pending => {}
                // the HTTP/2 layer gives the head first
                other => {
                    return Err(Failure { error: Error::Http(format!("internal: {other:?} before the response head")), retry_safe: false, peer_closed: false });
                }
            }
            if g.claim_baton(self.id) {
                drop(g);
                if !shared.lead_step(until, None) {
                    return Err(Failure { error: waits.expired(), retry_safe: false, peer_closed: false });
                }
                g = shared.lock();
            } else {
                g = match shared.wait_on(g, &self.slot, until, true) {
                    Ok(g) => g,
                    Err(()) => return Err(Failure { error: waits.expired(), retry_safe: false, peer_closed: false }),
                };
            }
        }
    }

    /// Reads body bytes into `out`; 0 is the end of the body (and of the stream).
    pub(super) fn read(&mut self, out: &mut [u8], waits: Waits) -> Result<usize, Failure> {
        if out.is_empty() || self.ended {
            return Ok(0);
        }
        // what was taken before and not yet handed out
        if self.carry_pos < self.carry.len() {
            return Ok(self.hand_out(out));
        }
        let shared = self.shared.clone();
        let mut reading = Reading { shared: &shared, stream: self.id, keep: false };
        self.read_reading(&shared, &mut reading, out, waits)
    }

    fn read_reading(&mut self, shared: &Shared, reading: &mut Reading<'_>, out: &mut [u8], waits: Waits) -> Result<usize, Failure> {
        let mut until: Option<Instant> = None;
        let mut g = shared.lock();
        loop {
            if let Some(f) = g.cancelled(self.id) {
                return Err(f);
            }
            match g.h2.take_stream_data(self.id, &mut self.carry) {
                StreamEvent::Data(_n) => {
                    #[cfg(test)]
                    shared.body_bytes[1].fetch_add(_n, Ordering::Relaxed);
                    let credit = g.h2.wants_write();
                    drop(g);
                    if credit {
                        // the peer is given room to send more
                        shared.send_now();
                    }
                    self.carry_pos = 0;
                    // more is asked for next, probably by this thread
                    reading.keep = true;
                    return Ok(self.hand_out(out));
                }
                // trailers are read and dropped
                StreamEvent::Trailers(_) | StreamEvent::Head(_) => continue,
                StreamEvent::End => {
                    self.ended = true;
                    return Ok(0);
                }
                StreamEvent::Failed(e) => return Err(Shared::failure(&g, e, true)),
                StreamEvent::Pending => {}
            }
            let until = *until.get_or_insert_with(|| waits.until());
            if g.claim_baton(self.id) {
                drop(g);
                // This thread reads the socket, and nothing of the body is waiting (the poll above found nothing): what comes
                // for this stream is decrypted, parsed and written straight into `out`, without the stream's buffer and a
                // copy out of it in between (BACKLOG B-87). What does not fit is kept as usual, for the next read.
                let mut direct = Direct::new(self.id, out);
                if !shared.lead_step(until, Some(&mut direct)) {
                    return Err(Failure { error: waits.expired(), retry_safe: false, peer_closed: false });
                }
                let n = direct.written();
                #[cfg(test)]
                shared.body_bytes[0].fetch_add(n, Ordering::Relaxed);
                g = shared.lock();
                if n > 0 {
                    // (the credit for those bytes is on its way: `lead_step` sent what the read queued)
                    if let Some(f) = g.cancelled(self.id) {
                        return Err(f);
                    }
                    reading.keep = true;
                    return Ok(n);
                }
            } else {
                g = match shared.wait_on(g, &self.slot, until, true) {
                    Ok(g) => g,
                    Err(()) => return Err(Failure { error: waits.expired(), retry_safe: false, peer_closed: false }),
                };
            }
        }
    }

    /// Waits for the whole of what is left of the response and returns it as one buffer, which is the one the connection
    /// has been keeping the body in as it came: it is not copied out, and the server is given credit for it as it
    /// arrives (see [`Connection::collect_stream`]), not as it is read. `limit` bounds the body, all told. The thread
    /// sleeps until the response is complete or has failed; the time `waits` allows without progress is the time without
    /// a byte of the body, not the time the whole of it takes.
    pub(super) fn collect(&mut self, limit: u64, waits: Waits) -> Result<Vec<u8>, Failure> {
        // what was taken before and not yet handed out comes first
        let front: Vec<u8> = if self.carry_pos < self.carry.len() { self.carry[self.carry_pos..].to_vec() } else { Vec::new() };
        self.carry = Vec::new();
        self.carry_pos = 0;
        if self.ended {
            return Ok(front);
        }
        let (_, mut body) = self.wait_collected(limit, waits)?;
        if !front.is_empty() {
            body.splice(0..0, front);
        }
        Ok(body)
    }

    /// The head and the body of the response, both, with one wait: the thread is not woken for the head (the server
    /// usually sends the head and the body in different segments) and again for the body, only once for the whole. As
    /// [`H2Stream::collect`] otherwise.
    pub(super) fn response(&mut self, limit: u64, waits: Waits) -> Result<(Head, Vec<u8>), Failure> {
        let (head, body) = self.wait_collected(limit, waits)?;
        match head {
            Some(head) => {
                self.got_head = true;
                Ok((head, body))
            }
            None => Err(Failure { error: Error::Http("internal: a response without a head".into()), retry_safe: false, peer_closed: false }),
        }
    }

    /// Sets the stream collecting and waits until it is done: its head if it was not taken and the body.
    fn wait_collected(&mut self, limit: u64, waits: Waits) -> Result<(Option<Head>, Vec<u8>), Failure> {
        let shared = self.shared.clone();
        // (outside the function that holds the state lock, so that the right to read goes back, and the reader thread is told,
        // with the lock let go)
        let _reading = Reading { shared: &shared, stream: self.id, keep: false };
        self.wait_collected_reading(&shared, limit, waits)
    }

    fn wait_collected_reading(&mut self, shared: &Shared, limit: u64, waits: Waits) -> Result<(Option<Head>, Vec<u8>), Failure> {
        let mut body = Vec::new();
        let mut g = shared.lock();
        g.h2.collect_stream(self.id, limit);
        let mut seen: Option<u64> = None;
        let mut until = waits.until();
        let mut timed_out = false;
        loop {
            if let Some(f) = g.cancelled(self.id) {
                return Err(f);
            }
            match g.h2.collected(self.id, &mut body) {
                Collected::Done(head) => {
                    self.ended = true;
                    return Ok((head, body));
                }
                Collected::Failed { error, got_head } => {
                    if error.reason == BODY_TOO_BIG {
                        return Err(Failure { error: Error::Http(BODY_TOO_BIG.into()), retry_safe: false, peer_closed: false });
                    }
                    return Err(Shared::failure(&g, error, got_head));
                }
                Collected::Pending(progress) => {
                    let moved = seen != Some(progress);
                    if waits.deadline.is_some_and(|d| Instant::now() >= d) || (timed_out && !moved) {
                        return Err(Failure { error: waits.expired(), retry_safe: false, peer_closed: false });
                    }
                    if moved {
                        seen = Some(progress);
                        until = waits.until();
                    }
                    timed_out = false;
                }
            }
            if g.claim_baton(self.id) {
                // nobody else reads: this thread does, and finds out itself when the response is whole
                drop(g);
                timed_out = !shared.lead_step(until, None);
                g = shared.lock();
            } else {
                g = match shared.wait_on(g, &self.slot, until, true) {
                    Ok(g) => g,
                    Err(()) => {
                        // the time is up: the next look tells whether bytes came meanwhile, in which case the wait goes on
                        timed_out = true;
                        shared.lock()
                    }
                };
            }
        }
    }

    /// Copies from what was taken into `out`.
    fn hand_out(&mut self, out: &mut [u8]) -> usize {
        let n = (self.carry.len() - self.carry_pos).min(out.len());
        out[..n].copy_from_slice(&self.carry[self.carry_pos..self.carry_pos + n]);
        self.carry_pos += n;
        n
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        let shared = &self.shared;
        let mut g = shared.lock();
        let before = g.h2.output().len();
        g.h2.release_stream(self.id);
        g.slots.remove(&self.id);
        g.cancelled.retain(|id| *id != self.id);
        g.settle();
        // what giving the stream up queued (a reset, a credit), which this thread sends; output that was queued before is
        // somebody else's to send, and the writer thread is not woken for it (BACKLOG B-89)
        let queued = g.h2.output().len() > before;
        let closing = g.closing;
        // (the right to read, if this stream's caller has it)
        let handoff = g.rest_baton(self.id, false);
        drop(g);
        if closing {
            shared.notify_writer();
        } else if queued {
            shared.send_now();
        }
        handoff.wake(shared);
    }
}

// ---------------------------------------------------------------------------------------------------- registry

/// What a request finds when it asks for a connection to an origin.
pub(super) enum Acquired {
    /// A live connection with room for another stream.
    Conn(Arc<Shared>),
    /// There is none: the caller dials, and tells the registry how it went through the ticket.
    Dial(Ticket),
    /// The origin did not choose HTTP/2 the last time: use HTTP/1.1.
    Http1,
}

#[derive(Default)]
struct Origin {
    conns: Vec<Arc<Shared>>,
    dialing: bool,
    http1_since: Option<Instant>,
}

/// A client's HTTP/2 connections, by origin.
pub(super) struct Registry {
    origins: Mutex<HashMap<Key, Origin>>,
    changed: Condvar,
}

impl Registry {
    pub(super) fn new() -> Registry {
        Registry { origins: Mutex::new(HashMap::new()), changed: Condvar::new() }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Key, Origin>> {
        self.origins.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A connection to `key` that can take a request, or the duty to dial one, or the news that the origin speaks
    /// HTTP/1.1. Waits (up to `wait`, or the request's deadline) while another request is dialing.
    pub(super) fn acquire(self: &Arc<Self>, key: &Key, waits: Waits, wait: Duration) -> Result<Acquired, Error> {
        let give_up = {
            let now = Instant::now();
            let by_wait = now.checked_add(wait).unwrap_or_else(|| now + Duration::from_secs(3600));
            waits.deadline.map_or(by_wait, |d| by_wait.min(d))
        };
        let mut map = self.lock();
        loop {
            let origin = map.entry(key.clone()).or_default();
            // the least loaded of those that can take a stream (one look at each connection)
            let mut best: Option<(usize, &Arc<Shared>)> = None;
            let mut dead = false;
            for c in &origin.conns {
                match c.probe() {
                    Probe::Dead => dead = true,
                    Probe::Full => {}
                    Probe::Open(load) => {
                        if best.is_none_or(|(l, _)| load < l) {
                            best = Some((load, c));
                        }
                    }
                }
            }
            let best = best.map(|(_, c)| c.clone());
            if dead {
                origin.conns.retain(|c| c.is_alive());
            }
            if let Some(c) = best {
                return Ok(Acquired::Conn(c));
            }
            match origin.http1_since {
                Some(t) if t.elapsed() < HTTP1_MEMORY => return Ok(Acquired::Http1),
                _ => origin.http1_since = None,
            }
            if !origin.dialing {
                origin.dialing = true;
                return Ok(Acquired::Dial(Ticket { registry: self.clone(), key: key.clone(), settled: false }));
            }
            let now = Instant::now();
            if now >= give_up {
                return Err(waits.expired());
            }
            map = self.changed.wait_timeout(map, give_up - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }

    /// Closes the connections that have no stream in flight.
    pub(super) fn close_idle(&self) {
        let conns: Vec<Arc<Shared>> = self.lock().values().flat_map(|o| o.conns.iter().cloned()).collect();
        for c in conns {
            c.close_if_idle();
        }
    }

    /// The first of the connections, if there is one (tests of the transport).
    #[cfg(test)]
    pub(super) fn any_connection(&self) -> Option<Arc<Shared>> {
        self.lock().values().flat_map(|o| o.conns.iter().cloned()).next()
    }

    /// How many reads of the sockets callers made, and how many the reader threads did, on all the connections.
    #[cfg(test)]
    pub(super) fn reads(&self) -> (usize, usize) {
        let conns: Vec<Arc<Shared>> = self.lock().values().flat_map(|o| o.conns.iter().cloned()).collect();
        conns.iter().fold((0, 0), |(a, b), c| (a + c.reads[0].load(Ordering::Relaxed), b + c.reads[1].load(Ordering::Relaxed)))
    }

    /// How many bytes of bodies read in pieces went straight into the callers' buffers, and how many through the streams'
    /// buffers, on all the connections.
    #[cfg(test)]
    pub(super) fn body_bytes(&self) -> (usize, usize) {
        let conns: Vec<Arc<Shared>> = self.lock().values().flat_map(|o| o.conns.iter().cloned()).collect();
        conns.iter().fold((0, 0), |(a, b), c| (a + c.body_bytes[0].load(Ordering::Relaxed), b + c.body_bytes[1].load(Ordering::Relaxed)))
    }

    /// How many connections have no stream in flight.
    pub(super) fn idle(&self) -> usize {
        let conns: Vec<Arc<Shared>> = self.lock().values().flat_map(|o| o.conns.iter().cloned()).collect();
        conns.iter().filter(|c| c.is_idle()).count()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let origins = std::mem::take(&mut *self.origins.lock().unwrap_or_else(|e| e.into_inner()));
        for origin in origins.into_values() {
            for c in origin.conns {
                c.retire();
            }
        }
    }
}

/// The duty to dial a connection to an origin, held by the request that has been told to. Requests to the
/// origin wait for it to be settled.
pub(super) struct Ticket {
    registry: Arc<Registry>,
    key: Key,
    settled: bool,
}

impl Ticket {
    /// The dial gave an HTTP/2 connection: it is shared from now on.
    pub(super) fn h2(mut self, conn: Arc<Shared>) {
        self.settled = true;
        {
            let mut map = self.registry.lock();
            let origin = map.entry(self.key.clone()).or_default();
            origin.conns.push(conn);
            origin.dialing = false;
            origin.http1_since = None;
        }
        self.registry.changed.notify_all();
    }

    /// The server chose HTTP/1.1.
    pub(super) fn http1(mut self) {
        self.settled = true;
        {
            let mut map = self.registry.lock();
            let origin = map.entry(self.key.clone()).or_default();
            origin.dialing = false;
            origin.http1_since = Some(Instant::now());
        }
        self.registry.changed.notify_all();
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.settled {
            // the dial failed: whoever waits may try for themselves
            {
                let mut map = self.registry.lock();
                if let Some(origin) = map.get_mut(&self.key) {
                    origin.dialing = false;
                }
            }
            self.registry.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    //! The rules of who reads the socket, on the state alone (the tests with a connection and a server are in `h2_client_tests`).
    use super::*;

    fn state() -> State {
        State::new(Connection::new(Config::default()))
    }

    fn open(s: &mut State) -> u32 {
        let request = Request { method: "GET", scheme: "https", authority: "x", path: "/", headers: &[], secret: &[] };
        s.h2.open_stream(&request, true).ok().expect("a stream is opened")
    }

    fn paused() -> Option<Instant> {
        Some(Instant::now())
    }

    #[test]
    fn the_right_to_read_goes_to_whoever_asks_if_nobody_uses_it() {
        let mut s = state();
        assert!(s.claim_baton(1));
        assert_eq!(s.baton, Baton::Caller { stream: 1, paused_since: None });
        // the owner may ask again; nobody else takes it from a caller who is reading
        assert!(s.claim_baton(1));
        assert!(!s.claim_baton(3));
        assert_eq!(s.baton, Baton::Caller { stream: 1, paused_since: None });
        // the reader thread's read is not interrupted
        s.baton = Baton::Reader;
        assert!(!s.claim_baton(1));
        assert_eq!(s.baton, Baton::Reader);
    }

    #[test]
    fn the_right_to_read_is_taken_from_a_caller_who_has_stopped_reading() {
        let mut s = state();
        s.baton = Baton::Caller { stream: 1, paused_since: paused() };
        assert!(s.claim_baton(3));
        assert_eq!(s.baton, Baton::Caller { stream: 3, paused_since: None });
    }

    #[test]
    fn nobody_is_given_the_right_to_read_a_transport_that_is_going_away() {
        let mut s = state();
        s.begin_close(false);
        assert!(!s.claim_baton(1));
        assert_eq!(s.baton, Baton::Nobody);
        let mut s = state();
        s.baton = Baton::Caller { stream: 1, paused_since: paused() };
        s.begin_close(false);
        assert!(!s.claim_baton(3));
    }

    #[test]
    fn only_the_owner_lets_go_of_the_right_to_read() {
        let mut s = state();
        s.baton = Baton::Caller { stream: 1, paused_since: None };
        assert!(matches!(s.rest_baton(3, false), Handoff::Nobody));
        assert_eq!(s.baton, Baton::Caller { stream: 1, paused_since: None });
        assert!(matches!(s.rest_baton(3, true), Handoff::Nobody));
        assert_eq!(s.baton, Baton::Caller { stream: 1, paused_since: None });
        s.baton = Baton::Reader;
        assert!(matches!(s.rest_baton(1, false), Handoff::Nobody));
        assert_eq!(s.baton, Baton::Reader);
    }

    #[test]
    fn a_caller_keeps_the_right_between_reads_only_while_it_is_alone() {
        let mut s = state();
        let a = open(&mut s);
        s.baton = Baton::Caller { stream: a, paused_since: None };
        assert!(matches!(s.rest_baton(a, true), Handoff::Nobody));
        assert!(matches!(s.baton, Baton::Caller { stream, paused_since: Some(_) } if stream == a));
        // not when it is not asked to
        s.baton = Baton::Caller { stream: a, paused_since: None };
        assert!(matches!(s.rest_baton(a, false), Handoff::Nobody));
        assert_eq!(s.baton, Baton::Nobody);
        // and not when another request is in flight: it is given back, and the reader thread, if it waits, is told
        let _b = open(&mut s);
        s.baton = Baton::Caller { stream: a, paused_since: None };
        s.parked = Parked::Leader;
        assert!(matches!(s.rest_baton(a, true), Handoff::Reader));
        assert_eq!(s.baton, Baton::Nobody);
        assert_eq!(s.parked, Parked::No);
        // (nobody is told if it does not wait)
        s.baton = Baton::Caller { stream: a, paused_since: None };
        s.parked = Parked::No;
        assert!(matches!(s.rest_baton(a, true), Handoff::Nobody));
        assert_eq!(s.baton, Baton::Nobody);
    }

    #[test]
    fn a_caller_that_lets_go_of_the_right_gives_it_to_one_who_waits_for_its_response() {
        let mut s = state();
        let (a, b, c) = (open(&mut s), open(&mut s), open(&mut s));
        let slot = |s: &mut State, id: u32, waiting: bool, can_lead: bool| {
            let slot = Slot::new();
            slot.waiting.store(waiting, Ordering::Relaxed);
            slot.can_lead.store(can_lead, Ordering::Relaxed);
            s.slots.insert(id, slot.clone());
            slot
        };
        slot(&mut s, a, true, true);
        // b waits to send its body (it could not read the socket), c is not asleep: neither is given the right
        slot(&mut s, b, true, false);
        let c_slot = slot(&mut s, c, false, true);
        s.baton = Baton::Caller { stream: a, paused_since: None };
        s.parked = Parked::Leader;
        assert!(matches!(s.rest_baton(a, false), Handoff::Reader), "the caller's own slot, or one that cannot read, was chosen");
        assert_eq!(s.baton, Baton::Nobody);
        // c waits now: it is given the right, and its wake-up is claimed; the reader thread is left alone
        c_slot.waiting.store(true, Ordering::Relaxed);
        s.baton = Baton::Caller { stream: a, paused_since: None };
        s.parked = Parked::Leader;
        assert!(matches!(s.rest_baton(a, true), Handoff::Caller(ref slot) if Arc::ptr_eq(slot, &c_slot)));
        assert_eq!(s.baton, Baton::Caller { stream: c, paused_since: None });
        assert!(!c_slot.waiting.load(Ordering::Relaxed));
        assert_eq!(s.parked, Parked::Leader);
        // and it can use it, and nobody else can take it from it
        assert!(!s.claim_baton(a));
        assert!(s.claim_baton(c));
        // a transport that is going away gives it to nobody
        c_slot.waiting.store(true, Ordering::Relaxed);
        s.begin_close(false);
        assert!(matches!(s.rest_baton(c, false), Handoff::Nobody | Handoff::Reader));
        assert_eq!(s.baton, Baton::Nobody);
    }

    #[test]
    fn the_reader_thread_stays_out_of_the_way_after_the_last_request_ends() {
        let mut s = state();
        assert!(s.park_for().is_some_and(|d| d <= PARK_WINDOW));
        let id = open(&mut s);
        s.idle_since = None;
        // (a request is in flight now, and nobody has told the reader thread of any news for it)
        assert_eq!(s.park_for(), None);
        s.h2.release_stream(id);
        s.idle_since = Some(Instant::now() - PARK_WINDOW * 2);
        assert_eq!(s.park_for(), None, "the window had passed");
        s.idle_since = Some(Instant::now());
        s.closing = true;
        assert_eq!(s.park_for(), None);
    }

    #[test]
    fn the_reader_thread_steps_aside_for_the_caller_of_the_only_stream_it_woke_and_for_no_other() {
        let mut s = state();
        let a = open(&mut s);
        s.idle_since = None;
        s.handover = Some(Instant::now());
        assert!(s.park_for().is_some());
        // later than the window
        s.handover = Some(Instant::now() - PARK_WINDOW * 2);
        assert_eq!(s.park_for(), None);
        // never handed anything
        s.handover = None;
        assert_eq!(s.park_for(), None);
        // with two requests in flight somebody has to read for the other: the reader thread does
        let _b = open(&mut s);
        s.handover = Some(Instant::now());
        assert_eq!(s.park_for(), None);
        let _ = a;
    }
}
