//! `TlsStream::split`: two threads on one connection. Against the crate's TLS server over real sockets (an echo larger than
//! any socket buffer, which one blocking stream cannot do; KeyUpdates that the server asks for while the client writes; close
//! in one direction; the Finished sent at the split) and against a scripted peer that holds the record keys (TLS 1.2's
//! HelloRequest answered in the middle of the client's writes; a damaged record).

use super::conn::ClientConnection;
use super::messages::HS_KEY_UPDATE;
use super::server::*;
use super::suite::*;
use super::tls12::{RecordCipher12, Suite12};
use super::*;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

fn serve_one<T: Send + 'static>(config: ServerConfig, handler: impl FnOnce(ServerStream<TcpStream>) -> T + Send + 'static) -> (u16, JoinHandle<Result<T>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        let stream = ServerStream::accept(socket, &config)?;
        Ok(handler(stream))
    });
    (port, handle)
}

fn client(port: u16, config: &ClientConfig) -> TlsStream<TcpStream> {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(TIMEOUT)).unwrap();
    s.set_write_timeout(Some(TIMEOUT)).unwrap();
    TlsStream::connect(s, "localhost", config).unwrap()
}

fn setup() -> (ServerConfig, ClientConfig) {
    let (server, pki) = ServerConfig::for_names(&["localhost"]).unwrap();
    (server, ClientConfig::new(pki.trust_store()))
}

fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect()
}

/// Echoes what it reads until the client's close_notify, asking for a KeyUpdate every `rekey_every` reads (0: never), and
/// then closes. Returns how many bytes it echoed and how many KeyUpdates it asked for.
fn echo(mut s: ServerStream<TcpStream>, rekey_every: usize) -> (usize, usize) {
    let mut buf = vec![0u8; 64 * 1024];
    let (mut total, mut reads, mut asked) = (0, 0, 0);
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        reads += 1;
        if rekey_every > 0 && reads % rekey_every == 0 {
            s.connection_mut().send_key_update(true).unwrap();
            asked += 1;
        }
        s.write_all(&buf[..n]).unwrap();
        total += n;
    }
    s.close().unwrap();
    (total, asked)
}

/// Writes `data` from one thread while this one reads the echo, and returns what came back.
fn echo_through_halves(tls: TlsStream<TcpStream>, data: Arc<Vec<u8>>) -> Vec<u8> {
    let (mut reader, mut writer) = tls.split().unwrap();
    let sending = data.clone();
    let w = thread::spawn(move || {
        for chunk in sending.chunks(50_000) {
            writer.write_all(chunk).unwrap();
        }
        writer.close().unwrap();
    });
    let mut back = Vec::with_capacity(data.len());
    reader.read_to_end(&mut back).unwrap();
    w.join().unwrap();
    back
}

#[test]
fn an_echo_larger_than_the_socket_buffers_needs_both_halves_at_once() {
    // 8 MiB is far more than both kernels' socket buffers hold: written by one thread that does not read, it would stop
    // with the server blocked writing the echo back and the client blocked writing the rest
    let data = Arc::new(pattern(8 << 20, 7));
    for suite in Suite::ALL {
        let (server, client_config) = setup();
        let (port, handle) = serve_one(server.with_suites(&[suite]), |s| echo(s, 0));
        let back = echo_through_halves(client(port, &client_config), data.clone());
        assert!(back == *data, "{suite:?}: the echo differs");
        assert_eq!(handle.join().unwrap().unwrap().0, data.len());
    }
}

#[test]
fn key_updates_the_server_asks_for_are_answered_in_order_while_the_client_writes() {
    // the server asks every 16 reads; the client also rekeys on its own every 50 records: the reading half queues the
    // answers among the records the writing half is making, and one record out of order would not decrypt
    let data = Arc::new(pattern(4 << 20, 11));
    let (server, client_config) = setup();
    let (port, handle) = serve_one(server, |s| echo(s, 16));
    let back = echo_through_halves(client(port, &client_config.with_rekey_after_records(50)), data.clone());
    assert!(back == *data, "the echo differs");
    let (echoed, asked) = handle.join().unwrap().unwrap();
    assert_eq!(echoed, data.len());
    assert!(asked >= 4, "the server asked for {asked} KeyUpdates only");
}

#[test]
fn closing_the_writing_half_ends_our_side_and_the_reader_reads_on() {
    let (server, client_config) = setup();
    let (port, handle) = serve_one(server, |mut s| {
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap(); // up to our close_notify
        s.write_all(b"after your close: ").unwrap();
        s.write_all(&got).unwrap();
        s.close().unwrap();
    });
    let (mut reader, mut writer) = client(port, &client_config).split().unwrap();
    writer.write_all(b"hello").unwrap();
    writer.close().unwrap();
    assert!(writer.write(b"more").is_err(), "a write after close_notify");
    let mut back = Vec::new();
    reader.read_to_end(&mut back).unwrap();
    assert_eq!(back, b"after your close: hello");
    handle.join().unwrap().unwrap();
    // what the halves say about the connection
    assert_eq!(reader.protocol_version(), Some(TlsVersion::Tls13));
    assert_eq!(writer.cipher_suite_name(), reader.cipher_suite_name());
    assert_eq!(reader.peer_certificates().len(), 1);
}

#[test]
fn the_finished_goes_out_at_the_split_so_a_client_that_only_reads_is_answered() {
    // the server's accept returns only once our Finished is in; a client that never writes still gets it there
    let (server, client_config) = setup();
    let (port, handle) = serve_one(server, |mut s| {
        s.write_all(b"welcome").unwrap();
        s.close().unwrap();
    });
    let (mut reader, writer) = client(port, &client_config).split().unwrap();
    let mut back = Vec::new();
    reader.read_to_end(&mut back).unwrap();
    assert_eq!(back, b"welcome");
    drop(writer);
    handle.join().unwrap().unwrap();
}

#[test]
fn the_halves_can_go_to_other_threads() {
    fn send<T: Send>() {}
    send::<TlsReadHalf<TcpStream>>();
    send::<TlsWriteHalf<TcpStream>>();
}

// ------------------------------------------------------------------------------------------------ scripted peer

/// Reads one record from `io` (header and payload).
fn read_record(io: &mut impl Read) -> Option<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).ok()?;
    let mut payload = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
    io.read_exact(&mut payload).ok()?;
    Some((header, payload))
}

#[test]
fn a_tls12_hello_request_is_answered_among_the_records_being_written() {
    // a TLS 1.2 connection with fixed keys on one side of a socket pair, and a peer on the other side that sends a
    // HelloRequest for every 4 KiB it receives while the client's writing half keeps writing: the answers (a no_renegotiation
    // warning each) go out among the application data under the next sequence numbers, so the peer must open every record
    // in order. After 20 answers the peer says "stop", the client closes, and the peer says "bye".
    use std::sync::atomic::{AtomicBool, Ordering};
    let suite = Suite12::EcdheEcdsaChacha20Poly1305;
    let (key_c, key_s, iv) = ([3u8; 32], [4u8; 32], [5u8; 12]);
    let conn = ClientConnection::established12(RecordCipher12::new(suite, &key_s, &iv), RecordCipher12::new(suite, &key_c, &iv));
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    ours.set_read_timeout(Some(TIMEOUT)).unwrap();
    theirs.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (mut reader, mut writer) = TlsStream::from_parts(ours, conn).split().unwrap();
    let mut peer_out = RecordCipher12::new(suite, &key_s, &iv);
    let mut peer_in = RecordCipher12::new(suite, &key_c, &iv);
    let mut theirs_w = theirs.try_clone().unwrap();
    let peer = thread::spawn(move || {
        let (mut data, mut asked, mut answered) = (Vec::new(), 0usize, 0usize);
        let mut send = |kind: u8, content: &[u8], out: &mut RecordCipher12| {
            let mut wire = Vec::new();
            out.encrypt_into(kind, content, &mut wire);
            theirs_w.write_all(&wire).unwrap();
        };
        loop {
            let (header, mut payload) = read_record(&mut theirs).expect("the client closes properly");
            let (kind, start, len) = peer_in.decrypt_in_place(&header, &mut payload).expect("every record opens, in order");
            let content = &payload[start..start + len];
            match kind {
                RT_APPLICATION_DATA => {
                    data.extend_from_slice(content);
                    if data.len() / 4096 != (data.len() - len) / 4096 {
                        send(RT_HANDSHAKE, &[0, 0, 0, 0], &mut peer_out);
                        asked += 1;
                    }
                }
                RT_ALERT if content == [1, 100] => {
                    answered += 1;
                    if answered == 20 {
                        send(RT_APPLICATION_DATA, b"stop", &mut peer_out);
                    }
                }
                RT_ALERT if content == [1, 0] => {
                    send(RT_APPLICATION_DATA, b"bye", &mut peer_out);
                    send(RT_ALERT, &[1, 0], &mut peer_out);
                    break;
                }
                other => panic!("record type {other}: {content:?}"),
            }
        }
        (data, asked, answered)
    });
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let w = thread::spawn(move || {
        let mut sent = Vec::new();
        let mut i = 0u32;
        while !stopped.load(Ordering::Acquire) {
            let chunk = pattern(1000, i);
            writer.write_all(&chunk).unwrap();
            sent.extend_from_slice(&chunk);
            i += 1;
        }
        writer.close().unwrap();
        sent
    });
    let mut first = [0u8; 4];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"stop");
    stop.store(true, Ordering::Release);
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"bye");
    let sent = w.join().unwrap();
    let (data, asked, answered) = peer.join().unwrap();
    assert!(data == sent, "the data arrived changed");
    assert!(answered >= 20 && answered <= asked, "{answered} answers to {asked} HelloRequests");
}

#[test]
fn a_damaged_record_fails_the_reader_sends_the_alert_and_fails_the_writer() {
    let suite = Suite::Aes128GcmSha256;
    let n = suite.hash().output_len();
    let (read_secret, write_secret) = (vec![2u8; n], vec![1u8; n]);
    let conn = ClientConnection::established(suite, &read_secret, &write_secret);
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    ours.set_read_timeout(Some(TIMEOUT)).unwrap();
    theirs.set_read_timeout(Some(TIMEOUT)).unwrap();
    let (mut reader, mut writer) = TlsStream::from_parts(ours, conn).split().unwrap();
    let mut peer_out = RecordCipher::new(suite, &read_secret);
    let mut record = peer_out.encrypt(RT_APPLICATION_DATA, b"fine");
    let mut bad = peer_out.encrypt(RT_APPLICATION_DATA, b"damaged");
    let last = bad.len() - 1;
    bad[last] ^= 1;
    record.extend_from_slice(&bad);
    theirs.write_all(&record).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(reader.read(&mut buf).unwrap(), 4);
    assert_eq!(&buf[..4], b"fine");
    let e = reader.read(&mut buf).unwrap_err();
    assert!(e.to_string().contains("bad_record_mac"), "{e}");
    // the alert reached the peer
    let mut peer_in = RecordCipher::new(suite, &write_secret);
    let (header, payload) = read_record(&mut theirs).unwrap();
    let (kind, content) = peer_in.decrypt(&header, &payload).unwrap();
    assert_eq!((kind, content), (RT_ALERT, vec![2, 20]));
    // and the writing half cannot go on
    assert!(writer.write(b"x").is_err());
}

/// One side of a socket pair whose writes wait while a gate is shut (every duplicate shares the gate), and which says when
/// a write is waiting.
struct Gated {
    io: UnixStream,
    gate: Arc<(std::sync::Mutex<(bool, bool)>, std::sync::Condvar)>,
}

impl Gated {
    /// (open, a write is waiting)
    fn set_open(&self, open: bool) {
        let (m, cv) = &*self.gate;
        m.lock().unwrap().0 = open;
        cv.notify_all();
    }

    fn wait_for_a_blocked_write(&self) {
        let (m, cv) = &*self.gate;
        let mut g = m.lock().unwrap();
        while !g.1 {
            g = cv.wait(g).unwrap();
        }
    }
}

impl Read for Gated {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.io.read(buf)
    }
}

impl Write for Gated {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        {
            let (m, cv) = &*self.gate;
            let mut g = m.lock().unwrap();
            while !g.0 {
                g.1 = true;
                cv.notify_all();
                g = cv.wait(g).unwrap();
            }
            g.1 = false;
        }
        self.io.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}

impl Duplex for Gated {
    fn duplicate(&self) -> io::Result<Self> {
        Ok(Gated { io: self.io.try_clone()?, gate: self.gate.clone() })
    }
}

#[test]
fn the_reader_goes_on_while_a_write_is_blocked_and_its_answer_follows_that_write() {
    // the writing half is stuck in a write (the transport will not take it); the server asks for a KeyUpdate and sends
    // "ping": the reading half reads the ping all the same (it does not wait for the stuck write), and the answer it queued
    // goes out right after the stuck write, without another write by anyone, in the order a peer can open
    let suite = Suite::Chacha20Poly1305Sha256;
    let n = suite.hash().output_len();
    let (read_secret, write_secret) = (vec![2u8; n], vec![1u8; n]);
    let conn = ClientConnection::established(suite, &read_secret, &write_secret);
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    theirs.set_read_timeout(Some(TIMEOUT)).unwrap();
    let ours = Gated { io: ours, gate: Arc::new((std::sync::Mutex::new((true, false)), std::sync::Condvar::new())) };
    let control = ours.duplicate().unwrap();
    let (mut reader, mut writer) = TlsStream::from_parts(ours, conn).split().unwrap();
    control.set_open(false);
    let w = thread::spawn(move || {
        writer.write_all(b"held").unwrap();
        writer
    });
    control.wait_for_a_blocked_write();
    // the request first, alone, so that the reader has an answer to send before it waits for more; the ping a little later
    let mut peer_out = RecordCipher::new(suite, &read_secret);
    theirs.write_all(&peer_out.encrypt(RT_HANDSHAKE, &[HS_KEY_UPDATE, 0, 0, 1, 1])).unwrap();
    peer_out = peer_out.next_generation();
    let mut later = theirs.try_clone().unwrap();
    let pinger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        later.write_all(&peer_out.encrypt(RT_APPLICATION_DATA, b"ping")).unwrap();
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let r = thread::spawn(move || {
        let mut ping = [0u8; 4];
        reader.read_exact(&mut ping).unwrap();
        tx.send(ping).unwrap();
        reader
    });
    let ping = rx.recv_timeout(Duration::from_secs(5));
    // now let the write through (also if the reader is stuck, so that the test ends): the writer sends what it held, then
    // the answer
    control.set_open(true);
    assert_eq!(ping.expect("the reader waited for the stuck write"), *b"ping");
    let _reader = r.join().unwrap();
    pinger.join().unwrap();
    let writer = w.join().unwrap();
    let mut peer_in = RecordCipher::new(suite, &write_secret);
    let mut got = Vec::new();
    for _ in 0..2 {
        let (header, payload) = read_record(&mut theirs).unwrap();
        let (kind, content) = peer_in.decrypt(&header, &payload).unwrap();
        got.push((kind, content));
    }
    assert_eq!(got, vec![(RT_APPLICATION_DATA, b"held".to_vec()), (RT_HANDSHAKE, vec![HS_KEY_UPDATE, 0, 0, 1, 0])]);
    // and what follows is under the next keys
    drop(writer);
    let mut peer_in = peer_in.next_generation();
    let (header, payload) = read_record(&mut theirs).unwrap();
    assert_eq!(peer_in.decrypt(&header, &payload).unwrap(), (RT_ALERT, vec![1, 0]));
}
