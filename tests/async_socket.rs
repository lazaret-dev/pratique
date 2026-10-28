//! Local-only acceptance tests, also included by Workglen's portable workspace suite.
use pratique::asyncio::{
    block_on, socket::SocketBudget, timeout, yield_now, AsyncReadExt, AsyncWriteExt,
};
use std::{
    future::Future,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    sync::{Arc, Barrier},
    task::{Context, Waker},
    time::{Duration, Instant},
};

fn addr(ip: &str) -> SocketAddr {
    format!("{ip}:0").parse().unwrap()
}

#[test]
fn executor_and_timer_can_interrupt_a_continuously_ready_task() {
    let start = Instant::now();
    assert!(block_on(timeout(Duration::from_millis(25), async {
        loop {
            yield_now().await;
        }
    }))
    .is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(
        block_on(async {
            yield_now().await;
            42
        }),
        42
    );
}

#[test]
fn socket_budget_is_shared_and_returns_failed_or_dropped_reservations() {
    assert!(SocketBudget::new(0).is_err());
    let budget = SocketBudget::new(1).unwrap();
    let clone = budget.clone();
    let first = budget.udp_bind(addr("127.0.0.1")).unwrap();
    assert_eq!(clone.in_use(), 1);
    assert_eq!(clone.limit(), 1);
    assert!(
        matches!(clone.udp_bind(addr("127.0.0.1")),Err(e)if e.kind()==io::ErrorKind::WouldBlock)
    );
    drop(first);
    assert_eq!(clone.in_use(), 0);
    let occupied = UdpSocket::bind(addr("127.0.0.1")).unwrap();
    assert!(budget.udp_bind(occupied.local_addr().unwrap()).is_err());
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn parallel_socket_admission_never_exceeds_the_shared_cap() {
    let budget = SocketBudget::new(4).unwrap();
    let ready = Arc::new(Barrier::new(17));
    let release = Arc::new(Barrier::new(17));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let budget = budget.clone();
            let ready = ready.clone();
            let release = release.clone();
            std::thread::spawn(move || {
                let socket = budget.udp_bind(addr("127.0.0.1"));
                ready.wait();
                release.wait();
                drop(socket);
            })
        })
        .collect();
    ready.wait();
    assert_eq!(budget.in_use(), 4);
    release.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn udp_ipv4_ipv6_and_connected_peer_filtering() {
    for ip in ["127.0.0.1", "[::1]"] {
        let server = UdpSocket::bind(addr(ip)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let budget = SocketBudget::new(1).unwrap();
        let socket = budget.udp_bind(addr(ip)).unwrap();
        socket.connect(address).unwrap();
        assert_eq!(socket.peer_addr().unwrap(), address);
        let rogue = UdpSocket::bind(addr(ip)).unwrap();
        rogue
            .send_to(b"forged", socket.local_addr().unwrap())
            .unwrap();
        let worker = std::thread::spawn(move || {
            let mut bytes = [0; 16];
            let (n, peer) = server.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..n], b"query");
            server.send_to(b"answer", peer).unwrap();
        });
        block_on(async {
            assert_eq!(socket.send(b"query").await.unwrap(), 5);
            let mut bytes = [0; 16];
            let n = timeout(Duration::from_secs(2), socket.recv(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&bytes[..n], b"answer");
        });
        worker.join().unwrap();
        drop(socket);
        assert_eq!(budget.in_use(), 0);
    }
}

#[test]
fn udp_cancellation_closes_socket_and_releases_capacity() {
    let budget = SocketBudget::new(1).unwrap();
    let socket = budget.udp_bind(addr("127.0.0.1")).unwrap();
    let address = socket.local_addr().unwrap();
    let start = Instant::now();
    assert!(block_on(timeout(Duration::from_millis(25), async move {
        let mut bytes = [0; 8];
        socket.recv_from(&mut bytes).await
    }))
    .is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(budget.in_use(), 0);
    let reopened = budget.udp_bind(address).unwrap();
    drop(reopened);
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn tcp_ipv4_ipv6_partial_reads_and_half_close() {
    for ip in ["127.0.0.1", "[::1]"] {
        let server = TcpListener::bind(addr(ip)).unwrap();
        let address = server.local_addr().unwrap();
        let budget = SocketBudget::new(1).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = server.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = [0; 5];
            socket.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"hello");
            for b in b"world" {
                socket.write_all(&[*b]).unwrap();
                std::thread::sleep(Duration::from_millis(3));
            }
            assert_eq!(socket.read(&mut bytes).unwrap(), 0);
        });
        block_on(async {
            let mut socket = timeout(Duration::from_secs(2), budget.tcp_connect(address))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(socket.peer_addr().unwrap(), address);
            let mut bytes = [0; 5];
            socket.write_all(b"hello").await.unwrap();
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"world");
            socket.close().await.unwrap();
        });
        worker.join().unwrap();
        assert_eq!(budget.in_use(), 0);
    }
}

#[test]
fn refused_and_dropped_tcp_connect_return_capacity() {
    let listener = TcpListener::bind(addr("127.0.0.1")).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let budget = SocketBudget::new(1).unwrap();
    let result = block_on(timeout(Duration::from_secs(1), budget.tcp_connect(address))).unwrap();
    assert!(result.is_err());
    assert_eq!(budget.in_use(), 0);
    let listener = TcpListener::bind(addr("127.0.0.1")).unwrap();
    let mut connecting = Box::pin(budget.tcp_connect(listener.local_addr().unwrap()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(connecting.as_mut().poll(&mut cx).is_pending());
    assert_eq!(budget.in_use(), 0);
    assert!(connecting.as_mut().poll(&mut cx).is_pending());
    assert_eq!(budget.in_use(), 1);
    drop(connecting);
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn cancellation_during_tcp_read_closes_the_peer_without_a_background_worker() {
    let listener = TcpListener::bind(addr("127.0.0.1")).unwrap();
    let address = listener.local_addr().unwrap();
    let budget = SocketBudget::new(1).unwrap();
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).unwrap(), 0);
    });
    block_on(async {
        let mut socket = budget.tcp_connect(address).await.unwrap();
        assert!(timeout(Duration::from_millis(25), async move {
            let mut byte = [0];
            socket.read_exact(&mut byte).await
        })
        .await
        .is_err());
    });
    worker.join().unwrap();
    assert_eq!(budget.in_use(), 0);
}

#[test]
fn tcp_backpressure_is_cancellable_without_detached_writes() {
    let listener = TcpListener::bind(addr("127.0.0.1")).unwrap();
    let address = listener.local_addr().unwrap();
    let budget = SocketBudget::new(1).unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (_socket, _) = listener.accept().unwrap();
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    });
    block_on(async {
        let mut socket = budget.tcp_connect(address).await.unwrap();
        let bytes = vec![7; 1024 * 1024];
        assert!(timeout(Duration::from_millis(40), async move {
            for _ in 0..128 {
                socket.write_all(&bytes).await.unwrap();
            }
        })
        .await
        .is_err());
    });
    assert_eq!(budget.in_use(), 0);
    done_tx.send(()).unwrap();
    worker.join().unwrap();
}

#[test]
fn trickled_tcp_payload_does_not_reset_an_absolute_deadline() {
    let listener = TcpListener::bind(addr("127.0.0.1")).unwrap();
    let address = listener.local_addr().unwrap();
    let budget = SocketBudget::new(1).unwrap();
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        for _ in 0..100 {
            if socket.write_all(&[1]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(8));
        }
    });
    let start = Instant::now();
    block_on(async {
        let mut socket = budget.tcp_connect(address).await.unwrap();
        assert!(timeout(Duration::from_millis(40), async move {
            let mut bytes = [0; 100];
            socket.read_exact(&mut bytes).await
        })
        .await
        .is_err());
    });
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eq!(budget.in_use(), 0);
    worker.join().unwrap();
}
