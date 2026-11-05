//! Small OS boundary: create/connect nonblocking TCP, then probe readiness with poll(0).
//! Descriptor ownership moves immediately into std, which closes it on every error/drop.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native {
    use std::{
        ffi::{c_int, c_short, c_void},
        io,
        mem::size_of,
        net::{SocketAddr, TcpStream},
        os::fd::{AsRawFd, FromRawFd},
    };
    #[cfg(target_os = "linux")]
    type Nfds = std::ffi::c_ulong;
    #[cfg(target_os = "macos")]
    type Nfds = u32;
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }
    #[repr(C)]
    struct Address4 {
        #[cfg(target_os = "macos")]
        len: u8,
        #[cfg(target_os = "macos")]
        family: u8,
        #[cfg(target_os = "linux")]
        family: u16,
        port: u16,
        address: [u8; 4],
        padding: [u8; 8],
    }
    #[repr(C)]
    struct Address6 {
        #[cfg(target_os = "macos")]
        len: u8,
        #[cfg(target_os = "macos")]
        family: u8,
        #[cfg(target_os = "linux")]
        family: u16,
        port: u16,
        flow: u32,
        address: [u8; 16],
        scope: u32,
    }
    const _: () = assert!(
        size_of::<Address4>() == 16 && size_of::<Address6>() == 28 && size_of::<PollFd>() == 8
    );
    #[cfg(target_os = "linux")]
    const IPV6: c_int = 10;
    #[cfg(target_os = "macos")]
    const IPV6: c_int = 30;
    extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn connect(fd: c_int, address: *const c_void, len: u32) -> c_int;
        fn poll(fds: *mut PollFd, count: Nfds, timeout: c_int) -> c_int;
        #[cfg(target_os = "macos")]
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        #[cfg(target_os = "macos")]
        fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            len: u32,
        ) -> c_int;
    }
    pub(super) fn start(address: SocketAddr) -> io::Result<TcpStream> {
        #[cfg(target_os = "linux")]
        let flags = 1 | 0o2000000; // SOCK_STREAM | SOCK_CLOEXEC
        #[cfg(target_os = "macos")]
        let flags = 1;
        // SAFETY: socket takes integer constants, returns a new owned descriptor or -1.
        let fd = unsafe { socket(if address.is_ipv4() { 2 } else { IPV6 }, flags, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh TCP socket and is transferred exactly once into std ownership.
        let stream = unsafe { TcpStream::from_raw_fd(fd) };
        #[cfg(target_os = "macos")]
        {
            let one: c_int = 1;
            // SAFETY: a live owned fd, F_SETFD/FD_CLOEXEC and a valid int buffer for SO_NOSIGPIPE.
            if unsafe { fcntl(fd, 2, 1) } < 0
                || unsafe {
                    setsockopt(
                        fd,
                        0xffff,
                        0x1022,
                        (&one as *const c_int).cast(),
                        size_of::<c_int>() as u32,
                    )
                } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        stream.set_nonblocking(true)?;
        let result = match address {
            SocketAddr::V4(a) => {
                let address = Address4 {
                    #[cfg(target_os = "macos")]
                    len: 16,
                    family: 2,
                    port: a.port().to_be(),
                    address: a.ip().octets(),
                    padding: [0; 8],
                };
                // SAFETY: exact sockaddr_in ABI and size; pointer lives for the synchronous call.
                unsafe {
                    connect(
                        fd,
                        (&address as *const Address4).cast(),
                        size_of::<Address4>() as u32,
                    )
                }
            }
            SocketAddr::V6(a) => {
                let address = Address6 {
                    #[cfg(target_os = "macos")]
                    len: 28,
                    family: IPV6 as _,
                    port: a.port().to_be(),
                    flow: a.flowinfo(),
                    address: a.ip().octets(),
                    scope: a.scope_id(),
                };
                // SAFETY: exact sockaddr_in6 ABI and size; pointer lives for the synchronous call.
                unsafe {
                    connect(
                        fd,
                        (&address as *const Address6).cast(),
                        size_of::<Address6>() as u32,
                    )
                }
            }
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            #[cfg(target_os = "linux")]
            let in_progress = error.raw_os_error() == Some(115);
            #[cfg(target_os = "macos")]
            let in_progress = error.raw_os_error() == Some(36);
            if !in_progress && error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(stream)
    }
    pub(super) fn ready(stream: &TcpStream) -> io::Result<bool> {
        let mut fd = PollFd {
            fd: stream.as_raw_fd(),
            events: 4,
            revents: 0,
        }; // POLLOUT
           // SAFETY: one initialized pollfd, live borrowed descriptor, zero timeout; never blocks.
        let result = unsafe { poll(&mut fd, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(false);
        }
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        if fd.revents & 4 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TCP connection failed",
            ));
        }
        Ok(true)
    }
}

#[cfg(target_os = "windows")]
mod native {
    use std::{
        ffi::{c_char, c_int, c_long, c_void},
        io,
        mem::MaybeUninit,
        net::{SocketAddr, TcpStream},
        os::windows::io::{AsRawSocket, FromRawSocket},
        sync::OnceLock,
    };

    type Socket = usize;
    const INVALID_SOCKET: Socket = !0;
    const SOCKET_ERROR: c_int = -1;
    const SOCK_STREAM: c_int = 1;
    const IPPROTO_TCP: c_int = 6;
    const WSA_FLAG_OVERLAPPED: u32 = 1;
    const WSAEINTR: c_int = 10004;
    const WSAEWOULDBLOCK: c_int = 10035;
    const WSAEINPROGRESS: c_int = 10036;
    const WSAEALREADY: c_int = 10037;
    const FD_SETSIZE: usize = 64;

    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct WsaData {
        version: u16,
        high_version: u16,
        max_sockets: u16,
        max_udp_datagram: u16,
        vendor_info: *mut c_char,
        description: [c_char; 257],
        system_status: [c_char; 129],
    }

    #[cfg(target_pointer_width = "32")]
    #[repr(C)]
    struct WsaData {
        version: u16,
        high_version: u16,
        description: [c_char; 257],
        system_status: [c_char; 129],
        max_sockets: u16,
        max_udp_datagram: u16,
        vendor_info: *mut c_char,
    }

    #[repr(C)]
    struct Address4 {
        family: u16,
        port: u16,
        address: [u8; 4],
        padding: [u8; 8],
    }

    #[repr(C)]
    struct Address6 {
        family: u16,
        port: u16,
        flow: u32,
        address: [u8; 16],
        scope: u32,
    }

    #[repr(C)]
    struct FdSet {
        count: u32,
        sockets: [Socket; FD_SETSIZE],
    }

    #[repr(C)]
    struct Timeval {
        seconds: c_long,
        microseconds: c_long,
    }

    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(
        std::mem::size_of::<Address4>() == 16
            && std::mem::size_of::<Address6>() == 28
            && std::mem::size_of::<FdSet>() == 520
            && std::mem::size_of::<Timeval>() == 8
    );
    #[cfg(target_pointer_width = "32")]
    const _: () = assert!(
        std::mem::size_of::<Address4>() == 16
            && std::mem::size_of::<Address6>() == 28
            && std::mem::size_of::<FdSet>() == 260
            && std::mem::size_of::<Timeval>() == 8
    );

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAStartup(version: u16, data: *mut WsaData) -> c_int;
        fn WSAGetLastError() -> c_int;
        fn WSASocketW(
            family: c_int,
            kind: c_int,
            protocol: c_int,
            protocol_info: *mut c_void,
            group: u32,
            flags: u32,
        ) -> Socket;
        fn connect(socket: Socket, address: *const c_void, len: c_int) -> c_int;
        fn select(
            ignored: c_int,
            read: *mut FdSet,
            write: *mut FdSet,
            except: *mut FdSet,
            timeout: *const Timeval,
        ) -> c_int;
    }

    fn start_winsock() -> io::Result<()> {
        static STARTED: OnceLock<Result<(), c_int>> = OnceLock::new();
        match STARTED.get_or_init(|| {
            let mut data = MaybeUninit::<WsaData>::uninit();
            // SAFETY: `data` points to enough aligned, writable space for WSADATA. Winsock remains
            // initialized for the process: this library deliberately holds its startup reference.
            let result = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
            if result == 0 {
                Ok(())
            } else {
                Err(result)
            }
        }) {
            Ok(()) => Ok(()),
            Err(code) => Err(io::Error::from_raw_os_error(*code)),
        }
    }

    fn last_error() -> io::Error {
        // SAFETY: WSAGetLastError reads this thread's Winsock error value and has no preconditions.
        io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
    }

    pub(super) fn start(address: SocketAddr) -> io::Result<TcpStream> {
        start_winsock()?;
        // SAFETY: integer constants request a new overlapped TCP socket; no pointers are supplied.
        let socket = unsafe {
            WSASocketW(
                if address.is_ipv4() { 2 } else { 23 },
                SOCK_STREAM,
                IPPROTO_TCP,
                std::ptr::null_mut(),
                0,
                WSA_FLAG_OVERLAPPED,
            )
        };
        if socket == INVALID_SOCKET {
            return Err(last_error());
        }
        // SAFETY: `socket` is freshly owned and is transferred exactly once into std ownership.
        let stream = unsafe { TcpStream::from_raw_socket(socket as _) };
        stream.set_nonblocking(true)?;
        let result = match address {
            SocketAddr::V4(address) => {
                let address = Address4 {
                    family: 2,
                    port: address.port().to_be(),
                    address: address.ip().octets(),
                    padding: [0; 8],
                };
                // SAFETY: exact sockaddr_in ABI and size; pointer lives for the synchronous call.
                unsafe {
                    connect(
                        socket,
                        (&address as *const Address4).cast(),
                        size_of::<Address4>(),
                    )
                }
            }
            SocketAddr::V6(address) => {
                let address = Address6 {
                    family: 23,
                    port: address.port().to_be(),
                    flow: address.flowinfo(),
                    address: address.ip().octets(),
                    scope: address.scope_id(),
                };
                // SAFETY: exact sockaddr_in6 ABI and size; pointer lives for the synchronous call.
                unsafe {
                    connect(
                        socket,
                        (&address as *const Address6).cast(),
                        size_of::<Address6>(),
                    )
                }
            }
        };
        if result == SOCKET_ERROR {
            let error = last_error();
            if !matches!(
                error.raw_os_error(),
                Some(WSAEINTR) | Some(WSAEWOULDBLOCK) | Some(WSAEINPROGRESS) | Some(WSAEALREADY)
            ) {
                return Err(error);
            }
        }
        Ok(stream)
    }

    pub(super) fn ready(stream: &TcpStream) -> io::Result<bool> {
        let socket = stream.as_raw_socket() as Socket;
        let mut write = FdSet {
            count: 1,
            sockets: [0; FD_SETSIZE],
        };
        write.sockets[0] = socket;
        let mut except = FdSet {
            count: 1,
            sockets: [0; FD_SETSIZE],
        };
        except.sockets[0] = socket;
        let timeout = Timeval {
            seconds: 0,
            microseconds: 0,
        };
        // SAFETY: the two fd_sets each hold the one live borrowed socket, and the zero
        // timeval makes Winsock's select return immediately. Its first argument is ignored.
        let result = unsafe { select(0, std::ptr::null_mut(), &mut write, &mut except, &timeout) };
        if result == SOCKET_ERROR {
            return Err(last_error());
        }
        // Winsock may publish a failed nonblocking connect through SO_ERROR without
        // putting the socket in select's exception set (notably for loopback refusal).
        // SO_ERROR is the authoritative completion result, so inspect it every poll.
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        if result == 0 {
            return Ok(false);
        }
        if write.count == 0 && except.count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TCP connection failed",
            ));
        }
        Ok(true)
    }

    const fn size_of<T>() -> c_int {
        std::mem::size_of::<T>() as c_int
    }
}

pub(super) fn start(address: std::net::SocketAddr) -> std::io::Result<std::net::TcpStream> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        native::start(address)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = address;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nonblocking TCP connect requires Linux, macOS or Windows",
        ))
    }
}
pub(super) fn ready(stream: &std::net::TcpStream) -> std::io::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        native::ready(stream)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = stream;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nonblocking TCP connect requires Linux, macOS or Windows",
        ))
    }
}
