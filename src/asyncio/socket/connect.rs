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
pub(super) fn start(address: std::net::SocketAddr) -> std::io::Result<std::net::TcpStream> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        native::start(address)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = address;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nonblocking TCP connect requires Linux or macOS",
        ))
    }
}
pub(super) fn ready(stream: &std::net::TcpStream) -> std::io::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        native::ready(stream)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "nonblocking TCP connect requires Linux or macOS",
        ))
    }
}
