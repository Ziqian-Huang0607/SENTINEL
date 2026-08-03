//! Low-level probe transport abstraction.
//!
//! The scanner is designed to run **unprivileged**: the default and only
//! always-available probe mechanism is a plain TCP `connect(2)`, which needs
//! no special capabilities on Linux or macOS.
//!
//! An optional *privileged* raw-socket path (ICMP echo for host discovery) is
//! available behind the `privileged` cargo feature:
//!
//! ```text
//! cargo build --features privileged   # requires root or CAP_NET_RAW at runtime
//! ```
//!
//! With the feature enabled, [`ProbeEngine::icmp_available`] reports whether a
//! raw ICMP socket could be opened; discovery prefers ICMP and transparently
//! falls back to TCP connect probes when raw sockets are unavailable. With the
//! feature disabled (default), [`ProbeEngine::icmp_echo`] always returns
//! [`ProbeError::Unsupported`].

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Errors from low-level probe operations.
#[derive(Debug, Error)]
pub enum ProbeError {
    /// The requested probe mechanism is not compiled in / not permitted.
    #[error("probe mechanism unsupported in this build or without privileges")]
    Unsupported,
    /// Underlying I/O failure.
    #[error("probe io error: {0}")]
    Io(#[from] io::Error),
}

/// Probe engine bundling the per-attempt timeout with the available
/// transports. Cheap to clone and share across tasks.
#[derive(Debug, Clone, Copy)]
pub struct ProbeEngine {
    timeout: Duration,
}

impl ProbeEngine {
    /// Creates an engine with the given per-connection timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// The configured per-attempt timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Unprivileged TCP-connect probe: returns true when `ip:port` accepts a
    /// TCP connection within the configured timeout. This is the workhorse
    /// used for host discovery, port scanning and fingerprinting.
    pub async fn tcp_connect(&self, ip: Ipv4Addr, port: u16) -> bool {
        let addr = SocketAddrV4::new(ip, port);
        matches!(
            timeout(self.timeout, TcpStream::connect(addr)).await,
            Ok(Ok(_stream))
        )
    }

    /// Opens a TCP stream to `ip:port` with the configured timeout. Used by
    /// the fingerprinting stage, which needs the live connection.
    pub async fn tcp_open(&self, ip: Ipv4Addr, port: u16) -> io::Result<TcpStream> {
        let addr = SocketAddrV4::new(ip, port);
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(res) => res,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
        }
    }

    /// Whether the privileged ICMP echo path is usable in this process.
    pub fn icmp_available(&self) -> bool {
        privileged::icmp_available()
    }

    /// Privileged ICMP echo probe. With the default feature set this always
    /// returns [`ProbeError::Unsupported`] and callers must use TCP connect.
    pub async fn icmp_echo(&self, ip: Ipv4Addr) -> Result<bool, ProbeError> {
        privileged::icmp_echo(ip, self.timeout).await
    }
}

#[cfg(not(feature = "privileged"))]
mod privileged {
    use super::{Ipv4Addr, ProbeError};
    use std::time::Duration;

    pub fn icmp_available() -> bool {
        false
    }

    pub async fn icmp_echo(_ip: Ipv4Addr, _timeout: Duration) -> Result<bool, ProbeError> {
        Err(ProbeError::Unsupported)
    }
}

/// Privileged raw-socket ICMP echo implementation (feature `privileged`).
///
/// Builds a minimal ICMPv4 echo request by hand (8-byte header + payload,
/// RFC 1071 internet checksum) and exchanges it over a raw socket. Requires
/// root or `CAP_NET_RAW`; all failures degrade to `Ok(false)`/`Unsupported`
/// so callers can fall back to TCP connect probing.
#[cfg(feature = "privileged")]
mod privileged {
    use super::{Ipv4Addr, ProbeError};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io;
    use std::mem::MaybeUninit;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    const ICMP_ECHO_REQUEST: u8 = 8;
    const ICMP_ECHO_REPLY: u8 = 0;
    const HEADER_LEN: usize = 8;
    const PAYLOAD_LEN: usize = 24;

    /// True when a raw ICMPv4 socket can be opened (root / CAP_NET_RAW).
    pub fn icmp_available() -> bool {
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
    }

    /// Sends one ICMP echo request and waits for the matching reply.
    pub async fn icmp_echo(ip: Ipv4Addr, timeout: Duration) -> Result<bool, ProbeError> {
        // Raw sockets are blocking; run the exchange on the blocking pool.
        let res = tokio::task::spawn_blocking(move || icmp_echo_blocking(ip, timeout)).await;
        match res {
            Ok(inner) => inner,
            Err(join) => Err(ProbeError::Io(io::Error::other(join))),
        }
    }

    fn icmp_echo_blocking(ip: Ipv4Addr, timeout: Duration) -> Result<bool, ProbeError> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        let ident: u16 = (std::process::id() & 0xffff) as u16;
        let seq: u16 = 1;
        let mut packet = [0u8; HEADER_LEN + PAYLOAD_LEN];
        packet[0] = ICMP_ECHO_REQUEST;
        packet[1] = 0; // code
        packet[4..6].copy_from_slice(&ident.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        for (i, byte) in packet.iter_mut().enumerate().skip(HEADER_LEN) {
            *byte = (i - HEADER_LEN) as u8;
        }
        let sum = internet_checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());

        let dest = SockAddr::from(SocketAddr::from((ip, 0)));
        socket.send_to(&packet, &dest)?;

        let deadline = Instant::now() + timeout;
        loop {
            let mut buf: [MaybeUninit<u8>; 1500] = [MaybeUninit::uninit(); 1500];
            match socket.recv_from(&mut buf) {
                Ok((n, _from)) => {
                    // Safe: recv_from initialised the first n bytes.
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                    if is_matching_reply(data, ident, seq) {
                        return Ok(true);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Ok(false),
                Err(e) => return Err(ProbeError::Io(e)),
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }

    /// Checks an IPv4 packet for an ICMP echo reply matching id/seq.
    fn is_matching_reply(data: &[u8], ident: u16, seq: u16) -> bool {
        if data.len() < 20 + HEADER_LEN {
            return false;
        }
        let ihl = usize::from(data[0] & 0x0f) * 4;
        if data.len() < ihl + HEADER_LEN {
            return false;
        }
        let icmp = &data[ihl..];
        icmp[0] == ICMP_ECHO_REPLY
            && icmp[1] == 0
            && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
            && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
    }

    /// RFC 1071 ones-complement checksum over `data`.
    fn internet_checksum(data: &[u8]) -> u16 {
        let mut acc: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for pair in &mut chunks {
            acc += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            acc += u32::from(last) << 8;
        }
        while (acc >> 16) != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn checksum_known_vector() {
            // Echo request with zeroed checksum must checksum to a fixed value.
            let mut packet = [0u8; 8];
            packet[0] = ICMP_ECHO_REQUEST;
            packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
            packet[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
            let sum = internet_checksum(&packet);
            // Verify: header with checksum inserted sums to 0xffff.
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
            assert_eq!(internet_checksum(&packet), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_connect_detects_open_and_closed() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();
        let engine = ProbeEngine::new(Duration::from_millis(300));

        assert!(engine.tcp_connect(Ipv4Addr::LOCALHOST, port).await);
        // Port 1 on loopback is closed for practical purposes.
        assert!(!engine.tcp_connect(Ipv4Addr::LOCALHOST, 1).await);
    }

    #[cfg(not(feature = "privileged"))]
    #[tokio::test]
    async fn icmp_reports_unsupported_by_default() {
        let engine = ProbeEngine::new(Duration::from_millis(50));
        assert!(!engine.icmp_available());
        let res = engine.icmp_echo(Ipv4Addr::LOCALHOST).await;
        assert!(matches!(res, Err(ProbeError::Unsupported)));
    }
}
