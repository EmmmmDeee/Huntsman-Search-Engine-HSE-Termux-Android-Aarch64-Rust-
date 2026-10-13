//! Network abstraction layer enforcing trait injection and hermetic test isolation.
//!
//! Every byte the engine sends or receives passes through the [`Transport`] trait, so the
//! collectors are verified offline against [`MockTransport`] while production runs on
//! [`UnprivilegedPosixTransport`]. The driver needs nothing an Android/Termux userland process
//! lacks: no raw sockets, no root, only TCP streams and ephemeral UDP sockets.

use crate::error::HuntsmanError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::debug;

/// Protocol dialogue interface decoupled from raw network sockets.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Open a TCP connection to `host:port`, send `payload`, and collect the peer's response.
    ///
    /// `timeout` bounds the whole dialogue (connect, send and read), and `max_bytes` bounds
    /// the response. The dialogue ends, and the bytes collected so far are returned, when
    /// any of the following happens:
    ///
    /// - the peer closes its side (EOF). A clean close with no bytes at all is an empty,
    ///   successful dialogue: the port accepted the connection and said nothing;
    /// - the peer has sent at least one byte and then stays silent for the implementation's
    ///   quiet period, so banner and keep-alive servers that never close are answered well
    ///   before the deadline;
    /// - the deadline passes, or the connection is reset, aborted or otherwise lost, after at
    ///   least one byte has arrived. A complete banner followed by a reset is a response, not
    ///   a fault: refusal banners (`421`, `554`, `413`) are exactly the evidence a dialogue
    ///   exists to capture.
    ///
    /// The payload is written in full before the response is read. A peer that answers and
    /// closes without reading the payload is tolerated: its answer is returned.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::Transport`] when the connection cannot be opened or the
    /// payload cannot be sent, and when the deadline, a reset or any other connection loss
    /// arrives before a single byte was received. Returns
    /// [`HuntsmanError::BufferLimitExceeded`] when the peer sends more than `max_bytes`; the
    /// excess is never read into memory.
    async fn tcp_dialogue(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError>;

    /// Issue an unprivileged UDP query (e.g., standard DNS port 53) and return the first
    /// datagram the peer answers with, bounded to `max_bytes`.
    ///
    /// `host` may be a hostname or an IPv4/IPv6 literal; the ephemeral socket is opened in
    /// the address family of the resolved target.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::Transport`] on resolve/bind/connect/send/receive/timeout
    /// failure.
    async fn udp_query(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError>;
}

/// Unprivileged POSIX network driver for Android userland execution.
///
/// A TCP response is complete once the peer has been silent for the driver's quiet period
/// after its first byte, which is how banner and keep-alive servers that never close are
/// answered before the dialogue deadline (see [`Transport::tcp_dialogue`]).
#[derive(Debug, Clone)]
pub struct UnprivilegedPosixTransport {
    quiet_period: Duration,
}

impl UnprivilegedPosixTransport {
    /// Quiet period used by [`Self::new`] and [`Default`]: one second of peer silence after
    /// the first response byte ends a dialogue with a peer that keeps the connection open.
    /// Multi-segment responses arrive back to back, so a second of silence marks a complete
    /// response even on high-latency mobile links, while a socket permit is never held for
    /// the whole deadline just to learn that a banner server will not hang up.
    pub const DEFAULT_QUIET_PERIOD: Duration = Duration::from_secs(1);

    /// Driver with [`Self::DEFAULT_QUIET_PERIOD`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_quiet_period(Self::DEFAULT_QUIET_PERIOD)
    }

    /// Driver whose TCP dialogues end after `quiet_period` of peer silence following the
    /// first response byte. The dialogue deadline always applies as well, so a quiet period
    /// longer than the deadline simply defers to the deadline.
    #[must_use]
    pub fn with_quiet_period(quiet_period: Duration) -> Self {
        Self { quiet_period }
    }

    /// The quiet period this driver applies after the first response byte.
    #[must_use]
    pub fn quiet_period(&self) -> Duration {
        self.quiet_period
    }
}

impl Default for UnprivilegedPosixTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes read from the socket per syscall. Small enough that 128 concurrent dialogues keep
/// well under a megabyte of read scratch, large enough for a banner in one read.
const READ_CHUNK: usize = 2048;

/// Why the response read loop stopped, short of the peer exceeding `max_bytes`.
#[derive(Debug)]
enum ReadEnd {
    /// The peer closed its side cleanly.
    Eof,
    /// Neither the deadline nor the quiet period saw another byte.
    Silence,
    /// The connection was reset, aborted or otherwise lost mid-read.
    Lost(io::Error),
}

/// `timeout` from now; a timeout too large to represent saturates at a year, which no
/// dialogue reaches, instead of overflowing the clock.
fn deadline_after(timeout: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(timeout)
        .unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
}

/// Whether a send failure means the peer already closed the connection, in which case any
/// answer it sent before closing is still waiting in the receive queue.
fn peer_closed(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}

/// `host:port` for display, bracketing IPv6 literals as RFC 3986 requires.
fn describe_target(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The unspecified address of `target`'s family on port 0: an ephemeral socket bound here can
/// reach `target`, whereas a `0.0.0.0` socket can never send to an IPv6 peer.
fn wildcard_bind_addr(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    }
}

/// Grow `buffer` so it can take `incoming` more bytes, doubling up to `cap` (never beyond), so
/// a large `max_bytes` costs no more than the bytes that actually arrive.
fn reserve_bounded(buffer: &mut Vec<u8>, incoming: usize, cap: usize) {
    let spare = buffer.capacity() - buffer.len();
    if spare >= incoming {
        return;
    }
    let doubled = buffer.capacity().max(READ_CHUNK).min(cap - buffer.len());
    buffer.reserve_exact(doubled.max(incoming));
}

/// Read the peer's response, never holding more than `max_bytes + 1` bytes of it.
///
/// Reads until EOF, until `deadline`, or, once at least one byte has arrived, until the peer
/// is silent for `quiet_period`. The caller decides what each ending means given how many
/// bytes arrived.
///
/// # Errors
/// Returns [`HuntsmanError::BufferLimitExceeded`] as soon as the peer has sent more than
/// `max_bytes`; the excess is never read.
async fn read_response(
    stream: &mut TcpStream,
    deadline: Instant,
    quiet_period: Duration,
    max_bytes: usize,
) -> Result<(Vec<u8>, ReadEnd), HuntsmanError> {
    // One byte past the limit is read so that "exactly max_bytes" and "more" are told apart.
    let cap = max_bytes.saturating_add(1);
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    let mut quiet_deadline: Option<Instant> = None;

    loop {
        let limit = quiet_deadline.map_or(deadline, |quiet| quiet.min(deadline));
        let want = (cap - buffer.len()).min(READ_CHUNK);
        match tokio::time::timeout_at(limit, stream.read(&mut chunk[..want])).await {
            Ok(Ok(0)) => return Ok((buffer, ReadEnd::Eof)),
            Ok(Ok(n)) => {
                reserve_bounded(&mut buffer, n, cap);
                buffer.extend_from_slice(&chunk[..n]);
                if buffer.len() > max_bytes {
                    return Err(HuntsmanError::BufferLimitExceeded {
                        limit: max_bytes,
                        attempted: buffer.len(),
                    });
                }
                quiet_deadline = Instant::now().checked_add(quiet_period);
            }
            Ok(Err(err)) if err.kind() == ErrorKind::Interrupted => {}
            Ok(Err(err)) => return Ok((buffer, ReadEnd::Lost(err))),
            Err(_) => return Ok((buffer, ReadEnd::Silence)),
        }
    }
}

#[async_trait]
impl Transport for UnprivilegedPosixTransport {
    async fn tcp_dialogue(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError> {
        let deadline = deadline_after(timeout);
        let target = describe_target(host, port);

        // The (host, port) tuple resolves hostnames and parses IPv4 and IPv6 literals alike.
        let mut stream =
            match tokio::time::timeout_at(deadline, TcpStream::connect((host, port))).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    return Err(HuntsmanError::Transport(format!(
                        "Connection to {target} failed: {err}"
                    )))
                }
                Err(_) => {
                    return Err(HuntsmanError::Transport(format!(
                        "Connection to {target} timed out after {timeout:?}"
                    )))
                }
            };

        // A peer that answers and closes without reading the payload fails the write; its
        // answer is still queued for us, so only a write fault with no answer is reported.
        let mut write_fault: Option<io::Error> = None;
        if !payload.is_empty() {
            match tokio::time::timeout_at(deadline, stream.write_all(payload)).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) if peer_closed(&err) => write_fault = Some(err),
                Ok(Err(err)) => {
                    return Err(HuntsmanError::Transport(format!(
                        "Write to {target} failed: {err}"
                    )))
                }
                Err(_) => {
                    return Err(HuntsmanError::Transport(format!(
                        "Write to {target} timed out after {timeout:?}"
                    )))
                }
            }
        }

        let (buffer, end) =
            read_response(&mut stream, deadline, self.quiet_period, max_bytes).await?;
        if !buffer.is_empty() {
            // Whatever ended the dialogue, the peer answered: that answer is the evidence.
            if let ReadEnd::Lost(err) = &end {
                debug!(
                    "Connection to {target} lost after {} response bytes: {err}",
                    buffer.len()
                );
            }
            return Ok(buffer);
        }
        if let Some(err) = write_fault {
            return Err(HuntsmanError::Transport(format!(
                "Write to {target} failed: {err}"
            )));
        }
        match end {
            ReadEnd::Eof => Ok(buffer),
            ReadEnd::Silence => Err(HuntsmanError::Transport(format!(
                "TCP dialogue with {target} received nothing within {timeout:?}"
            ))),
            ReadEnd::Lost(err) => Err(HuntsmanError::Transport(format!(
                "Read from {target} failed: {err}"
            ))),
        }
    }

    async fn udp_query(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError> {
        let target = describe_target(host, port);
        tokio::time::timeout(timeout, async {
            let resolved = tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| HuntsmanError::Transport(format!("Resolving {target} failed: {e}")))?
                .next()
                .ok_or_else(|| {
                    HuntsmanError::Transport(format!("{target} resolved to no address"))
                })?;

            let socket = UdpSocket::bind(wildcard_bind_addr(resolved))
                .await
                .map_err(|e| {
                    HuntsmanError::Transport(format!(
                        "Failed to bind ephemeral UDP socket for {resolved}: {e}"
                    ))
                })?;
            socket.connect(resolved).await.map_err(|e| {
                HuntsmanError::Transport(format!("UDP connect to {resolved} failed: {e}"))
            })?;

            socket.send(payload).await.map_err(|e| {
                HuntsmanError::Transport(format!("UDP transmit to {resolved} failed: {e}"))
            })?;

            let mut temp_buf = vec![0u8; max_bytes];
            let len = socket.recv(&mut temp_buf).await.map_err(|e| {
                HuntsmanError::Transport(format!("UDP receive from {resolved} failed: {e}"))
            })?;

            temp_buf.truncate(len);
            Ok(temp_buf)
        })
        .await
        .map_err(|_| HuntsmanError::Transport(format!("UDP dialogue with {target} timed out")))?
    }
}

/// Deterministic mock transport for offline unit testing and hermetic CI verification.
#[derive(Clone, Default)]
pub struct MockTransport {
    tcp_responses: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    udp_responses: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MockTransport {
    /// Create a new, empty mock transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a deterministic mock TCP response for a given `host:port`.
    pub async fn register_tcp(&self, host: &str, port: u16, response: Vec<u8>) {
        let mut map = self.tcp_responses.lock().await;
        map.insert(format!("{host}:{port}"), response);
    }

    /// Register a deterministic mock UDP response for a given `host:port`.
    pub async fn register_udp(&self, host: &str, port: u16, response: Vec<u8>) {
        let mut map = self.udp_responses.lock().await;
        map.insert(format!("{host}:{port}"), response);
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn tcp_dialogue(
        &self,
        host: &str,
        port: u16,
        _payload: &[u8],
        _timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError> {
        let key = format!("{host}:{port}");
        let map = self.tcp_responses.lock().await;
        match map.get(&key) {
            Some(data) => {
                if data.len() > max_bytes {
                    Err(HuntsmanError::BufferLimitExceeded {
                        limit: max_bytes,
                        attempted: data.len(),
                    })
                } else {
                    Ok(data.clone())
                }
            }
            None => Err(HuntsmanError::Transport(format!(
                "Mock TCP route missing: {key}"
            ))),
        }
    }

    async fn udp_query(
        &self,
        host: &str,
        port: u16,
        _payload: &[u8],
        _timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError> {
        let key = format!("{host}:{port}");
        let map = self.udp_responses.lock().await;
        match map.get(&key) {
            Some(data) => {
                if data.len() > max_bytes {
                    Err(HuntsmanError::BufferLimitExceeded {
                        limit: max_bytes,
                        attempted: data.len(),
                    })
                } else {
                    Ok(data.clone())
                }
            }
            None => Err(HuntsmanError::Transport(format!(
                "Mock UDP route missing: {key}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// A loopback listener on an ephemeral port, and that port.
    async fn loopback_listener() -> (TcpListener, u16) {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) => panic!("loopback bind failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr failed: {err}"),
        };
        (listener, port)
    }

    /// Accept one client, write `banner`, then hold the connection open until the client goes away.
    fn banner_then_hold(
        listener: TcpListener,
        banner: &'static [u8],
    ) -> tokio::task::JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            socket.write_all(banner).await?;
            let mut sink = [0u8; 64];
            while socket.read(&mut sink).await? > 0 {}
            Ok(())
        })
    }

    #[tokio::test]
    async fn a_banner_from_a_peer_that_never_closes_is_returned_before_the_deadline() {
        let (listener, port) = loopback_listener().await;
        let server = banner_then_hold(listener, b"SSH-2.0-OpenSSH_9.6\r\n");
        let transport = UnprivilegedPosixTransport::default();

        let started = std::time::Instant::now();
        let result = transport
            .tcp_dialogue("127.0.0.1", port, b"", Duration::from_secs(5), 4096)
            .await;
        let elapsed = started.elapsed();
        server.abort();

        match result {
            Ok(bytes) => assert_eq!(bytes, b"SSH-2.0-OpenSSH_9.6\r\n"),
            Err(err) => panic!("banner dialogue failed instead of returning the banner: {err}"),
        }
        assert!(
            elapsed < Duration::from_secs(4),
            "the banner was only returned at the deadline ({elapsed:?})"
        );
    }

    #[tokio::test]
    async fn a_configured_quiet_period_ends_the_dialogue_sooner_than_the_default() {
        let (listener, port) = loopback_listener().await;
        let server = banner_then_hold(listener, b"* OK IMAP4rev1 ready\r\n");
        let transport = UnprivilegedPosixTransport::with_quiet_period(Duration::from_millis(50));
        assert_eq!(transport.quiet_period(), Duration::from_millis(50));

        let started = std::time::Instant::now();
        let result = transport
            .tcp_dialogue("127.0.0.1", port, b"", Duration::from_secs(5), 4096)
            .await;
        let elapsed = started.elapsed();
        server.abort();

        match result {
            Ok(bytes) => assert_eq!(bytes, b"* OK IMAP4rev1 ready\r\n"),
            Err(err) => panic!("banner dialogue failed: {err}"),
        }
        assert!(
            elapsed < UnprivilegedPosixTransport::DEFAULT_QUIET_PERIOD,
            "a 50 ms quiet period took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_banner_followed_by_a_reset_is_returned_not_a_transport_fault() {
        let (listener, port) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            // Wait for the client's request to arrive, answer, and close without reading it:
            // closing with unread data in the receive queue makes the kernel send RST, not FIN.
            socket.readable().await?;
            socket
                .write_all(b"421 Too many connections, closing\r\n")
                .await?;
            drop(socket);
            Ok::<(), io::Error>(())
        });
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .tcp_dialogue("127.0.0.1", port, b"HELP\r\n", Duration::from_secs(3), 4096)
            .await;
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("server failed: {err}"),
            Err(err) => panic!("server task failed: {err}"),
        }

        match result {
            Ok(bytes) => assert_eq!(bytes, b"421 Too many connections, closing\r\n"),
            Err(err) => panic!("the refusal banner was lost to a transport fault: {err}"),
        }
    }

    #[tokio::test]
    async fn the_deadline_after_a_partial_response_returns_the_bytes_received() {
        let (listener, port) = loopback_listener().await;
        let server = banner_then_hold(listener, b"220 mail.example ESMTP\r\n");
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .tcp_dialogue("127.0.0.1", port, b"", Duration::from_millis(200), 4096)
            .await;
        server.abort();

        match result {
            Ok(bytes) => assert_eq!(bytes, b"220 mail.example ESMTP\r\n"),
            Err(err) => panic!("the deadline discarded a received banner: {err}"),
        }
    }

    #[tokio::test]
    async fn a_silent_peer_is_a_transport_timeout() {
        let (listener, port) = loopback_listener().await;
        let server = banner_then_hold(listener, b"");
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .tcp_dialogue("127.0.0.1", port, b"", Duration::from_millis(100), 4096)
            .await;
        server.abort();

        assert!(
            matches!(result, Err(HuntsmanError::Transport(_))),
            "a peer that sends nothing must be a transport timeout: {result:?}"
        );
    }

    #[tokio::test]
    async fn more_than_max_bytes_is_a_limit_error_and_exactly_max_bytes_is_not() {
        for (max_bytes, expect_ok) in [(64usize, true), (63usize, false)] {
            let (listener, port) = loopback_listener().await;
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                socket.write_all(&[b'x'; 64]).await?;
                Ok::<(), io::Error>(())
            });
            let transport = UnprivilegedPosixTransport::default();

            let result = transport
                .tcp_dialogue("127.0.0.1", port, b"", Duration::from_secs(3), max_bytes)
                .await;
            match server.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => panic!("server failed: {err}"),
                Err(err) => panic!("server task failed: {err}"),
            }

            if expect_ok {
                match result {
                    Ok(bytes) => assert_eq!(bytes.len(), 64),
                    Err(err) => panic!("exactly max_bytes must be accepted: {err}"),
                }
            } else {
                assert!(
                    matches!(
                        result,
                        Err(HuntsmanError::BufferLimitExceeded { limit: 63, attempted }) if attempted > 63
                    ),
                    "more than max_bytes must be a buffer limit error: {result:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_clean_close_without_a_banner_is_an_empty_response() {
        let (listener, port) = loopback_listener().await;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            drop(socket);
            Ok::<(), io::Error>(())
        });
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .tcp_dialogue("127.0.0.1", port, b"", Duration::from_secs(3), 4096)
            .await;
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("server failed: {err}"),
            Err(err) => panic!("server task failed: {err}"),
        }

        match result {
            Ok(bytes) => assert!(bytes.is_empty(), "{bytes:?}"),
            Err(err) => panic!("a clean close is an empty dialogue, not a fault: {err}"),
        }
    }

    #[tokio::test]
    async fn a_response_sent_while_the_payload_is_unread_survives_the_write_fault() {
        // A 4 KiB server receive buffer and a 4 MiB payload: write_all cannot finish before the
        // server answers and resets, so the write itself fails with the response still unread.
        let socket = match tokio::net::TcpSocket::new_v4() {
            Ok(socket) => socket,
            Err(err) => panic!("socket failed: {err}"),
        };
        if let Err(err) = socket.set_recv_buffer_size(4096) {
            panic!("set_recv_buffer_size failed: {err}");
        }
        let bind_addr: SocketAddr = match "127.0.0.1:0".parse() {
            Ok(addr) => addr,
            Err(err) => panic!("bind addr: {err}"),
        };
        if let Err(err) = socket.bind(bind_addr) {
            panic!("bind failed: {err}");
        }
        let listener = match socket.listen(1) {
            Ok(listener) => listener,
            Err(err) => panic!("listen failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr failed: {err}"),
        };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            // The payload is unread when the socket closes, so the close is an RST.
            socket.readable().await?;
            socket
                .write_all(b"HTTP/1.1 413 Payload Too Large\r\n\r\n")
                .await?;
            drop(socket);
            Ok::<(), io::Error>(())
        });
        let transport = UnprivilegedPosixTransport::default();
        let payload = vec![b'P'; 4 * 1024 * 1024];

        let result = transport
            .tcp_dialogue("127.0.0.1", port, &payload, Duration::from_secs(5), 4096)
            .await;
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("server failed: {err}"),
            Err(err) => panic!("server task failed: {err}"),
        }

        match result {
            Ok(bytes) => assert_eq!(bytes, b"HTTP/1.1 413 Payload Too Large\r\n\r\n"),
            Err(err) => panic!("the 413 answer was lost to the write fault: {err}"),
        }
    }

    #[tokio::test]
    async fn udp_query_round_trips_a_datagram_over_ipv4_loopback() {
        let server = match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(err) => panic!("udp bind failed: {err}"),
        };
        let port = match server.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr failed: {err}"),
        };
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (len, peer) = server.recv_from(&mut buf).await?;
            server.send_to(&buf[..len], peer).await?;
            Ok::<(), io::Error>(())
        });
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .udp_query("127.0.0.1", port, b"ping", Duration::from_secs(3), 64)
            .await;
        match echo.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("echo server failed: {err}"),
            Err(err) => panic!("echo task failed: {err}"),
        }
        match result {
            Ok(bytes) => assert_eq!(bytes, b"ping"),
            Err(err) => panic!("udp echo failed: {err}"),
        }
    }

    /// Whether this host can open IPv6 sockets at all; sandboxes without AF_INET6 cannot.
    async fn ipv6_loopback_available() -> bool {
        tokio::net::UdpSocket::bind("[::1]:0").await.is_ok()
    }

    #[tokio::test]
    async fn udp_query_reaches_an_ipv6_resolver() {
        if !ipv6_loopback_available().await {
            eprintln!("skipping: this host has no IPv6 loopback (AF_INET6 unsupported)");
            return;
        }
        let server = match tokio::net::UdpSocket::bind("[::1]:0").await {
            Ok(socket) => socket,
            Err(err) => panic!("udp v6 bind failed: {err}"),
        };
        let port = match server.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr failed: {err}"),
        };
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (len, peer) = server.recv_from(&mut buf).await?;
            server.send_to(&buf[..len], peer).await?;
            Ok::<(), io::Error>(())
        });
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .udp_query("::1", port, b"ping6", Duration::from_secs(3), 64)
            .await;
        match echo.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("echo server failed: {err}"),
            Err(err) => panic!("echo task failed: {err}"),
        }
        match result {
            Ok(bytes) => assert_eq!(bytes, b"ping6"),
            Err(err) => panic!("udp over IPv6 failed: {err}"),
        }
    }

    #[tokio::test]
    async fn tcp_dialogue_reaches_an_ipv6_literal() {
        if !ipv6_loopback_available().await {
            eprintln!("skipping: this host has no IPv6 loopback (AF_INET6 unsupported)");
            return;
        }
        let listener = match TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(err) => panic!("tcp v6 bind failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("local_addr failed: {err}"),
        };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await?;
            socket.write_all(b"v6 banner\r\n").await?;
            Ok::<(), io::Error>(())
        });
        let transport = UnprivilegedPosixTransport::default();

        let result = transport
            .tcp_dialogue("::1", port, b"", Duration::from_secs(3), 4096)
            .await;
        match server.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => panic!("server failed: {err}"),
            Err(err) => panic!("server task failed: {err}"),
        }
        match result {
            Ok(bytes) => assert_eq!(bytes, b"v6 banner\r\n"),
            Err(err) => panic!("tcp dialogue with an IPv6 literal failed: {err}"),
        }
    }

    #[test]
    fn the_ephemeral_bind_address_follows_the_target_family() {
        let v4: SocketAddr = match "1.1.1.1:53".parse() {
            Ok(addr) => addr,
            Err(err) => panic!("v4 literal: {err}"),
        };
        let v6: SocketAddr = match "[2606:4700:4700::1111]:53".parse() {
            Ok(addr) => addr,
            Err(err) => panic!("v6 literal: {err}"),
        };
        let bind_v4 = wildcard_bind_addr(v4);
        let bind_v6 = wildcard_bind_addr(v6);
        assert!(bind_v4.is_ipv4() && bind_v4.ip().is_unspecified() && bind_v4.port() == 0);
        assert!(bind_v6.is_ipv6() && bind_v6.ip().is_unspecified() && bind_v6.port() == 0);
        assert_eq!(bind_v4.to_string(), "0.0.0.0:0");
        assert_eq!(bind_v6.to_string(), "[::]:0");
    }

    #[test]
    fn ipv6_literals_are_bracketed_in_target_descriptions() {
        assert_eq!(describe_target("::1", 53), "[::1]:53");
        assert_eq!(describe_target("1.1.1.1", 53), "1.1.1.1:53");
        assert_eq!(
            describe_target("resolver.example", 853),
            "resolver.example:853"
        );
    }

    #[test]
    fn response_buffers_never_reserve_past_the_limit() {
        let cap = 100;
        let mut buffer = Vec::new();
        let mut total = 0;
        while total < cap {
            let incoming = (cap - total).min(7);
            reserve_bounded(&mut buffer, incoming, cap);
            assert!(
                buffer.capacity() <= cap,
                "capacity {} > {cap}",
                buffer.capacity()
            );
            buffer.extend_from_slice(&vec![0u8; incoming]);
            total += incoming;
        }
        assert_eq!(buffer.len(), cap);

        let mut large = Vec::new();
        reserve_bounded(&mut large, 1, 1 << 20);
        assert!(large.capacity() >= 1 && large.capacity() <= READ_CHUNK);
    }

    #[tokio::test]
    async fn the_mock_returns_registered_bytes_and_enforces_the_limit() {
        let mock = MockTransport::new();
        mock.register_tcp("example.com", 22, b"SSH-2.0-mock\r\n".to_vec())
            .await;
        mock.register_udp("1.1.1.1", 53, vec![0xAB; 8]).await;

        match mock
            .tcp_dialogue("example.com", 22, b"", Duration::from_secs(1), 64)
            .await
        {
            Ok(bytes) => assert_eq!(bytes, b"SSH-2.0-mock\r\n"),
            Err(err) => panic!("mock tcp failed: {err}"),
        }
        assert!(matches!(
            mock.udp_query("1.1.1.1", 53, b"", Duration::from_secs(1), 7)
                .await,
            Err(HuntsmanError::BufferLimitExceeded {
                limit: 7,
                attempted: 8
            })
        ));
        assert!(matches!(
            mock.tcp_dialogue("missing.example", 80, b"", Duration::from_secs(1), 64)
                .await,
            Err(HuntsmanError::Transport(_))
        ));
    }
}
