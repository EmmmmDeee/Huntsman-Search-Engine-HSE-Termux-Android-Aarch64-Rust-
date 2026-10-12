//! Network abstraction layer enforcing trait injection and hermetic test isolation.

use crate::error::HuntsmanError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Protocol dialogue interface decoupled from raw network sockets.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Transmit a framed request over TCP and read up to `max_bytes` into an allocated buffer.
    ///
    /// # Errors
    /// Returns [`HuntsmanError::Transport`] on connect/read/write/timeout failure and
    /// [`HuntsmanError::BufferLimitExceeded`] when the peer sends at least `max_bytes`.
    async fn tcp_dialogue(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError>;

    /// Issue an unprivileged UDP query (e.g., standard DNS port 53).
    ///
    /// # Errors
    /// Returns [`HuntsmanError::Transport`] on bind/connect/send/receive/timeout failure.
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
#[derive(Debug, Default)]
pub struct UnprivilegedPosixTransport;

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
        tokio::time::timeout(timeout, async {
            let addr = format!("{host}:{port}");
            let mut stream = TcpStream::connect(&addr).await.map_err(|e| {
                HuntsmanError::Transport(format!("Connection to {addr} failed: {e}"))
            })?;

            if !payload.is_empty() {
                stream.write_all(payload).await.map_err(|e| {
                    HuntsmanError::Transport(format!("Write to {addr} failed: {e}"))
                })?;
            }

            let mut buffer = Vec::new();
            let mut reader = stream.take(max_bytes as u64);
            reader
                .read_to_end(&mut buffer)
                .await
                .map_err(|e| HuntsmanError::Transport(format!("Read from {addr} failed: {e}")))?;

            if buffer.len() >= max_bytes {
                return Err(HuntsmanError::BufferLimitExceeded {
                    limit: max_bytes,
                    attempted: buffer.len(),
                });
            }

            Ok(buffer)
        })
        .await
        .map_err(|_| {
            HuntsmanError::Transport(format!("TCP dialogue with {host}:{port} timed out"))
        })?
    }

    async fn udp_query(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HuntsmanError> {
        tokio::time::timeout(timeout, async {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| {
                    HuntsmanError::Transport(format!("Failed to bind ephemeral UDP socket: {e}"))
                })?;
            let target = format!("{host}:{port}");
            socket.connect(&target).await.map_err(|e| {
                HuntsmanError::Transport(format!("UDP connect to {target} failed: {e}"))
            })?;

            socket.send(payload).await.map_err(|e| {
                HuntsmanError::Transport(format!("UDP transmit to {target} failed: {e}"))
            })?;

            let mut temp_buf = vec![0u8; max_bytes];
            let len = socket.recv(&mut temp_buf).await.map_err(|e| {
                HuntsmanError::Transport(format!("UDP receive from {target} failed: {e}"))
            })?;

            temp_buf.truncate(len);
            Ok(temp_buf)
        })
        .await
        .map_err(|_| {
            HuntsmanError::Transport(format!("UDP dialogue with {host}:{port} timed out"))
        })?
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
