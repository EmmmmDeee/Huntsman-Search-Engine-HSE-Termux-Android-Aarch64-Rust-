//! Bounded TCP connect scan is not implemented.
//!
//! A direct `TcpStream` violates the architecture boundary: only the transport
//! and the listener own a socket. Port presence for public IPs is covered by
//! InternetDB. A no-root connect scan requires a transport method that does
//! not yet exist.

/// Ports that would be scanned.
pub const DEFAULT_PORTS: &[u16] = &[22, 80, 443, 8080, 8443];

/// One open port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
}
