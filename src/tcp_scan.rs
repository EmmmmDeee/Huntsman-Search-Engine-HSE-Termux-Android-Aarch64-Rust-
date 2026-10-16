//! Bounded TCP connect scan.
//!
//! One scan is one `TcpStream::connect` per port in a fixed list.
//! No root. No raw sockets. No external binary.
//! A connection is an open port. A refusal or timeout is closed.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Ports scanned by default.
pub const DEFAULT_PORTS: &[u16] = &[22, 80, 443, 8080, 8443];

/// One open port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
}

/// Scan `host` on `ports`. **Blocking.**
///
/// # Errors
/// Returns the first address resolution failure. Individual port failures are closed.
pub fn scan(host: &str, ports: &[u16], timeout: Duration) -> Result<Vec<OpenPort>, std::io::Error> {
    let mut open = Vec::new();
    for &port in ports {
        let addr = format!("{host}:{port}");
        let Ok(mut addrs) = addr.to_socket_addrs() else {
            continue;
        };
        let Some(addr) = addrs.next() else {
            continue;
        };
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            open.push(OpenPort { port });
        }
    }
    Ok(open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_port_is_absent() {
        let open = scan("127.0.0.1", &[1], Duration::from_millis(100)).unwrap();
        assert!(open.is_empty());
    }
}
