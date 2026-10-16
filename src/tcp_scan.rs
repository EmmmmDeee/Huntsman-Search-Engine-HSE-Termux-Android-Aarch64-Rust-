//! Bounded TCP connect scan.
//!
//! One scan is one `TcpStream::connect` per port in a fixed list.
//! Resolves once. No root. No raw sockets. No external binary.
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
/// Returns the address resolution failure. Individual port failures are closed.
pub fn scan(host: &str, ports: &[u16], timeout: Duration) -> Result<Vec<OpenPort>, std::io::Error> {
    let addr = format!("{host}:0");
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    let Some(base) = addrs.into_iter().next() else {
        return Ok(Vec::new());
    };
    let mut open = Vec::new();
    for &port in ports {
        let mut addr = base;
        addr.set_port(port);
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
        let open = scan("127.0.0.1", &[1], Duration::from_millis(50)).unwrap();
        assert!(open.is_empty());
    }

    #[test]
    fn an_unresolvable_host_is_an_error() {
        assert!(scan("invalid.invalid", &[80], Duration::from_millis(50)).is_err());
    }
}
