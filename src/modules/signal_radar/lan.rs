//! LAN neighbour discovery for signal_radar.
//!
//! Reads `/proc/net/arp` for resolved ARP entries, emitting both
//! `MacAddress` and `IpAddress` entities. Then sweeps common ports
//! (22, 80, 443) on each ARP IP via non-blocking TCP connect with a
//! 500 ms timeout per host/port — no root, no raw sockets.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

use super::SRC;

const SWEEP_PORTS: &[u16] = &[22, 80, 443];
const SWEEP_TIMEOUT_MS: u64 = 500;

/// Parse `/proc/net/arp`.
///
/// Format (after header line):
/// `IP address  HW type  Flags  HW address        Mask  Device`
///
/// Flags `0x2` means a complete (resolved) ARP entry. We skip everything
/// else (0x0 = incomplete, 0x4 = proxy) and the placeholder MAC
/// `00:00:00:00:00:00`.
pub(super) fn parse_arp(content: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for line in content.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let (Some(ip), Some(_hw_type), Some(flags), Some(mac), Some(_mask), Some(dev)) = (
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
        ) else {
            continue;
        };

        // Only complete entries (flags == 0x2)
        if flags != "0x2" {
            continue;
        }
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        // IP entity
        let mut ip_e = Entity::new(
            EntityKind::IpAddress,
            ip,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        ip_e.tag("lan-host");
        ip_e.add_evidence(
            Evidence::new(SRC, format!("ARP neighbour on {dev}"))
                .with_attr("mac", mac)
                .with_attr("interface", dev)
                .with_attr("flags", flags),
        );
        result.push(ip_e);

        // MAC entity
        let mut mac_e = Entity::new(
            EntityKind::MacAddress,
            mac,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        mac_e.tag("arp-neighbor");
        mac_e.tag("lan");
        mac_e.add_evidence(
            Evidence::new(SRC, format!("ARP: {ip} via {dev}"))
                .with_attr("ip", ip)
                .with_attr("interface", dev)
                .with_attr("flags", flags),
        );
        result.push(mac_e);
    }

    result
}

/// TCP connect sweep of well-known ports on ARP-discovered IPs.
///
/// Returns a list of `"ip:port"` strings for open ports found.
pub(super) async fn port_sweep(ips: &[String]) -> Vec<String> {
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    let mut open = Vec::new();

    for ip in ips {
        for &port in SWEEP_PORTS {
            let addr = format!("{ip}:{port}");
            let dur = Duration::from_millis(SWEEP_TIMEOUT_MS);
            if timeout(dur, TcpStream::connect(&addr))
                .await
                .is_ok_and(|r| r.is_ok())
            {
                open.push(addr);
            }
        }
    }

    open
}

/// Full LAN scan: ARP parse + optional port sweep for discovered IPs.
///
/// `open_ports` evidence is added as tags to the already-emitted IP
/// entities where a port was found open.
pub(super) async fn scan_lan(scan_id: &str) -> ModuleResult {
    let content = match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(s) => s,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = parse_arp(&content, scan_id);

    // Collect unique IPs from the ARP result for the port sweep.
    let ips: Vec<String> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress)
        .map(|e| e.value.clone())
        .collect();

    if ips.is_empty() {
        return result;
    }

    let open = port_sweep(&ips).await;

    // Tag IP entities whose port was found open.
    for open_addr in &open {
        if let Some(colon) = open_addr.rfind(':') {
            let ip = &open_addr[..colon];
            let port = &open_addr[colon + 1..];
            for e in &mut result.entities {
                if e.kind == EntityKind::IpAddress && e.value == ip {
                    e.tag(format!("open:{port}"));
                }
            }
        }
    }

    result
}
