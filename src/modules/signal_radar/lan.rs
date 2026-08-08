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
/// Bounded concurrency for the port sweep's ip×port cross product — same
/// pattern and cap as `modules::portscan::scan_ports`'s `MAX_CONCURRENT`, so a
/// large ARP table (a /24 subnet can carry up to 254 hosts) can't fire
/// hundreds of simultaneous TCP connects at once.
const SWEEP_MAX_CONCURRENT: usize = 16;

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

/// TCP connect sweep of `ports` on `ips`.
///
/// Returns a list of `"ip:port"` strings for open ports found, sorted for
/// deterministic output. Runs the ip×port cross product CONCURRENTLY, bounded
/// by [`SWEEP_MAX_CONCURRENT`] — the same `Semaphore` + `JoinSet` pattern
/// `modules::portscan::scan_ports` uses (whose own test binds a real
/// ephemeral listener; `ports` is a parameter here for the same reason: an
/// ephemeral port is injectable in tests where the production
/// [`SWEEP_PORTS`] (22/80/443) is not). The previous fully-sequential loop
/// could block for up to `ips.len() * ports.len() * SWEEP_TIMEOUT_MS`
/// (several seconds on even a modest LAN with a handful of unreachable/
/// filtered hosts) when every attempt is an independent, I/O-bound wait with
/// nothing to serialise on.
pub(super) async fn port_sweep(ips: &[String], ports: &[u16]) -> Vec<String> {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    let sem = Arc::new(Semaphore::new(SWEEP_MAX_CONCURRENT));
    let mut set = tokio::task::JoinSet::new();
    for ip in ips {
        for &port in ports {
            let addr = format!("{ip}:{port}");
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let dur = Duration::from_millis(SWEEP_TIMEOUT_MS);
                timeout(dur, TcpStream::connect(&addr))
                    .await
                    .is_ok_and(|r| r.is_ok())
                    .then_some(addr)
            });
        }
    }

    let mut open = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(addr)) = joined {
            open.push(addr);
        }
    }
    open.sort_unstable();
    open
}

/// Full LAN scan: ARP parse + optional port sweep for discovered IPs.
///
/// `open_ports` evidence is added as tags to the already-emitted IP
/// entities where a port was found open.
pub(super) async fn scan_lan(scan_id: &str) -> ModuleResult {
    // `/proc/net/arp` is unreadable to an unprivileged app on the primary
    // target platform: on non-root Termux (Android 14 / SDK 34, SELinux
    // domain `untrusted_app`) the read returns EACCES — the file exists but
    // access is denied (reconfirmed live on-device 2026-07-31). That is the
    // normal, permanent condition here, not a fault, so it must stay a clean
    // empty result: promoting the denial to a `ModuleError` would fire on
    // every sweep and trip signal_radar's circuit breaker. The errno kind is
    // surfaced at debug level only, so a verbose diagnostics run can still
    // tell "denied" (EACCES, on-device) and "no such file" (ENOENT, off-Linux)
    // apart from a genuinely empty ARP table — without that distinction ever
    // reaching the operator as a finding or the breaker as a failure.
    let content = match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(
                error = %e,
                kind = ?e.kind(),
                "signal_radar: /proc/net/arp unreadable — treating as empty",
            );
            return ModuleResult::new();
        }
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

    let open = port_sweep(&ips, SWEEP_PORTS).await;

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
