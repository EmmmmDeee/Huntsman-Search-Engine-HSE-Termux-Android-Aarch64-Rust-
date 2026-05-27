//! Local network discovery — ARP table + network interface enumeration.
//!
//! Reads `/sys/class/net/*/address` and `/sys/class/net/*/operstate` for
//! interfaces, then `/proc/net/arp` for the ARP table. Pure file I/O via
//! `tokio::fs` — no root, no termux-api, no network traffic. Passive sensor.
//!
//! Off-Linux hosts (macOS, Windows) lack these paths and no-op cleanly.
//! Accepts any target — local-network data is environmental and does not
//! depend on the scan target. Exclude with `--exclude local_net`.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::Target,
};

const SRC: &str = "local_net";

pub struct LocalNet;

#[async_trait]
impl Module for LocalNet {
    fn name(&self) -> &'static str {
        "local_net"
    }
    fn description(&self) -> &'static str {
        "Local network discovery via ARP table and network interfaces"
    }
    fn priority(&self) -> u8 {
        58
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        // ── 1. Network interfaces (/sys/class/net) ──────────────────
        if let Ok(mut entries) = tokio::fs::read_dir("/sys/class/net").await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let iface_os = entry.file_name();
                if iface_os == "lo" {
                    continue;
                }

                let dir = entry.path();
                let mac = match tokio::fs::read_to_string(dir.join("address")).await {
                    Ok(s) => s.trim().to_lowercase(),
                    Err(_) => continue,
                };
                if mac.is_empty() || mac == "00:00:00:00:00:00" {
                    continue;
                }

                let state = tokio::fs::read_to_string(dir.join("operstate"))
                    .await
                    .map_or_else(|_| "unknown".into(), |s| s.trim().to_string());

                let iface = iface_os.to_string_lossy();
                let mut e = Entity::new(EntityKind::MacAddress, &mac, 0.95, &ctx.scan_id);
                e.tag("local-interface");
                e.add_evidence(
                    Evidence::new(SRC, format!("Local interface {iface} ({state})"))
                        .with_attr("interface", iface.as_ref())
                        .with_attr("operstate", &state),
                );
                result.push(e);
            }
        }

        // ── 2. ARP table (/proc/net/arp) ─────────────────────────────
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/arp").await {
            parse_arp(&content, &ctx.scan_id, &mut result);
        }

        Ok(result)
    }
}

/// Parses the ARP table format. First line is the header; data rows have
/// columns: IP, HW type, Flags, MAC, Mask, Device. Rows with the placeholder
/// MAC `00:00:00:00:00:00` are incomplete (no resolution yet) and skipped.
fn parse_arp(content: &str, scan_id: &str, result: &mut ModuleResult) {
    for line in content.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let (Some(ip), Some(hw_type), Some(flags), Some(mac), Some(_mask), Some(dev)) = (
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
            cols.next(),
        ) else {
            continue;
        };
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        let vendor = oui_vendor(mac);

        let mut ip_entity = Entity::new(EntityKind::IpAddress, ip, 0.95, scan_id);
        ip_entity.tag("local-arp");
        let mut ip_ev = Evidence::new(SRC, format!("ARP entry on {dev}"))
            .with_attr("mac", mac)
            .with_attr("interface", dev)
            .with_attr("hw_type", hw_type)
            .with_attr("flags", flags);
        if let Some(v) = vendor {
            ip_ev = ip_ev.with_attr("vendor", v);
        }
        ip_entity.add_evidence(ip_ev);
        result.push(ip_entity);

        let mut mac_entity = Entity::new(EntityKind::MacAddress, mac, 0.95, scan_id);
        mac_entity.tag("local-arp");
        if let Some(v) = vendor {
            mac_entity.tag(format!("vendor:{}", v.to_lowercase().replace(' ', "-")));
        }
        let mut mac_ev = Evidence::new(SRC, format!("ARP: {ip} via {dev}"))
            .with_attr("ip", ip)
            .with_attr("interface", dev)
            .with_attr("hw_type", hw_type)
            .with_attr("flags", flags);
        if let Some(v) = vendor {
            mac_ev = mac_ev.with_attr("vendor", v);
        }
        mac_entity.add_evidence(mac_ev);
        result.push(mac_entity);
    }
}

fn oui_vendor(mac: &str) -> Option<&'static str> {
    let prefix = mac.get(..8)?.to_uppercase();
    match prefix.as_str() {
        "00:50:56" | "00:0C:29" | "00:05:69" => Some("VMware"),
        "08:00:27" => Some("VirtualBox"),
        "52:54:00" => Some("QEMU"),
        "00:15:5D" => Some("Hyper-V"),
        "00:16:3E" => Some("Xen"),
        "02:42:AC" | "02:42:00" => Some("Docker"),
        "DC:A6:32" | "B8:27:EB" | "E4:5F:01" => Some("Raspberry Pi"),
        "3C:22:FB" | "AC:BC:32" | "F0:18:98" => Some("Apple"),
        "00:25:00" | "04:D4:C4" | "88:36:6C" => Some("Apple"),
        "FC:F5:C4" | "3C:06:30" | "38:F9:D3" => Some("Apple"),
        "28:6C:07" | "48:2C:A0" | "CC:46:D6" => Some("Samsung"),
        "00:1A:11" | "00:E0:4C" | "52:54:AB" => Some("Realtek"),
        "00:24:D7" | "B4:2E:99" | "C8:5B:76" => Some("Intel"),
        "00:1B:21" | "3C:97:0E" | "40:8D:5C" => Some("Intel"),
        "00:26:18" | "00:AA:01" | "68:05:CA" => Some("Cisco"),
        "00:0C:42" | "A4:56:02" | "C4:71:54" => Some("Cisco"),
        "00:1E:58" | "04:18:D6" | "24:A0:74" => Some("TP-Link"),
        "00:0E:8F" | "2C:56:DC" | "78:44:76" => Some("Netgear"),
        "00:90:A9" | "04:A1:51" | "6C:B0:CE" => Some("Huawei"),
        "74:DA:38" | "7C:B5:9B" | "AC:CF:85" => Some("Espressif"),
        "84:0D:8E" | "84:F3:EB" | "A0:20:A6" => Some("Espressif"),
        _ => None,
    }
}

/// Standalone helper used by tests — wraps `parse_arp` to return a
/// `ModuleResult` directly, matching the old `arp_scan` test API.
#[cfg(test)]
fn parse_arp_result(content: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();
    parse_arp(content, scan_id, &mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    // ── Tests carried from net_interfaces.rs ─────────────────────────

    #[test]
    fn is_passive() {
        assert!(LocalNet.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(LocalNet.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn module_name() {
        assert_eq!(LocalNet.name(), "local_net");
    }

    #[test]
    fn module_priority() {
        assert_eq!(LocalNet.priority(), 58);
    }

    #[test]
    fn accepts_all_target_kinds() {
        assert!(LocalNet.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(LocalNet.accepts(&Target::new(TargetKind::IpAddress, "10.0.0.1")));
        assert!(LocalNet.accepts(&Target::new(TargetKind::Username, "user1")));
    }

    #[test]
    fn cost_is_free() {
        assert_eq!(LocalNet.cost(), ModuleCost::Free);
    }

    #[test]
    fn info_aggregates_metadata() {
        let info = LocalNet.info();
        assert_eq!(info.name, "local_net");
        assert_eq!(info.priority, 58);
        assert!(info.passive);
    }

    // ── Tests (from local network discovery) ───────────────────────────────

    #[test]
    fn parser_emits_two_entities_per_complete_row() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
192.168.1.5      0x1         0x2         11:22:33:44:55:66     *        wlan0
";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 4); // 2 rows x (IP + MAC)
    }

    #[test]
    fn parser_skips_incomplete_rows() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_skips_short_rows() {
        let r = parse_arp_result("IP\nshort line\n", "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_entity_fields_correct() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 2);

        // First entity: IP address
        let ip = &r.entities[0];
        assert_eq!(ip.kind, EntityKind::IpAddress);
        assert_eq!(ip.value, "192.168.1.1");
        assert!((ip.confidence - 0.95).abs() < 1e-6);
        assert!(ip.has_tag("local-arp"));
        assert_eq!(ip.evidence.len(), 1);
        assert_eq!(ip.evidence[0].source, "local_net");
        assert_eq!(
            ip.evidence[0].attributes.get("mac").unwrap(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(ip.evidence[0].attributes.get("interface").unwrap(), "wlan0");

        // Second entity: MAC address
        let mac = &r.entities[1];
        assert_eq!(mac.kind, EntityKind::MacAddress);
        assert_eq!(mac.value, "aa:bb:cc:dd:ee:ff");
        assert!(mac.has_tag("local-arp"));
        assert_eq!(mac.evidence[0].attributes.get("ip").unwrap(), "192.168.1.1");
        assert_eq!(
            mac.evidence[0].attributes.get("interface").unwrap(),
            "wlan0"
        );
    }

    #[test]
    fn parser_header_only_yields_empty() {
        let sample =
            "IP address       HW type     Flags       HW address            Mask     Device\n";
        let r = parse_arp_result(sample, "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_mixed_valid_and_incomplete_rows() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         de:ad:be:ef:00:01     *        eth0
10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.3         0x1         0x2         de:ad:be:ef:00:03     *        eth0
";
        let r = parse_arp_result(sample, "s");
        // Row 2 is incomplete (all-zero MAC) so skipped; rows 1 and 3 produce 2 entities each
        assert_eq!(r.entities.len(), 4);
        assert_eq!(r.entities[0].value, "10.0.0.1");
        assert_eq!(r.entities[2].value, "10.0.0.3");
    }

    #[test]
    fn parser_empty_input() {
        let r = parse_arp_result("", "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    // ── OUI vendor lookup ────────────────────────────────────────────

    #[test]
    fn oui_known_vendors() {
        assert_eq!(oui_vendor("00:50:56:aa:bb:cc"), Some("VMware"));
        assert_eq!(oui_vendor("08:00:27:11:22:33"), Some("VirtualBox"));
        assert_eq!(oui_vendor("52:54:00:ab:cd:ef"), Some("QEMU"));
        assert_eq!(oui_vendor("02:42:AC:11:00:02"), Some("Docker"));
    }

    #[test]
    fn oui_unknown_vendor() {
        assert_eq!(oui_vendor("aa:bb:cc:dd:ee:ff"), None);
    }

    #[test]
    fn oui_short_mac_returns_none() {
        assert_eq!(oui_vendor("aa:bb"), None);
    }
}
