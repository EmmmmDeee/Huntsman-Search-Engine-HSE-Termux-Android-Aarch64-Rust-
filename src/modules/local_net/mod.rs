//! Local network discovery — ARP table + network interface enumeration.
//!
//! Reads `/sys/class/net/*/address` and `/sys/class/net/*/operstate` for
//! interfaces, then `/proc/net/arp` for the ARP table. Pure file I/O via
//! `tokio::fs` — no root, no termux-api, no network traffic. Passive sensor.
//!
//! Off-Linux hosts (macOS, Windows) lack these paths and no-op cleanly.
//! Local-network data is environmental — it describes the operator's own LAN,
//! never a remote subject — so it engages only on a deliberately-local seed
//! (coordinates / MAC), not a name/email/domain/IP scan. Exclude with
//! `--exclude local_net`.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
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
    fn accepts(&self, t: &Target) -> bool {
        // Local-network data describes the operator's own LAN, not a remote
        // subject — engage only on a deliberately-local seed (coordinates / MAC)
        // so the operator's ARP/interface entries aren't attributed to a
        // name/email/domain/IP subject (fault-tree cut set MCS-A). Expansion is
        // already gated for LOCAL_PASSIVE_MODULES, so this governs the seed round.
        matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Sensor
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Sensor default (T1592 Host Information) covers MAC address discovery
        // (hardware identification). local_net also enumerates local network
        // IpAddress entities → T1590.005 IP Addresses, absent from Sensor default.
        &["T1590.005", "T1592"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::MacAddress, EntityKind::IpAddress];
        KINDS
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
                e.tag(crate::core::tags::LOCAL_INTERFACE);
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
        ip_entity.tag(crate::core::tags::LOCAL_ARP);
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
        mac_entity.tag(crate::core::tags::LOCAL_ARP);
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
    include!("tests.rs");
}
