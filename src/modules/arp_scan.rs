//! ARP table reader — parses `/proc/net/arp` on Linux/Android. No root,
//! no termux-api binary needed, no network traffic — passive sensor.
//!
//! On a non-Linux host (macOS dev box, etc.) the file doesn't exist and
//! the module no-ops with an empty `ModuleResult`.
//!
//! Accepts any target — the ARP table is environmental and doesn't depend
//! on what's being scanned. Exclude with `--exclude arp_scan` if you don't
//! want local-network entities mixed into your scan results.

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::Target,
};

pub struct ArpScan;

#[async_trait]
impl Module for ArpScan {
    fn name(&self) -> &'static str {
        "arp_scan"
    }
    fn priority(&self) -> u8 {
        58
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // not Linux, no /proc — no-op
        let Ok(content) = tokio::fs::read_to_string("/proc/net/arp").await else {
            return Ok(ModuleResult::new());
        };
        Ok(parse_arp(&content, &ctx.scan_id))
    }
}

/// Parses the ARP table format. First line is the header; data rows have
/// columns: IP, HW type, Flags, MAC, Mask, Device. Rows with the placeholder
/// MAC `00:00:00:00:00:00` are incomplete (no resolution yet) and skipped.
fn parse_arp(content: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let ip = cols[0];
        let mac = cols[3];
        let dev = cols[5];
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        let mut ip_entity = Entity::new(EntityKind::IpAddress, ip, 0.95, scan_id);
        ip_entity.tag("local-arp");
        ip_entity.add_evidence(
            Evidence::new("arp_scan", format!("ARP entry on {dev}"))
                .with_attr("mac", mac)
                .with_attr("interface", dev),
        );
        result.push(ip_entity);

        let mut mac_entity = Entity::new(EntityKind::MacAddress, mac, 0.95, scan_id);
        mac_entity.tag("local-arp");
        mac_entity.add_evidence(
            Evidence::new("arp_scan", format!("ARP: {ip} via {dev}"))
                .with_attr("ip", ip)
                .with_attr("interface", dev),
        );
        result.push(mac_entity);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(ArpScan.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(ArpScan.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(ArpScan.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn parser_emits_two_entities_per_complete_row() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
192.168.1.5      0x1         0x2         11:22:33:44:55:66     *        wlan0
";
        let r = parse_arp(sample, "test-scan");
        assert_eq!(r.entities.len(), 4); // 2 rows × (IP + MAC)
    }

    #[test]
    fn parser_skips_incomplete_rows() {
        let sample = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
";
        let r = parse_arp(sample, "test-scan");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parser_skips_short_rows() {
        let r = parse_arp("IP\nshort line\n", "test-scan");
        assert_eq!(r.entities.len(), 0);
    }
}
