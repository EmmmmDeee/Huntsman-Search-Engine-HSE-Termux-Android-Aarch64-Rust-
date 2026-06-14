//! Bluetooth scanner for signal_radar — parses `termux-bluetooth-scaninfo`
//! output with `hcitool scan` as a fallback.

use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::termux::termux_cmd;

use super::SRC;

#[derive(Deserialize)]
pub(super) struct BtDevice {
    pub(super) address: String,
    pub(super) name: Option<String>,
    #[serde(rename = "type")]
    pub(super) bt_type: Option<String>,
    #[serde(rename = "bondState")]
    pub(super) bond_state: Option<String>,
}

/// Parse the JSON array from `termux-bluetooth-scaninfo`.
pub(super) fn parse_bt_json(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let devices: Vec<BtDevice> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::with_capacity(devices.len());

    for dev in devices {
        if dev.address.is_empty() || dev.address == "00:00:00:00:00:00" {
            continue;
        }

        let name = dev.name.as_deref().unwrap_or("<unknown>");
        let bt_type = dev.bt_type.as_deref().unwrap_or("unknown");
        let bond_state = dev.bond_state.as_deref().unwrap_or("unknown");

        let mut e = Entity::new(EntityKind::MacAddress, &dev.address, 0.80, scan_id);
        e.tag("bluetooth");
        e.tag(format!("bt-{}", bt_type.to_lowercase()));
        e.tag(format!("bond:{}", bond_state.to_lowercase()));

        e.add_evidence(
            Evidence::new(SRC, format!("Bluetooth device: {name}"))
                .with_attr("name", name)
                .with_attr("address", &dev.address)
                .with_attr("type", bt_type)
                .with_attr("bond_state", bond_state),
        );

        result.push(e);
    }

    result
}

/// Parse plain-text `hcitool scan` output (fallback).
///
/// Each data line is: `\t<MAC>\t<name>`
pub(super) fn parse_hcitool(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let text = match std::str::from_utf8(stdout) {
        Ok(s) => s,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Scanning") {
            continue;
        }
        let mut parts = trimmed.splitn(2, '\t');
        let Some(addr) = parts.next() else { continue };
        let name = parts.next().unwrap_or("<unknown>").trim();
        let addr = addr.trim();

        if addr.is_empty() || addr == "00:00:00:00:00:00" {
            continue;
        }

        let mut e = Entity::new(EntityKind::MacAddress, addr, 0.80, scan_id);
        e.tag("bluetooth");
        e.tag("bt-classic");
        e.tag("bond:none");

        e.add_evidence(
            Evidence::new(SRC, format!("Bluetooth device (hcitool): {name}"))
                .with_attr("name", name)
                .with_attr("address", addr)
                .with_attr("source", "hcitool"),
        );

        result.push(e);
    }

    result
}

/// Run bluetooth scan: try termux-bluetooth-scaninfo first; fall back to
/// `hcitool scan` if no results.
pub(super) async fn scan_bluetooth(scan_id: &str) -> ModuleResult {
    if let Some(stdout) = termux_cmd("termux-bluetooth-scaninfo", &[], 10_000).await {
        let result = parse_bt_json(&stdout, scan_id);
        if !result.is_empty() {
            return result;
        }
    }

    // Fallback: hcitool scan (classic BT only, requires hcitools installed)
    if let Some(stdout) = termux_cmd("hcitool", &["scan", "--flush"], 10_000).await {
        return parse_hcitool(&stdout, scan_id);
    }

    ModuleResult::new()
}
