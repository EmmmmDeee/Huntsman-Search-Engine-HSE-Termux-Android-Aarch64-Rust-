//! Bluetooth scanner for signal_radar — parses `termux-bluetooth-scaninfo`
//! output.
//!
//! No `hcitool scan` fallback: this project's exclusive target is a no-root
//! Termux/Android install, where classic-BT `hcitool` is neither packaged
//! (no `bluez` in Termux's repo) nor usable even if sideloaded (an HCI
//! inquiry needs a raw Bluetooth socket/ioctl stock Android gates behind
//! privileges Termux cannot grant without root) — the fallback could never
//! actually fire on the real target device, only ever silently no-op.

use serde::Deserialize;

use crate::core::{confidence, 
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

        let mut e = Entity::new(EntityKind::MacAddress, &dev.address, confidence::HIGH_PLUSPLUS, scan_id);
        e.tag("bluetooth");
        e.tag(format!("bt-{}", bt_type.to_lowercase()));
        e.tag(format!("bond:{}", bond_state.to_lowercase()));

        let mut ev = Evidence::new(SRC, format!("Bluetooth device: {name}"))
            .with_attr("name", name)
            .with_attr("address", &dev.address)
            .with_attr("type", bt_type)
            .with_attr("bond_state", bond_state);

        // OUI classification — the same primitive the WiGLE path applies, so a
        // radar pin carries the vendor + device class where the address is real
        // hardware, and is flagged `randomized` (not attributed to any vendor)
        // where it is a locally-administered privacy address. This is the signal
        // AU-115 partitions on: a randomized MAC is a rotating throwaway, not a
        // followable device, and must never be plotted as one.
        if let Some(oui) = crate::util::oui::classify_mac(&dev.address) {
            e.tag(format!("vendor:{}", oui.vendor));
            e.tag(format!("device:{}", oui.class.as_str()));
            let trackable = crate::util::oui::is_locally_administered(&dev.address) == Some(false);
            e.tag(if trackable { "trackable" } else { "randomized" });
            ev = ev
                .with_attr("vendor", oui.vendor)
                .with_attr("device_class", oui.class.as_str())
                .with_attr("trackable", trackable.to_string());
        }

        e.add_evidence(ev);

        result.push(e);
    }

    result
}

/// Run bluetooth scan via `termux-bluetooth-scaninfo` (the Termux:API BLE/BT
/// scan shim — no root, no raw socket).
pub(super) async fn scan_bluetooth(scan_id: &str) -> ModuleResult {
    match termux_cmd("termux-bluetooth-scaninfo", &[], 10_000).await {
        Some(stdout) => parse_bt_json(&stdout, scan_id),
        None => ModuleResult::new(),
    }
}
