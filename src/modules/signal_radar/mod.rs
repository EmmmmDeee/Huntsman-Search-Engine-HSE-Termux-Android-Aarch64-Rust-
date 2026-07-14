//! Real-time multi-sensor signal radar — WiFi AP scan, Bluetooth scan,
//! cell tower survey, GPS fix, and LAN ARP discovery in a single parallel pass.
//!
//! All sensors run concurrently via `tokio::join!`.  Off-device (no Termux
//! binaries) every termux-backed sub-sensor no-ops cleanly.  `/proc/net/arp`
//! and the TCP port sweep work anywhere on Linux.
//!
//! MITRE ATT&CK Reconnaissance (TA0043):
//!   T1590.005 — IP Addresses (LAN ARP)
//!   T1592     — Gather Victim Host Information
//!   T1592.001 — Hardware (Bluetooth / WiFi / cell-radio identifiers)
//!
//! (Passive RF observation is *like* T1040 Network Sniffing, but that technique
//! belongs to Collection/Credential-Access, not Reconnaissance — so it is
//! deliberately not claimed against this Reconnaissance-only mapping.)

mod bluetooth;
mod cell;
mod gps;
mod lan;
mod wifi;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

pub(super) const SRC: &str = "signal_radar";

pub struct SignalRadar;

#[async_trait]
impl Module for SignalRadar {
    fn name(&self) -> &'static str {
        "signal_radar"
    }

    fn description(&self) -> &'static str {
        "Real-time multi-sensor signal radar: WiFi AP scan, Bluetooth, cell towers, GPS, and LAN ARP discovery"
    }

    fn priority(&self) -> u8 {
        60
    }

    fn is_passive(&self) -> bool {
        true
    }

    /// Surveys the operator's local RF environment — only relevant when the
    /// scan target is the operator's own physical location (geo/device seed).
    /// Running on a name/email/domain seed would attribute the phone's current
    /// GPS fix, visible cell towers, and nearby Wi-Fi APs to the remote
    /// subject, contaminating results (fault-tree cut set MCS-A).
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Sensor
    }

    fn max_timeout_ms(&self) -> u64 {
        25_000
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1590.005", "T1592", "T1592.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::MacAddress,
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::DeviceId,
        ];
        KINDS
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let scan_id = ctx.scan_id.as_str();

        // Run all sensors in parallel.
        let (wifi_out, bt_out, gps_out, lan_out) = tokio::join!(
            scan_wifi(scan_id),
            bluetooth::scan_bluetooth(scan_id),
            gps::scan_gps(scan_id),
            lan::scan_lan(scan_id),
        );

        let cell_out = scan_cell(scan_id).await;

        let mut result = ModuleResult::new();
        result.extend(wifi_out.entities);
        result.extend(bt_out.entities);
        result.extend(gps_out.entities);
        result.extend(lan_out.entities);
        result.extend(cell_out.entities);

        Ok(result)
    }
}

/// Fetch and parse `termux-wifi-scaninfo`.
async fn scan_wifi(scan_id: &str) -> ModuleResult {
    use crate::util::termux::termux_cmd;
    match termux_cmd("termux-wifi-scaninfo", &[], 8000).await {
        Some(stdout) => wifi::parse_scan(&stdout, scan_id),
        None => ModuleResult::new(),
    }
}

/// Fetch and parse `termux-telephony-cellinfo`. Per-cell `dbm`/signal data
/// already rides in this one response (see `cell::Cell::dbm`), so a second
/// `termux-telephony-signalstrength` call would only duplicate it — a prior
/// revision issued that second call and unconditionally discarded its
/// result, wasting a real ~3s on-device subprocess round-trip every scan for
/// nothing (`PROBLEM_TREE` T2.109).
async fn scan_cell(scan_id: &str) -> ModuleResult {
    use crate::util::termux::termux_cmd;

    match termux_cmd("termux-telephony-cellinfo", &[], 5000).await {
        Some(stdout) => cell::parse_cells(&stdout, scan_id),
        None => ModuleResult::new(),
    }
}
