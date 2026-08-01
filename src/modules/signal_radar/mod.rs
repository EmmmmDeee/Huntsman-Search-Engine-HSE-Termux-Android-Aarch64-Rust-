//! Real-time multi-sensor signal radar — WiFi AP scan, Bluetooth scan,
//! cell tower survey, GPS fix, and LAN ARP discovery in a single parallel pass.
//!
//! All sensors run concurrently via `tokio::join!`.  Off-device (no Termux
//! binaries) every termux-backed sub-sensor no-ops cleanly.  The LAN ARP
//! sensor reads `/proc/net/arp`, which an unprivileged app cannot read on the
//! primary target: on non-root Termux (Android 14 / SDK 34) the read returns
//! EACCES, so LAN ARP discovery and the port sweep that depends on it are
//! inert on-device and active only where that file is readable (desktop
//! Linux, or a rooted device).  The denial degrades to a clean empty result,
//! never an error — see `lan::scan_lan`.
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
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

pub(super) const SRC: &str = "signal_radar";

// The blank-vs-unparseable contract is single-sourced in
// `crate::modules::termux_sensor`; re-exported here so this module's sensor
// submodules keep calling `super::is_blank` / `super::unparseable`.
pub(super) use crate::modules::termux_sensor::{Sensor, is_blank};

/// [`crate::modules::termux_sensor::unparseable_for`] bound to this module's
/// `SRC`. Takes the [`Sensor`] rather than a label string, so an error can only
/// name a tool this module actually reads.
pub(super) fn unparseable(sensor: Sensor, e: &serde_json::Error) -> Error {
    crate::modules::termux_sensor::unparseable_for(SRC, sensor, e)
}

pub struct SignalRadar;

#[async_trait]
impl Module for SignalRadar {
    fn name(&self) -> &'static str {
        "signal_radar"
    }

    fn description(&self) -> &'static str {
        "Real-time multi-sensor signal radar — sweeps WiFi AP, Bluetooth, cell towers, GPS, and LAN ARP discovery"
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
            EntityKind::Ssid,
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

        // Sensors are independent observations of different things, so a
        // failure in one must never discard another's evidence: everything
        // collected is kept, and a failure is surfaced only when *nothing at
        // all* was observed. Before this contract, a malfunctioning sensor
        // returned an empty result, so "termux-api is broken" and "no devices
        // in range" were the same answer; now a total sensor failure reaches
        // the engine as a real `ModuleError`. Shared with `device_sensors` via
        // [`ModuleResult::collect_sensors`].
        ModuleResult::collect_sensors(SRC, [wifi_out, bt_out, gps_out, Ok(lan_out), cell_out])
    }
}

/// Fetch and parse `termux-wifi-scaninfo`.
async fn scan_wifi(scan_id: &str) -> Result<ModuleResult> {
    crate::modules::termux_sensor::read_and_parse(Sensor::WifiScan, |stdout| {
        wifi::parse_scan(stdout, scan_id)
    })
    .await
}

/// Fetch and parse `termux-telephony-cellinfo`. Per-cell `dbm`/signal data
/// already rides in this one response (see `cell::Cell::dbm`), so a second
/// `termux-telephony-signalstrength` call would only duplicate it — a prior
/// revision issued that second call and unconditionally discarded its
/// result, wasting a real ~3s on-device subprocess round-trip every scan for
/// nothing (`PROBLEM_TREE` T2.109).
async fn scan_cell(scan_id: &str) -> Result<ModuleResult> {
    crate::modules::termux_sensor::read_and_parse(Sensor::CellInfo, |stdout| {
        cell::parse_cells(stdout, scan_id)
    })
    .await
}
