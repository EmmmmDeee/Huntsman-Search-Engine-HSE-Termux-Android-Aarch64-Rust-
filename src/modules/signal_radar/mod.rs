//! Real-time multi-sensor signal radar — WiFi AP scan, Bluetooth scan,
//! cell tower survey, GPS fix, and LAN ARP discovery in a single parallel pass.
//!
//! All sensors run concurrently via `tokio::join!`.  Off-device (no Termux
//! binaries) every termux-backed sub-sensor no-ops cleanly.
//!
//! Two of the five are inert on the primary target, for reasons outside this
//! module's control. Both are documented at their source rather than left to be
//! rediscovered from an empty result:
//!
//!   * **LAN ARP** reads `/proc/net/arp`, which an unprivileged app cannot read
//!     on the primary target: on non-root Termux (Android 14 / SDK 34) the read
//!     returns EACCES, so LAN ARP discovery and the port sweep that depends on
//!     it are active only where that file is readable (desktop Linux, or a
//!     rooted device).  The denial degrades to a clean empty result, never an
//!     error — see `lan::scan_lan`.
//!   * **Bluetooth** has no tool to call: the official Termux:API ships no
//!     Bluetooth command at all, and the only implementation is a third-party
//!     fork emitting device names without addresses — see
//!     [`bluetooth`] for the verified evidence.
//!
//! So on a stock non-root Termux device this module is effectively a Wi-Fi,
//! cell and GPS radar. That is stated plainly because the alternative is an
//! operator reading three silent sensors as "nothing in range".
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
    entity::{EntityKind, Evidence},
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

/// Attribute `mac`'s vendor and device class onto `e`, and record the same on
/// `ev`, returning the extended evidence.
///
/// Both RF sensors in this module observe hardware addresses and both must say
/// the same thing about them, so this is written once. It was previously
/// copy-pasted verbatim into `wifi::parse_scan` and `bluetooth::parse_bt_json`
/// — the shape of duplication that drifts, and two more near-copies in
/// `wigle` have ALREADY drifted (they emit `vendor:`/`device:` but never the
/// `trackable`/`randomized` partition, so a WiGLE-sourced randomised address is
/// not marked as one).
///
/// The `trackable`/`randomized` split is the load-bearing part. A
/// locally-administered address is a rotating privacy identifier, not a
/// followable device, and AU-122 partitions on exactly this: plotting one as a
/// persistent pin invents a device that does not exist.
///
/// Callers must have already established that `mac` IS an address
/// ([`crate::util::oui::is_mac_address`]) and not a placeholder
/// ([`crate::util::oui::is_placeholder_bssid`]) — [`crate::util::oui::classify_mac`]
/// reads a hex PREFIX and cannot make that judgement itself.
pub(super) fn tag_oui(e: &mut crate::core::entity::Entity, ev: Evidence, mac: &str) -> Evidence {
    let Some(oui) = crate::util::oui::classify_mac(mac) else {
        return ev;
    };
    e.tag(format!("vendor:{}", oui.vendor));
    e.tag(format!("device:{}", oui.class.as_str()));
    let trackable = crate::util::oui::is_locally_administered(mac) == Some(false);
    e.tag(if trackable { "trackable" } else { "randomized" });
    ev.with_attr("vendor", oui.vendor)
        .with_attr("device_class", oui.class.as_str())
        .with_attr("trackable", trackable.to_string())
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

        // Run all five sensors in parallel — each spawns its own independent
        // `termux-*` subprocess against a DIFFERENT Android API (WifiManager,
        // BluetoothAdapter, TelephonyManager, LocationManager, /proc/net/arp),
        // so there is no shared resource to serialise on. `cell` previously
        // ran sequentially AFTER this join, contradicting this very doc
        // comment's "All sensors run concurrently" claim and adding its own
        // multi-second on-device subprocess round-trip on top of the other
        // four's worst case instead of overlapping it — real wall-clock (and
        // battery) cost on the primary Termux/Android target for a module
        // whose whole purpose is a fast real-time sweep.
        let (wifi_out, bt_out, gps_out, lan_out, cell_out) = tokio::join!(
            scan_wifi(scan_id),
            bluetooth::scan_bluetooth(scan_id),
            gps::scan_gps(scan_id),
            lan::scan_lan(scan_id),
            scan_cell(scan_id),
        );

        combine_sensors([wifi_out, bt_out, gps_out, Ok(lan_out), cell_out])
    }
}

/// Fold the five independent sensors into `process()`'s return value.
///
/// Sensors are independent observations of different things, so a failure in
/// one must never discard another's evidence: everything collected is kept,
/// and a failure is surfaced only when *nothing at all* was observed. That is
/// exactly [`ModuleResult::or_hard_failure`]'s contract, shared with
/// `ip_reputation` (T2.111) and `niamonx` (T2.114).
///
/// The distinction this preserves: before, a malfunctioning sensor returned an
/// empty result, so "termux-api is broken" and "no devices in range" were the
/// same answer. Now a total sensor failure reaches the engine as a real
/// `ModuleError` — visible to the operator, counted in `modules_errored`, and
/// fed to the circuit breaker and health streak.
fn combine_sensors(outcomes: [Result<ModuleResult>; 5]) -> Result<ModuleResult> {
    let mut combined = ModuleResult::new();
    let mut first_failure = None;
    for outcome in outcomes {
        match outcome {
            Ok(r) => combined.extend(r.entities),
            Err(e) => {
                tracing::warn!(module = SRC, error = %e, "signal_radar: sensor failed");
                first_failure.get_or_insert(e);
            }
        }
    }
    combined.or_hard_failure(first_failure)
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
