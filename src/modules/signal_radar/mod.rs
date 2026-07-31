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

/// True when a sensor tool exited 0 but printed nothing meaningful.
///
/// [`crate::util::termux::termux_cmd`] returns `Some(stdout)` for *any*
/// zero-exit run, empty stdout included, so blank output reaches the parsers
/// as an unparseable JSON error. That is an honest "nothing to report", not a
/// malfunction, and must stay an empty `Ok` — treating it as a hard failure
/// would make a quiet sensor (a Termux:API stub that exits 0 and prints
/// nothing, common where a runtime permission is withheld) error on every
/// sweep and trip the circuit breaker.
pub(super) fn is_blank(stdout: &[u8]) -> bool {
    stdout.iter().all(u8::is_ascii_whitespace)
}

/// A sensor tool answered with output that could not be parsed — a genuine
/// malfunction, distinct from both an absent tool and an empty answer.
pub(super) fn unparseable(sensor: &str, e: &serde_json::Error) -> Error {
    Error::module(SRC, format!("{sensor}: unparseable tool output ({e})"))
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
    use crate::util::termux::termux_cmd;
    match termux_cmd("termux-wifi-scaninfo", &[], 8000).await {
        Some(stdout) => wifi::parse_scan(&stdout, scan_id),
        // Absent tool / non-zero exit: nothing observed, nothing to attest.
        None => Ok(ModuleResult::new()),
    }
}

/// Fetch and parse `termux-telephony-cellinfo`. Per-cell `dbm`/signal data
/// already rides in this one response (see `cell::Cell::dbm`), so a second
/// `termux-telephony-signalstrength` call would only duplicate it — a prior
/// revision issued that second call and unconditionally discarded its
/// result, wasting a real ~3s on-device subprocess round-trip every scan for
/// nothing (`PROBLEM_TREE` T2.109).
async fn scan_cell(scan_id: &str) -> Result<ModuleResult> {
    use crate::util::termux::termux_cmd;

    match termux_cmd("termux-telephony-cellinfo", &[], 5000).await {
        Some(stdout) => cell::parse_cells(&stdout, scan_id),
        // Absent tool / non-zero exit: nothing observed, nothing to attest.
        None => Ok(ModuleResult::new()),
    }
}
