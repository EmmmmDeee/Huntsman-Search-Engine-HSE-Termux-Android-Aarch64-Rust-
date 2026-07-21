//! Device location sensors — WiFi connection info and GPS/network fix via Termux.
//!
//! Merges the former `wifi_connect` and `gps_fix` modules into a single
//! passive sensor pass.  Invokes `termux-wifi-connectioninfo` (3 s ceiling),
//! then a location fix that degrades from a fresh lock to the phone's
//! passively-cached last-known position so a fix is established with no input:
//! `-p gps -r once` (12 s) → `-p network -r once` (8 s) → `-p gps -r last` →
//! `-p network -r last` (the last-known stages are near-instant and tagged
//! `fix-age:last-known`).
//!
//! Off-device behaviour: termux-api binary missing → no-op (no error).

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::termux::termux_cmd;

mod gps;
mod wifi;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "device_sensors";

pub struct DeviceSensors;

#[async_trait]
impl Module for DeviceSensors {
    fn name(&self) -> &'static str {
        "device_sensors"
    }

    fn description(&self) -> &'static str {
        "Device sensor recon — geolocates via WiFi connection info and GPS/network fix through Termux"
    }

    fn priority(&self) -> u8 {
        70
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates | TargetKind::MacAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Sensor
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1590.005", "T1591.001", "T1592"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Coordinates,
            EntityKind::MacAddress,
            EntityKind::IpAddress,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        if let Some(stdout) = termux_cmd("termux-wifi-connectioninfo", &[], 3000).await {
            result.extend(wifi::parse_conn(&stdout, &ctx.scan_id).entities);
        }

        result.extend(scan_location(&ctx.scan_id).await.entities);

        Ok(result)
    }
}

/// Run `termux-location -p <provider> -r <request>`, bounded by `timeout_ms`,
/// and parse the result. Returns an empty `ModuleResult` off-device (binary
/// missing), on timeout, or on an invalid/no-fix payload. A `last` request reads
/// the OS's passively-cached last-known location and the entities are tagged
/// `fix-age:last-known` so a cached position is never read as a fresh lock.
async fn fetch_fix(provider: &str, request: &str, timeout_ms: u64, scan_id: &str) -> ModuleResult {
    match termux_cmd(
        "termux-location",
        &["-p", provider, "-r", request],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => {
            let mut r = gps::parse_fix(&stdout, scan_id);
            if request == "last" {
                for e in &mut r.entities {
                    e.tag("fix-age:last-known");
                }
            }
            r
        }
        None => ModuleResult::new(),
    }
}

/// Establish a device location fix from passive on-device signals, most precise
/// first and degrading to the OS's passively-cached last-known location so a
/// position is still established when no fresh lock is available — needs no
/// input: fresh GPS → fresh network → last-known GPS → last-known network.
async fn scan_location(scan_id: &str) -> ModuleResult {
    const STAGES: &[(&str, &str, u64)] = &[
        ("gps", "once", 12_000),
        ("network", "once", 8_000),
        ("gps", "last", 3_000),
        ("network", "last", 3_000),
    ];
    for &(provider, request, timeout_ms) in STAGES {
        let r = fetch_fix(provider, request, timeout_ms, scan_id).await;
        if !r.is_empty() {
            return r;
        }
    }
    ModuleResult::new()
}
