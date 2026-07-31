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
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::termux::termux_cmd;

mod gps;
mod wifi;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "device_sensors";

/// True when a sensor tool exited 0 but printed nothing meaningful.
///
/// [`crate::util::termux::termux_cmd`] returns `Some(stdout)` for *any*
/// zero-exit run, empty stdout included, so blank output reaches the parsers
/// as an unparseable JSON error. That is an honest "nothing to report", not a
/// malfunction, and must stay an empty `Ok` — treating it as a hard failure
/// would make a quiet sensor error on every scan and trip the circuit breaker.
/// Mirrors `signal_radar::is_blank`, which shares these tools.
pub(super) fn is_blank(stdout: &[u8]) -> bool {
    stdout.iter().all(u8::is_ascii_whitespace)
}

/// A sensor tool answered with output that could not be parsed — a genuine
/// malfunction, distinct from both an absent tool and an empty answer.
pub(super) fn unparseable(sensor: &str, e: &serde_json::Error) -> Error {
    Error::module(SRC, format!("{sensor}: unparseable tool output ({e})"))
}

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
        // The two sensors are independent observations of different things, so
        // a failure in one must never discard the other's evidence: everything
        // collected is kept, and a failure surfaces only when nothing at all
        // was observed. Same `or_hard_failure` contract as `signal_radar`.
        let wifi_out = match termux_cmd("termux-wifi-connectioninfo", &[], 3000).await {
            Some(stdout) => wifi::parse_conn(&stdout, &ctx.scan_id),
            // Absent tool / non-zero exit: nothing observed, nothing to attest.
            None => Ok(ModuleResult::new()),
        };
        let loc_out = scan_location(&ctx.scan_id).await;

        let mut result = ModuleResult::new();
        let mut first_failure = None;
        for outcome in [wifi_out, loc_out] {
            match outcome {
                Ok(r) => result.extend(r.entities),
                Err(e) => {
                    tracing::warn!(module = SRC, error = %e, "device_sensors: sensor failed");
                    first_failure.get_or_insert(e);
                }
            }
        }
        result.or_hard_failure(first_failure)
    }
}

/// Run `termux-location -p <provider> -r <request>`, bounded by `timeout_ms`,
/// and parse the result. Returns an empty `ModuleResult` off-device (binary
/// missing), on timeout, or on an invalid/no-fix payload. A `last` request reads
/// the OS's passively-cached last-known location and the entities are tagged
/// `fix-age:last-known` so a cached position is never read as a fresh lock.
async fn fetch_fix(
    provider: &str,
    request: &str,
    timeout_ms: u64,
    scan_id: &str,
) -> Result<ModuleResult> {
    match termux_cmd(
        "termux-location",
        &["-p", provider, "-r", request],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => {
            let mut r = gps::parse_fix(&stdout, scan_id)?;
            if request == "last" {
                for e in &mut r.entities {
                    e.tag("fix-age:last-known");
                }
            }
            Ok(r)
        }
        None => Ok(ModuleResult::new()),
    }
}

/// Establish a device location fix from passive on-device signals, most precise
/// first and degrading to the OS's passively-cached last-known location so a
/// position is still established when no fresh lock is available — needs no
/// input: fresh GPS → fresh network → last-known GPS → last-known network.
async fn scan_location(scan_id: &str) -> Result<ModuleResult> {
    const STAGES: &[(&str, &str, u64)] = &[
        ("gps", "once", 12_000),
        ("network", "once", 8_000),
        ("gps", "last", 3_000),
        ("network", "last", 3_000),
    ];
    // Each stage is an independent attempt at the same question, so a stage
    // that malfunctions must not abort the ladder — a later stage may still
    // establish a fix. The first failure is remembered and only surfaces if
    // no stage produced one.
    let mut first_failure = None;
    for &(provider, request, timeout_ms) in STAGES {
        match fetch_fix(provider, request, timeout_ms, scan_id).await {
            Ok(r) if !r.is_empty() => return Ok(r),
            Ok(_) => {}
            Err(e) => {
                first_failure.get_or_insert(e);
            }
        }
    }
    ModuleResult::new().or_hard_failure(first_failure)
}
