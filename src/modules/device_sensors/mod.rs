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

mod wifi;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "device_sensors";

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
        let wifi_out =
            crate::modules::termux_sensor::read_and_parse(Sensor::WifiConnection, |stdout| {
                wifi::parse_conn(stdout, &ctx.scan_id)
            })
            .await;
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

/// Establish a device location fix from passive on-device signals — the shared
/// ladder in [`crate::modules::device_fix::scan_location_ladder`], bound to this
/// module's evidence-source tag. The stages, their budgets and the
/// last-known-fix fallback semantics live there, single-sourced with
/// `signal_radar`, which ran a byte-identical copy.
async fn scan_location(scan_id: &str) -> Result<ModuleResult> {
    crate::modules::device_fix::scan_location_ladder(scan_id, SRC).await
}
