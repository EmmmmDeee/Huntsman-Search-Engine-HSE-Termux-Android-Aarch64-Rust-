//! Device location sensors — WiFi connection info and GPS/network fix via Termux.
//!
//! Merges the former `wifi_connect` and `gps_fix` modules into a single
//! passive sensor pass.  Invokes `termux-wifi-connectioninfo` (3 s ceiling),
//! then a location fix: `termux-location -p gps` first (12 s), falling back to
//! `-p network` (8 s) when GPS yields no valid fix.
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
        "Device location sensors: WiFi connection info and GPS/network fix via Termux"
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

        let gps = fetch_fix("gps", 12_000, &ctx.scan_id).await;
        let fix = if gps.entities.is_empty() {
            fetch_fix("network", 8_000, &ctx.scan_id).await
        } else {
            gps
        };
        result.extend(fix.entities);

        Ok(result)
    }
}

/// Run `termux-location -p <provider> -r once`, bounded by `timeout_ms`, and
/// parse the result. Returns an empty `ModuleResult` off-device (binary
/// missing), on timeout, or on an invalid/no-fix payload.
async fn fetch_fix(provider: &str, timeout_ms: u64, scan_id: &str) -> ModuleResult {
    match termux_cmd(
        "termux-location",
        &["-p", provider, "-r", "once"],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => gps::parse_fix(&stdout, scan_id),
        None => ModuleResult::new(),
    }
}
