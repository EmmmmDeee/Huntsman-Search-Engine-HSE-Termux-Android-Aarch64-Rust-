//! GPS / network location fix for signal_radar — the sensor shell around the
//! canonical parse in `crate::modules::device_fix`, shared with `device_sensors`.

use crate::core::{error::Result, module::ModuleResult};
use crate::modules::device_fix;
use crate::util::termux::termux_cmd;

use super::SRC;

/// This module's binding of the canonical
/// [`crate::modules::device_fix::parse_fix`] — the shared parse-to-entity
/// mapping for `termux-location` output, differing only in the evidence-source
/// tag. Kept as a wrapper so this module's tests exercise it by its local name.
fn parse_fix(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    device_fix::parse_fix(stdout, scan_id, SRC)
}

/// Fetch a location fix from `termux-location -p <provider> -r <request>`.
/// A `last` request reads the OS's passively-cached last-known location (no
/// fresh lock, near-instant); those entities are tagged `fix-age:last-known` so
/// a cached position is never mistaken for a fresh sensor lock.
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
            let mut r = parse_fix(&stdout, scan_id)?;
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
/// position is STILL established when no fresh lock is available this sweep —
/// the radar never depends on a single clean GPS fix, and needs no input. The
/// stages, in order: a fresh GPS lock (12 s), a fresh network (cell/Wi-Fi) fix
/// (8 s), the last-known GPS fix, then the last-known network fix (both
/// near-instant, read straight from the phone's location cache). Every stage
/// reads only the phone's own sensors/cache — no seed, no input.
pub(super) async fn scan_gps(scan_id: &str) -> Result<ModuleResult> {
    const STAGES: &[(&str, &str, u64)] = &[
        ("gps", "once", 12_000),
        ("network", "once", 8_000),
        ("gps", "last", 3_000),
        ("network", "last", 3_000),
    ];
    // Each stage is an independent attempt at the same question, so a stage
    // that malfunctions must not abort the ladder — a later stage may still
    // establish a fix. The first failure is remembered and only surfaces if
    // no stage produced one, via `or_hard_failure`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    // The `Fix` shape and the `is_valid_fix` / `fix_confidence` ladder now live
    // in `crate::modules::device_fix` and are tested there; these tests cover
    // this module's own `parse_fix` wrapper.

    #[test]
    fn parse_fix_valid_gps_json_emits_coordinates_entity() {
        let json = br#"{"latitude":-27.4705,"longitude":153.0260,"altitude":10.0,"accuracy":5.0,"speed":0.0,"bearing":0.0,"provider":"gps"}"#;
        let result = parse_fix(json, "test-scan").expect("valid fix JSON parses");
        assert_eq!(result.len(), 1);
        let e = &result.entities[0];
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("geoint"));
        assert!(e.has_tag("device-sensor"));
        assert!(e.has_tag("provider:gps"));
        assert!(e.has_tag("accuracy:5m"));
    }

    #[test]
    fn parse_fix_null_island_returns_empty() {
        let json = br#"{"latitude":0.0,"longitude":0.0,"provider":"gps"}"#;
        // An out-of-range fix is a real answer that locates nothing — an
        // honest empty Ok, not a malfunction.
        assert!(
            parse_fix(json, "test-scan")
                .expect("null island is a clean answer, not an error")
                .is_empty()
        );
    }

    /// Unparseable output means the tool answered with something broken. That
    /// is a malfunction and must surface as an error — reporting it as an empty
    /// result would be indistinguishable from "no fix available".
    #[test]
    fn parse_fix_malformed_json_is_an_error() {
        assert!(parse_fix(b"not valid json", "test-scan").is_err());
    }

    /// Blank output is the other half of that contract: a tool that exits 0 and
    /// prints nothing has answered "nothing to report", which is an empty Ok.
    #[test]
    fn parse_fix_blank_output_is_an_empty_ok() {
        for blank in [&b""[..], b"   ", b"\n\t "] {
            assert!(
                parse_fix(blank, "test-scan")
                    .expect("blank output is an empty answer, not an error")
                    .is_empty()
            );
        }
    }

    #[test]
    fn parse_fix_absent_provider_defaults_to_network_tag() {
        let json = br#"{"latitude":51.5074,"longitude":-0.1278}"#;
        let result = parse_fix(json, "test-scan").expect("valid fix JSON parses");
        assert_eq!(result.len(), 1);
        assert!(result.entities[0].has_tag("provider:network"));
    }
}
