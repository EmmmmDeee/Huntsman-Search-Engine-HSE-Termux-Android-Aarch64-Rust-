//! GPS / network location fix for signal_radar — the source-tag binding around
//! the canonical ladder and parse in [`crate::modules::device_fix`], shared with
//! `device_sensors`. The stages, their budgets and the last-known-fix fallback
//! semantics live there, not here.

use crate::core::{error::Result, module::ModuleResult};
use crate::modules::device_fix;

use super::SRC;

/// Establish a device location fix from passive on-device signals — the shared
/// ladder in [`crate::modules::device_fix::scan_location_ladder`], bound to this
/// module's evidence-source tag. The stages, their budgets and the
/// last-known-fix fallback semantics live there, single-sourced with
/// `device_sensors`, which ran a byte-identical copy.
pub(super) async fn scan_gps(scan_id: &str) -> Result<ModuleResult> {
    device_fix::scan_location_ladder(scan_id, SRC).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This module's binding of the canonical
    /// [`crate::modules::device_fix::parse_fix`] — the shared parse-to-entity
    /// mapping for `termux-location` output, differing only in the evidence-source
    /// tag.
    ///
    /// Test-only since the surrounding ladder moved to
    /// [`crate::modules::device_fix::scan_location_ladder`]: production now reaches
    /// the shared parse through that, and this binding survives solely so this
    /// module's parse tests keep exercising it under this module's own `SRC`.
    #[cfg(test)]
    fn parse_fix(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
        device_fix::parse_fix(stdout, scan_id, SRC)
    }
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
