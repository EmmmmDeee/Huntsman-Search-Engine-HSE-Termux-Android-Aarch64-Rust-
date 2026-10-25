//! Rootless Android Wi-Fi observations via the Termux:API scan-result cache.
//! This is *not* an active scan: Android owns the scan schedule. A remembered
//! result cannot establish a device's present location or proximity.

use std::fmt::Write as _;

use serde::Serialize;

use crate::error::Error;
use crate::radar::{LoggedDevice, LoggedSweep};
use crate::rf::{RadioKind, RfSighting, RfSource, band};
use crate::textnorm::escape_controls;

/// Older OS scan results are marked stale, never silently called live.
pub const STALE_AFTER_SECS: f64 = 300.0;
pub const MAX_SCAN_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WifiObservation {
    pub sighting: RfSighting,
    /// Android's raw `ScanResult` timestamp: microseconds since device boot.
    pub os_timestamp_us: Option<u64>,
    /// Age inferred from /proc/uptime, or None when no reliable clock exists.
    pub age_secs: Option<f64>,
    pub freshness: &'static str,
    pub frequency_mhz: Option<i64>,
    pub band: Option<&'static str>,
    pub channel_bandwidth_mhz: Option<String>,
    pub capabilities: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WifiScan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitm_assessment: Option<crate::mitm_guard::Report>,
    pub source: &'static str,
    pub acquisition: &'static str,
    pub status: &'static str,
    pub observed: usize,
    pub rejected: usize,
    pub observations: Vec<WifiObservation>,
}

impl WifiScan {
    /// One sweep of this device at `ts` for the track log: this scan's fresh observations, placed
    /// at `cell`, the registered serving cell as [`crate::cell_radar::CellScan::serving_cell`]
    /// names it, or unplaced when Android withheld one. A stale observation is not what the
    /// phone hears now, so it is left out. **Pure.**
    #[must_use]
    pub fn logged_sweep(&self, ts: u64, cell: Option<String>) -> LoggedSweep {
        LoggedSweep::new(
            ts,
            cell,
            self.observations
                .iter()
                .filter(|observation| observation.freshness != "stale")
                .map(|observation| LoggedDevice {
                    mac: observation.sighting.network_id.clone(),
                    name: observation.sighting.name.clone(),
                }),
        )
    }
}

impl crate::mitm_guard::WifiEvidenceSource for WifiScan {
    fn mitm_access_points(&self, current_only: bool) -> Vec<crate::mitm_guard::AccessPoint> {
        self.observations
            .iter()
            .filter(|row| !current_only || row.freshness == "os_cached")
            .map(|row| crate::mitm_guard::AccessPoint {
                ssid: row.sighting.name.clone().unwrap_or_default(),
                bssid: row.sighting.network_id.clone(),
                security: crate::mitm_guard::Security::parse(
                    row.capabilities
                        .as_deref()
                        .or(row.sighting.encryption.as_deref())
                        .unwrap_or(""),
                ),
                frequency_mhz: row.frequency_mhz,
            })
            .collect()
    }

    fn mitm_source(&self) -> &'static str {
        self.source
    }

    fn mitm_rejected(&self) -> usize {
        self.rejected
    }

    fn mitm_eligibility(&self, unique: usize) -> Option<crate::mitm_guard::Eligibility> {
        let mut counts = crate::mitm_guard::Eligibility {
            observed_records: self.observations.len(),
            eligible_access_points: unique,
            ..Default::default()
        };
        let mut candidates = 0usize;
        for row in &self.observations {
            if row.freshness == "stale" {
                counts.excluded_stale += 1;
                continue;
            }
            if row.freshness != "os_cached" {
                counts.excluded_unknown_freshness += 1;
                continue;
            }
            let ssid = row.sighting.name.as_deref().unwrap_or("");
            if ssid.is_empty() {
                counts.excluded_missing_ssid += 1;
            } else if ssid.len() > 32 {
                counts.excluded_oversized_ssid += 1;
            } else if ssid.eq_ignore_ascii_case("(hidden)")
                || ssid.eq_ignore_ascii_case("(no SSID)")
            {
                counts.excluded_hidden_ssid += 1;
            } else if !valid_wifi_bssid(&row.sighting.network_id) {
                counts.excluded_invalid_bssid += 1;
            } else {
                candidates += 1;
            }
        }
        counts.duplicate_rows = candidates.saturating_sub(unique);
        Some(counts)
    }


fn optional_string(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// A service-set identifier must be an individual hardware address, not
/// Android's redaction sentinel, zero, or an IEEE group/broadcast address.
/// Randomised (locally administered) *individual* BSSIDs remain valid.
pub use crate::rf::valid_wifi_bssid;

/// Age Android boot-relative scan timestamps without precision-losing integer casts.
/// A timestamp beyond 136 years of uptime has no meaningful handset age.
fn age_from_boot(uptime_secs: Option<f64>, timestamp_us: Option<u64>) -> Option<f64> {
    let uptime = uptime_secs?;
    let timestamp = timestamp_us?;
    if !uptime.is_finite() || uptime < 0.0 {
        return None;
    }
    let seconds = u32::try_from(timestamp / 1_000_000).ok()?;
    let micros = u32::try_from(timestamp % 1_000_000).ok()?;
    let observed = f64::from(seconds) + f64::from(micros) / 1_000_000.0;
    let age = uptime - observed;
    (age >= 0.0 && age.is_finite()).then_some(age)
}

/// Read a capture file with no trustworthy device boot-clock provenance.
/// Android `ScanResult` timestamps are relative to the *original device boot*.
/// Comparing them to this machine's `/proc/uptime` can fabricate a fresh reading.
/// The file may also be manually created: its reported origin is unverified.
pub fn parse_replay(bytes: &[u8]) -> Result<WifiScan, Error> {
    let mut replay = parse_scan(bytes, None)?;
    replay.source = "unverified_json_file";
    replay.acquisition = "offline_replay_no_boot_provenance";
    let historical_assessment = crate::mitm_guard::from_wifi_replay(&replay, None);
    replay.mitm_assessment = Some(historical_assessment);
    Ok(replay)
}

/// Parse Android's actual Termux:API schema. Absence of results is
/// inconclusive: `getScanResults()` can return an empty cached scan.
/// Refuse `API_ERROR` and unexpected JSON rather than promoting them to zero.
pub fn parse_scan(bytes: &[u8], uptime_secs: Option<f64>) -> Result<WifiScan, Error> {
    if usize::try_from(MAX_SCAN_BYTES).is_ok_and(|limit| bytes.len() > limit) {
        return Err(Error::Invalid("Wi-Fi scan output exceeds 1 MiB".into()));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Error::Invalid(format!("invalid Termux Wi-Fi JSON: {e}")))?;
    if let Some(message) = value.get("API_ERROR").and_then(serde_json::Value::as_str) {
        return Err(Error::Invalid(format!(
            "Termux:API Wi-Fi error: {}",
            escape_controls(message)
        )));
    }
    let rows = value
        .as_array()
        .ok_or_else(|| Error::Invalid("expected a Termux Wi-Fi scan JSON array".into()))?;
    let mut observations = Vec::new();
    let mut rejected = 0;
    for row in rows {
        let Some(bssid) = row.get("bssid").and_then(serde_json::Value::as_str) else {
            rejected += 1;
            continue;
        };
        if !valid_wifi_bssid(bssid) {
            rejected += 1;
            continue;
        }
        let Some(rssi) = row.get("rssi").and_then(serde_json::Value::as_i64) else {
            rejected += 1;
            continue;
        };
        if !(-150..=0).contains(&rssi) {
            rejected += 1;
            continue;
        }

        let timestamp = row
            .get("timestamp")
            .and_then(serde_json::Value::as_u64)
            .filter(|ts| *ts > 0);
        let age_secs = age_from_boot(uptime_secs, timestamp);
        let freshness = match age_secs {
            Some(age) if age > STALE_AFTER_SECS => "stale",
            Some(_) => "os_cached",
            None => "unknown",
        };
        let frequency_mhz = row
            .get("frequency_mhz")
            .and_then(serde_json::Value::as_i64)
            .filter(|freq| (2300..=7200).contains(freq));
        let mut sighting = RfSighting::new(bssid, RadioKind::Wifi, RfSource::WifiRadar);
        sighting.name = optional_string(row.get("ssid"));
        sighting.signal_dbm = i32::try_from(rssi).ok().map(f64::from);
        sighting.encryption = optional_string(row.get("capabilities"));
        // Android's microseconds-since-boot clock is not a UTC timestamp.
        // Never invent an observed_epoch or device coordinates.
        observations.push(WifiObservation {
            sighting,
            os_timestamp_us: timestamp,
            age_secs,
            freshness,
            frequency_mhz,
            band: band(frequency_mhz),
            channel_bandwidth_mhz: optional_string(row.get("channel_bandwidth_mhz")),
            capabilities: optional_string(row.get("capabilities")),
        });
    }
    let status = if observations.is_empty() {
        "inconclusive"
    } else if observations.iter().all(|o| o.freshness == "stale") {
        "stale_only"
    } else if observations.iter().any(|o| o.freshness == "os_cached") {
        "os_cached"
    } else {
        "freshness_unknown"
    };
    let mut scan = WifiScan {
        mitm_assessment: None,
        source: "termux-wifi-scaninfo",
        acquisition: "android_cached_scan_results_not_active_scan",
        status,
        observed: observations.len(),
        rejected,
        observations,
    };
    let report = crate::mitm_guard::from_wifi_scan(&scan, None);
    scan.mitm_assessment = Some(report);
    Ok(scan)
}

#[must_use]
pub fn render(scan: &WifiScan) -> String {
    let mut text = format!(
        "source={}\tacquisition={}\tstatus={}\tobserved={}\trejected={}\n",
        scan.source, scan.acquisition, scan.status, scan.observed, scan.rejected
    );
    for row in &scan.observations {
        let age = row
            .age_secs
            .map_or_else(|| "unknown".to_owned(), |n| format!("{n:.0}"));
        let _ = writeln!(
            text,
            "wifi\tbssid={}\tssid={}\trssi_dbm={:.0}\tband={}\tage_secs={}\tfreshness={}",
            escape_controls(&row.sighting.network_id),
            escape_controls(row.sighting.name.as_deref().unwrap_or("")),
            row.sighting.signal_dbm.unwrap_or_default(),
            row.band.unwrap_or("unknown"),
            age,
            row.freshness
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cached_wifi_is_a_sighting_not_a_location() {
        let input = br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"Lab","rssi":-57,"frequency_mhz":2412,"timestamp":980000000,"channel_bandwidth_mhz":"20","capabilities":"[WPA2-PSK]"}]"#;
        let scan = parse_scan(input, Some(1000.0)).unwrap();
        assert_eq!(scan.status, "os_cached");
        assert_eq!(scan.observed, 1);
        assert_eq!(scan.observations[0].age_secs, Some(20.0));
        assert_eq!(scan.observations[0].band, Some("2.4GHz"));
        assert_eq!(
            scan.observations[0].sighting.network_id,
            "3c:5a:b4:11:22:33"
        );
        assert_eq!(scan.observations[0].sighting.signal_dbm, Some(-57.0));
        assert_eq!(scan.observations[0].sighting.observed_epoch, None);
        assert!(!scan.observations[0].sighting.has_usable_position());
    }

    #[test]
    fn old_scan_is_explicitly_stale() {
        let input = br#"[{"bssid":"3C:5A:B4:11:22:33","rssi":-75,"timestamp":100000000}]"#;
        let scan = parse_scan(input, Some(1000.0)).unwrap();
        assert_eq!(scan.status, "stale_only");
        assert_eq!(scan.observations[0].freshness, "stale");
        assert_eq!(scan.observations[0].age_secs, Some(900.0));
    }

    #[test]
    fn uptime_unavailable_or_future_timestamp_never_claims_freshness() {
        let raw = br#"[{"bssid":"3C:5A:B4:11:22:33","rssi":-60,"timestamp":1000000000}]"#;
        for uptime in [None, Some(5.0), Some(f64::NAN)] {
            let report = parse_scan(raw, uptime).unwrap();
            assert_eq!(report.status, "freshness_unknown");
            assert_eq!(report.observations[0].age_secs, None);
        }
    }

    #[test]
    fn replay_never_ages_a_foreign_boot_clock_using_the_current_device() {
        // This timestamp would be only 20 s old on a 1000-s-uptime device,
        // but no imported file can prove it was captured in that device boot.
        let raw = br#"[{"bssid":"3C:5A:B4:11:22:33","rssi":-49,"timestamp":980000000}]"#;
        let directly_captured = parse_scan(raw, Some(1000.0)).unwrap();
        assert_eq!(directly_captured.observations[0].age_secs, Some(20.0));
        assert_eq!(directly_captured.status, "os_cached");

        let imported = parse_replay(raw).unwrap();
        assert_eq!(imported.source, "unverified_json_file");
        assert_eq!(imported.acquisition, "offline_replay_no_boot_provenance");
        assert_eq!(imported.status, "freshness_unknown");
        assert_eq!(imported.observations[0].age_secs, None);
        assert_eq!(imported.observations[0].freshness, "unknown");
        assert_eq!(imported.observations[0].os_timestamp_us, Some(980_000_000));
        assert_eq!(imported.observations[0].sighting.observed_epoch, None);
        assert!(!imported.observations[0].sighting.has_usable_position());
    }

    #[test]
    fn replay_errors_and_empty_capture_do_not_prove_absence() {
        assert!(parse_replay(br#"{"API_ERROR":"permissions"}"#).is_err());
        assert!(parse_replay(br#"{"a":"not an array"}"#).is_err());
        let empty = parse_replay(b"[]").unwrap();
        assert_eq!(empty.status, "inconclusive");
        assert_eq!(empty.observed, 0);
        assert_eq!(empty.source, "unverified_json_file");
    }

    #[test]
    fn empty_cache_is_not_proof_of_no_nearby_devices() {
        let report = parse_scan(b"[]", Some(1000.0)).unwrap();
        assert_eq!(report.status, "inconclusive");
        assert_eq!(report.observed, 0);
        assert!(report.observations.is_empty());
    }

    #[test]
    fn wi_fi_bssid_rejects_placeholders_groups_and_unassigned_identities() {
        // Multicast/group MACs and Android's permission sentinel are not
        // unique individual access-point identities even if the syntax fits.
        for invalid in [
            "00:00:00:00:00:00",
            "02:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "33:33:00:00:00:01",
            "not-an-address",
        ] {
            assert!(!valid_wifi_bssid(invalid), "{invalid}");
        }
        // Locally administered randomised unicast BSSIDs are legitimate.
        for valid in [
            "3C:5A:B4:11:22:33",
            "36:32:62:36:31:33",
            "02:11:22:33:44:55",
        ] {
            assert!(valid_wifi_bssid(valid), "{valid}");
        }
    }

    #[test]
    fn invalid_identity_records_never_create_wifi_observations_or_pivots() {
        let raw = br#"[{"bssid":"02:00:00:00:00:00","rssi":-33,"timestamp":980000000},{"bssid":"01:00:5e:00:00:01","rssi":-48},{"bssid":"ff:ff:ff:ff:ff:ff","rssi":-20},{"bssid":"00:00:00:00:00:00","rssi":-10},{"bssid":"36:32:62:36:31:33","rssi":-60,"timestamp":980000000}]"#;
        let scan = parse_scan(raw, Some(1000.0)).unwrap();
        assert_eq!((scan.observed, scan.rejected), (1, 4));
        assert_eq!(scan.status, "os_cached");
        assert_eq!(
            scan.observations[0].sighting.network_id,
            "36:32:62:36:31:33"
        );
        assert_eq!(scan.observations[0].age_secs, Some(20.0));

        let only_redacted = parse_replay(br#"[{"bssid":"02:00:00:00:00:00","rssi":-35}]"#).unwrap();
        assert_eq!(only_redacted.observed, 0);
        assert_eq!(only_redacted.rejected, 1);
        assert_eq!(only_redacted.status, "inconclusive");
    }

    #[test]
    fn malformed_records_are_counted_without_corrupting_valid_results() {
        let raw = br#"[{"bssid":"not-a-mac","rssi":-30},{"bssid":"3C:5A:B4:11:22:33","rssi":-30},{"bssid":"3C:5A:B4:11:22:34","rssi":900}]"#;
        let scan = parse_scan(raw, None).unwrap();
        assert_eq!((scan.observed, scan.rejected), (1, 2));
    }

    #[test]
    fn api_errors_and_unexpected_shapes_are_not_valid_zeros() {
        for raw in [
            r#"{"API_ERROR":"Location needs to be enabled"}"#,
            r#"{"arbitrary":"object"}"#,
            r"null",
            r#""not an array""#,
        ] {
            assert!(parse_scan(raw.as_bytes(), None).is_err(), "{raw}");
        }
    }

    #[test]
    fn live_mitm_exclusions_explain_zero_without_identifier_leak() {
        let raw = br#"[{"bssid":"02:11:22:33:44:55","ssid":"PrivateLab","rssi":-50,"timestamp":100000000,"capabilities":"[WPA2-PSK]"},{"bssid":"02:11:22:33:44:56","ssid":"PrivateLab","rssi":-50},{"bssid":"02:11:22:33:44:57","ssid":"(hidden)","rssi":-50,"timestamp":980000000},{"bssid":"02:11:22:33:44:58","rssi":-50,"timestamp":980000000},{"bssid":"02:00:00:00:00:00","ssid":"rejected","rssi":-50,"timestamp":980000000}]"#;
        let scan = parse_scan(raw, Some(1000.0)).unwrap();
        let report = scan.mitm_assessment.as_ref().unwrap();
        let e = report.eligibility.as_ref().unwrap();
        assert_eq!(scan.rejected, 1);
        assert_eq!(e.observed_records, 4);
        assert_eq!(e.excluded_stale, 1);
        assert_eq!(e.excluded_unknown_freshness, 1);
        assert_eq!(e.excluded_hidden_ssid, 1);
        assert_eq!(e.excluded_missing_ssid, 1);
        assert_eq!(e.eligible_access_points, 0);
        assert_eq!(report.status, "inconclusive");
        assert_eq!(report.evaluated_access_points, 0);
        let json = serde_json::to_string(report).unwrap();
        assert!(!json.contains("PrivateLab"));
        assert!(!json.contains("02:11:22:33:44:55"));
    }

    #[test]
    fn live_mitm_duplicates_and_oversized_ssids_reconcile() {
        let raw = br#"[{"bssid":"02:11:22:33:44:55","ssid":"Lab","rssi":-50,"timestamp":980000000},{"bssid":"02:11:22:33:44:55","ssid":"Lab","rssi":-55,"timestamp":980000000},{"bssid":"02:11:22:33:44:56","ssid":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","rssi":-45,"timestamp":980000000}]"#;
        let scan = parse_scan(raw, Some(1000.0)).unwrap();
        let report = scan.mitm_assessment.as_ref().unwrap();
        let e = report.eligibility.as_ref().unwrap();
        assert_eq!(e.observed_records, 3);
        assert_eq!(e.eligible_access_points, 1);
        assert_eq!(e.duplicate_rows, 1);
        assert_eq!(e.excluded_oversized_ssid, 1);
        assert_eq!(report.evaluated_access_points, 1);
        assert_eq!(report.status, "no_specific_indicators_observed");
    }

    #[test]
    fn control_characters_do_not_inject_report_rows() {
        let raw = br#"[{"bssid":"3C:5A:B4:11:22:33","ssid":"bad\nwifi\tfake","rssi":-60}]"#;
        let report = parse_scan(raw, None).unwrap();
        let rendered = render(&report);
        assert_eq!(rendered.lines().count(), 2);
        assert!(rendered.contains(r"\n"));
        assert!(!rendered.contains("\twifi\tfake"));
    }
}
