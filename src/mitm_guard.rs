//! Evidence-gated, advisory MITM/evil-twin Wi-Fi assessment for rootless Android.
//! Only scans and operator-supplied baselines are used; no packet injection,
//! deauthentication, raw monitor mode, forced disconnect, or credential collection.
//! Research basis: arxiv.org/abs/1903.05843 (evil-twin fingerprints),
//! 2203.00579 (multi-channel MITM review), 2302.00338 (802.1X certificates),
//! 2110.04259 (WPA3 IDS), 2512.10470 (rogue AP NIDS blind spots), and
//! 2601.22770 (Android TLS validation).
//! Research methods need additional sensors; no paper classifier is reproduced.
//! A scan cannot establish interception: all output is explicitly unconfirmed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::rf::valid_wifi_bssid;

pub const MAX_IMPORT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_BASELINE_BYTES: u64 = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Security {
    Unknown,
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
}

impl Security {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let u = text.to_ascii_uppercase();
        // Classify the weakest advertised mode: transition-mode SAE/PSK
        // can still accept WPA2 and mixed WPA/WPA2 can accept legacy WPA.
        // RSN-PSK is WPA2, not WPA1. Preserve Unknown for absent metadata.
        if u.contains("WEP") {
            Self::Wep
        } else if u.contains("[WPA-") || u.contains("WPA1") {
            Self::Wpa
        } else if u.contains("WPA2") || (u.contains("RSN") && u.contains("PSK")) {
            Self::Wpa2
        } else if u.contains("WPA3") || u.contains("SAE") {
            Self::Wpa3
        } else if u.contains("RSN") {
            Self::Wpa2
        } else if u.contains("WPA") {
            Self::Wpa
        } else if u.trim() == "OPEN"
            || (u.contains("[ESS]")
                && !u.contains("PSK")
                && !u.contains("RSN")
                && !u.contains("SAE"))
        {
            Self::Open
        } else {
            // WiGLE's "Unknown", a missing capability field, and a hidden SSID
            // do NOT imply an open/unprotected network.
            Self::Unknown
        }
    }

    fn ordinal(self) -> Option<u8> {
        match self {
            Self::Unknown => None,
            Self::Open => Some(0),
            Self::Wep => Some(1),
            Self::Wpa => Some(2),
            Self::Wpa2 => Some(3),
            Self::Wpa3 => Some(4),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub security: Security,
    pub frequency_mhz: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Baseline {
    pub networks: Vec<TrustedNetwork>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustedNetwork {
    pub ssid: String,
    pub bssids: Vec<String>,
    pub minimum_security: String,
}

/// An operator-maintained baseline must never be silently learned from an
/// untrusted capture. A poisoned baseline could suppress real warnings.
pub fn parse_baseline(bytes: &[u8]) -> Result<Baseline, String> {
    if usize::try_from(MAX_BASELINE_BYTES).is_ok_and(|limit| bytes.len() > limit) {
        return Err("baseline exceeds 128 KiB".into());
    }
    let baseline: Baseline =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid baseline JSON: {e}"))?;
    if baseline.networks.len() > 512 {
        return Err("baseline contains too many SSIDs".into());
    }
    let mut ssids = BTreeSet::new();
    for n in &baseline.networks {
        if n.ssid.is_empty() || n.ssid.len() > 32 || !ssids.insert(n.ssid.as_str()) {
            return Err("baseline SSIDs must be unique and 1..32 bytes".into());
        }
        if n.bssids.is_empty()
            || n.bssids.len() > 256
            || n.bssids.iter().any(|s| !valid_wifi_bssid(s))
        {
            return Err("baseline requires 1..256 valid individual BSSIDs per SSID".into());
        }
        if !matches!(
            n.minimum_security.trim().to_ascii_uppercase().as_str(),
            "OPEN" | "WEP" | "WPA" | "WPA2" | "WPA3"
        ) {
            return Err("baseline minimum_security must be OPEN, WEP, WPA, WPA2, or WPA3".into());
        }
    }
    Ok(baseline)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Heuristic classification, never a confirmed attack.
    pub code: &'static str,
    pub severity: &'static str,
    pub ssid: String,
    pub bssid: Option<String>,
    pub evidence: String,
    pub resolution: &'static str,
}

/// Aggregate eligibility for one live Wi-Fi capture; never includes identifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Eligibility {
    pub observed_records: usize,
    pub excluded_stale: usize,
    pub excluded_unknown_freshness: usize,
    pub excluded_missing_ssid: usize,
    pub excluded_oversized_ssid: usize,
    pub excluded_hidden_ssid: usize,
    pub excluded_invalid_bssid: usize,
    pub duplicate_rows: usize,
    pub eligible_access_points: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub source: &'static str,
    pub status: &'static str,
    pub evaluated_access_points: usize,
    pub rejected_records: usize,
    pub trusted_baseline_supplied: bool,
    pub mitm_confirmed: bool,
    pub findings: Vec<Finding>,
    pub capability_limit: &'static str,
    /// Live sensor counts; omitted for unverified historical captures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligibility: Option<Eligibility>,
}

/// Shared SSID assessment policy. Length is measured in UTF-8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SsidExclusion {
    Missing,
    Oversized,
    Hidden,
}

#[must_use]
pub(crate) fn ssid_exclusion(ssid: &str) -> Option<SsidExclusion> {
    if ssid.is_empty() {
        Some(SsidExclusion::Missing)
    } else if ssid.len() > 32 {
        Some(SsidExclusion::Oversized)
    } else if ssid.eq_ignore_ascii_case("(hidden)") || ssid.eq_ignore_ascii_case("(no SSID)") {
        Some(SsidExclusion::Hidden)
    } else {
        None
    }
}

fn assess_status(accepted: usize, findings: &[Finding]) -> &'static str {
    if accepted == 0 {
        "inconclusive"
    } else if findings.is_empty() {
        "no_specific_indicators_observed"
    } else {
        "unconfirmed_indicators"
    }
}

/// Group validated observations by byte-exact SSID and canonical BSSID.
fn grouped_access_points(
    observations: &[AccessPoint],
) -> BTreeMap<&str, BTreeMap<String, BTreeSet<Security>>> {
    // SSIDs are byte-exact, but BSSIDs are hexadecimal, case-insensitive identifiers.
    // Canonicalise once at this shared boundary even for direct library callers.
    let mut by_ssid: BTreeMap<&str, BTreeMap<String, BTreeSet<Security>>> = BTreeMap::new();
    for ap in observations {
        if ssid_exclusion(&ap.ssid).is_some() || !valid_wifi_bssid(&ap.bssid) {
            continue;
        }
        let modes = by_ssid
            .entry(&ap.ssid)
            .or_default()
            .entry(ap.bssid.to_ascii_lowercase())
            .or_default();
        // Unknown capabilities do not contradict a known mode; two distinct
        // known modes do. Preserve both, regardless of observation ordering.
        if ap.security != Security::Unknown {
            modes.insert(ap.security);
        }
    }
    by_ssid
}

/// Based on MITM/evil-twin literature, but these are conservative heuristics,
/// NOT reproduced ML classifiers or validated sensitivities from the papers.
#[must_use]
pub fn assess(
    observations: &[AccessPoint],
    baseline: Option<&Baseline>,
    source: &'static str,
    rejected: usize,
) -> Report {
    let by_ssid = grouped_access_points(observations);
    let accepted = by_ssid.values().map(BTreeMap::len).sum::<usize>();
    let mut findings = Vec::new();
    let trusted: BTreeMap<&str, &TrustedNetwork> = baseline
        .map(|b| b.networks.iter().map(|n| (n.ssid.as_str(), n)).collect())
        .unwrap_or_default();

    for (ssid, aps) in &by_ssid {
        for (bssid, modes) in aps {
            if modes.len() > 1 {
                findings.push(Finding {
                    code: "bssid_security_conflict_unverified",
                    severity: "review",
                    ssid: (*ssid).to_owned(),
                    bssid: Some(bssid.clone()),
                    evidence: "Records for the same SSID/BSSID advertise conflicting security modes; record order does not establish the current mode.".into(),
                    resolution: "Verify current security with the network administrator and repeat a fresh capture before drawing conclusions.",
                });
            }
        }
        if let Some(policy) = trusted.get(ssid) {
            let minimum = Security::parse(&policy.minimum_security).ordinal();
            for (bssid, modes) in aps {
                // A contradictory capture cannot establish a downgrade.
                if modes.len() > 1 {
                    continue;
                }
                let security = modes.iter().next().copied().unwrap_or(Security::Unknown);
                let enrolled = policy.bssids.iter().any(|b| b.eq_ignore_ascii_case(bssid));
                let downgrade = minimum
                    .zip(security.ordinal())
                    .is_some_and(|(min, current)| current < min);
                if security == Security::Unknown {
                    findings.push(Finding {
                        code: "trusted_ssid_security_unverified",
                        severity: "review",
                        ssid: (*ssid).to_owned(),
                        bssid: Some(bssid.clone()),
                        evidence: "Observed security capabilities are unavailable; this does not prove a downgrade or confirm baseline compliance.".into(),
                        resolution: "Verify the selected network's security and certificate configuration in Android settings or with the network administrator.",
                    });
                } else if downgrade {
                    findings.push(Finding {
                        code: "security_below_trusted_floor",
                        severity: "high",
                        ssid: (*ssid).to_owned(),
                        bssid: Some(bssid.clone()),
                        evidence: format!(
                            "Observed {:?} below operator baseline {} (authorised BSSID: {}). Baseline authenticity must be independently verified.",
                            security, policy.minimum_security, enrolled
                        ),
                        resolution: "Do not authenticate via this access point. Manually leave/forget the network and verify the BSSID, WPA mode and enterprise certificate with its administrator.",
                    });
                } else if !enrolled {
                    findings.push(Finding {
                        code: "bssid_not_on_operator_allowlist",
                        severity: "review",
                        ssid: (*ssid).to_owned(),
                        bssid: Some(bssid.clone()),
                        evidence: "SSID appears in the operator baseline but this BSSID is not authorised there; mesh expansion or equipment replacement is also possible.".into(),
                        resolution: "Verify the network inventory with its administrator before trusting or updating the allowlist.",
                    });
                }
            }
        } else {
            // Contradictory rows from one BSSID do not establish variation
            // between different physical BSSIDs.
            let modes: BTreeSet<_> = aps
                .values()
                .filter(|known| known.len() == 1)
                .flat_map(|known| known.iter().filter_map(|mode| mode.ordinal()))
                .collect();
            if modes.len() > 1 {
                findings.push(Finding {
                    code: "unverified_ssid_security_variation",
                    severity: "review",
                    ssid: (*ssid).to_owned(),
                    bssid: None,
                    evidence: format!(
                        "{} distinct BSSIDs advertise different security classifications, without a verified infrastructure baseline; WPA2/WPA3 transitional deployments are common.",
                        aps.len()
                    ),
                    resolution: "Check the legitimate operator's BSSID inventory and configured security; never classify an evil twin from this difference alone.",
                });
            }
        }
    }

    // Deterministic ordering makes reports diffable and reproducible.
    findings.sort_by(|a, b| {
        (a.ssid.as_str(), a.code, a.bssid.as_deref()).cmp(&(
            b.ssid.as_str(),
            b.code,
            b.bssid.as_deref(),
        ))
    });
    let status = assess_status(accepted, &findings);
    Report {
        source,
        status,
        evaluated_access_points: accepted,
        rejected_records: rejected,
        trusted_baseline_supplied: baseline.is_some(),
        mitm_confirmed: false,
        findings,
        capability_limit: "Passive scan heuristics cannot prove interception, validate AP ownership, read 802.11 management frames, observe ARP/TLS tampering, or forcibly disconnect Wi-Fi on unprivileged Android.",
        eligibility: None,
    }
}

/// Adapter contract for Wi-Fi observations. The assessment engine never
/// imports the radar parser, preventing an RF module dependency cycle.
pub trait WifiEvidenceSource {
    /// Convert only appropriately fresh observations for a current assessment.
    fn mitm_access_points(&self, current_only: bool) -> Vec<AccessPoint>;
    fn mitm_source(&self) -> &'static str;
    fn mitm_rejected(&self) -> usize;

    /// Only rootless live Wi-Fi captures supply exclusion counts.
    fn mitm_eligibility(&self, _unique_access_points: usize) -> Option<Eligibility> {
        None
    }
}

/// A replay lacking a trusted boot clock must never establish current proximity.
#[must_use]
pub fn from_wifi_scan(scan: &impl WifiEvidenceSource, baseline: Option<&Baseline>) -> Report {
    let observations = scan.mitm_access_points(true);
    let mut report = assess(
        &observations,
        baseline,
        scan.mitm_source(),
        scan.mitm_rejected(),
    );
    report.eligibility = scan.mitm_eligibility(report.evaluated_access_points);
    report
}

/// Historical captures can be assessed but cannot prove a live attack.
#[must_use]
pub fn from_wifi_replay(scan: &impl WifiEvidenceSource, baseline: Option<&Baseline>) -> Report {
    let observations = scan.mitm_access_points(false);
    let mut report = assess(
        &observations,
        baseline,
        "termux_wifi_replay_unverified",
        scan.mitm_rejected(),
    );
    if report.status == "unconfirmed_indicators" {
        report.status = "historical_unconfirmed_indicators";
    }
    report
}

/// Reads the normalized `WiGLE` JSONL export without treating Bluetooth/cell
/// records as Wi-Fi. Bounded input is enforced here and again at the CLI.
pub fn from_wigle_jsonl(bytes: &[u8], baseline: Option<&Baseline>) -> Result<Report, String> {
    if usize::try_from(MAX_IMPORT_BYTES).is_ok_and(|limit| bytes.len() > limit) {
        return Err("WiGLE JSONL exceeds 8 MiB".into());
    }
    let content = std::str::from_utf8(bytes).map_err(|_| "WiGLE JSONL must be UTF-8")?;
    let mut observations = Vec::new();
    let mut rejected = 0usize;
    for (index, line) in content.lines().enumerate() {
        if index >= 65_536 {
            return Err("WiGLE JSONL exceeds 65536 lines".into());
        }
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > 16_384 {
            return Err(format!("WiGLE JSONL record {} exceeds 16 KiB", index + 1));
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("WiGLE JSONL line {}: {e}", index + 1))?;
        if value.get("type").and_then(serde_json::Value::as_str) != Some("WIFI") {
            continue;
        }
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let bssid = value
            .get("network_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if name.len() > 32 || !valid_wifi_bssid(bssid) {
            rejected += 1;
            continue;
        }
        observations.push(AccessPoint {
            ssid: name.to_owned(),
            bssid: bssid.to_ascii_lowercase(),
            security: Security::parse(
                value
                    .get("encryption")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
            ),
            frequency_mhz: value
                .get("frequency_mhz")
                .and_then(serde_json::Value::as_i64),
        });
    }
    Ok(assess(
        &observations,
        baseline,
        "wigle_jsonl_unverified",
        rejected,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(ssid: &str, bssid: &str, security: Security) -> AccessPoint {
        AccessPoint {
            ssid: ssid.into(),
            bssid: bssid.into(),
            security,
            frequency_mhz: Some(2412),
        }
    }

    #[test]
    fn mixed_security_is_review_not_proof() {
        let r = assess(
            &[
                ap("LabNet", "02:11:22:33:44:55", Security::Wpa2),
                ap("LabNet", "02:22:33:44:55:66", Security::Wpa3),
            ],
            None,
            "fixture",
            0,
        );
        assert!(!r.mitm_confirmed);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].code, "unverified_ssid_security_variation");
        assert_eq!(r.findings[0].severity, "review");
    }

    #[test]
    fn direct_assessment_canonicalises_bssid_identity_and_findings() {
        let baseline = parse_baseline(
            br#"{"networks":[{"ssid":"Office","bssids":["3C:5A:B4:11:22:33"],"minimum_security":"WPA2"}]}"#,
        )
        .unwrap();
        let lower = ap("Office", "3c:5a:b4:11:22:33", Security::Wpa2);
        let upper = ap("Office", "3C:5A:B4:11:22:33", Security::Wpa2);

        for candidates in [
            [lower.clone(), upper.clone()],
            [upper.clone(), lower.clone()],
        ] {
            let report = assess(&candidates, Some(&baseline), "fixture", 0);
            assert_eq!(report.evaluated_access_points, 1);
            assert_eq!(report.status, "no_specific_indicators_observed");
            assert!(report.findings.is_empty());
            assert!(!report.mitm_confirmed);
        }

        let downgraded = assess(
            &[ap("Office", "3C:5A:B4:11:22:33", Security::Wpa)],
            Some(&baseline),
            "fixture",
            0,
        );
        assert_eq!(downgraded.evaluated_access_points, 1);
        assert_eq!(downgraded.findings[0].code, "security_below_trusted_floor");
        assert_eq!(
            downgraded.findings[0].bssid.as_deref(),
            Some("3c:5a:b4:11:22:33")
        );
    }

    #[test]
    fn conflicting_bssid_modes_are_order_independent_and_review_only() {
        let baseline = parse_baseline(
            br#"{"networks":[{"ssid":"Office","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#,
        )
        .unwrap();
        let low = ap("Office", "3C:5A:B4:11:22:33", Security::Wpa);
        let high = ap("Office", "3c:5a:b4:11:22:33", Security::Wpa3);
        let unknown = ap("Office", "3c:5a:b4:11:22:33", Security::Unknown);
        let first = assess(
            &[low.clone(), high.clone(), unknown.clone()],
            Some(&baseline),
            "fixture",
            0,
        );
        let last = assess(&[unknown, high, low], Some(&baseline), "fixture", 0);
        assert_eq!(first, last);
        assert_eq!(first.evaluated_access_points, 1);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].code, "bssid_security_conflict_unverified");
        assert_eq!(first.findings[0].severity, "review");
        assert_eq!(
            first.findings[0].bssid.as_deref(),
            Some("3c:5a:b4:11:22:33")
        );
        assert!(!first.mitm_confirmed);
    }

    #[test]
    fn one_bssid_conflict_does_not_imply_cross_bssid_variation() {
        let low = ap("Office", "3c:5a:b4:11:22:33", Security::Wpa);
        let high = ap("Office", "3C:5A:B4:11:22:33", Security::Wpa3);
        let first = assess(&[low.clone(), high.clone()], None, "fixture", 0);
        let last = assess(&[high, low], None, "fixture", 0);
        assert_eq!(first, last);
        assert_eq!(first.evaluated_access_points, 1);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].code, "bssid_security_conflict_unverified");
        assert!(!first.mitm_confirmed);
    }

    #[test]
    fn duplicate_name_same_security_is_not_evil_twin() {
        let r = assess(
            &[
                ap("MeshLab", "02:33:44:55:66:77", Security::Wpa2),
                ap("MeshLab", "02:44:55:66:77:88", Security::Wpa2),
            ],
            None,
            "fixture",
            0,
        );
        assert!(r.findings.is_empty());
    }

    #[test]
    fn trusted_floor_and_unknown_bssid_trigger_findings() {
        let baseline = parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
        let r = assess(
            &[ap("Corp", "3c:5a:b4:22:33:44", Security::Wpa2)],
            Some(&baseline),
            "fixture",
            0,
        );
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, "high");
        assert!(!r.mitm_confirmed);
    }

    #[test]
    fn unknown_is_not_open_and_missing_data_is_inconclusive() {
        assert_eq!(Security::parse("Unknown"), Security::Unknown);
        assert_eq!(Security::parse("[ESS]"), Security::Open);
        assert_eq!(Security::parse("[WPA2-PSK][ESS]"), Security::Wpa2);
        let r =
            from_wigle_jsonl(br#"{"type":"BLE","network_id":"3c:5a:b4:11:22:33"}"#, None).unwrap();
        assert_eq!(r.status, "inconclusive");
    }

    #[test]
    fn unidentifiable_ssid_placeholder_is_not_a_shared_network() {
        let result = assess(
            &[
                ap("(no SSID)", "02:11:22:33:44:55", Security::Wpa2),
                ap("(no SSID)", "02:22:33:44:55:66", Security::Wpa3),
            ],
            None,
            "fixture",
            0,
        );
        assert!(result.findings.is_empty());
        assert_eq!(result.status, "inconclusive");
    }

    #[test]
    fn baseline_validation_rejects_redacted_or_multicast_mac() {
        assert!(parse_baseline(br#"{"networks":[{"ssid":"X","bssids":["02:00:00:00:00:00"],"minimum_security":"WPA2"}]}"#).is_err());
        assert!(parse_baseline(br#"{"networks":[{"ssid":"X","bssids":["01:00:5e:00:00:01"],"minimum_security":"WPA2"}]}"#).is_err());
    }

    #[test]
    fn wigle_data_is_filtered_and_validated() {
        let raw = b"{\"type\":\"WIFI\",\"name\":\"Cafe\",\"network_id\":\"3C:5A:B4:11:22:33\",\"encryption\":\"WPA2\"}\n{\"type\":\"LTE\",\"network_id\":\"cell\"}\n";
        let r = from_wigle_jsonl(raw, None).unwrap();
        assert_eq!(r.evaluated_access_points, 1);
        assert_eq!(r.rejected_records, 0);
    }

    #[test]
    fn transition_security_does_not_overstate_wpa3_only() {
        assert_eq!(
            Security::parse("[WPA2-PSK-CCMP][RSN-SAE-CCMP][ESS]"),
            Security::Wpa2
        );
        assert_eq!(Security::parse("[RSN-SAE-CCMP][ESS]"), Security::Wpa3);
        assert_eq!(Security::parse("[RSN-PSK-CCMP][ESS]"), Security::Wpa2);
        assert_eq!(Security::parse("[ESS]"), Security::Open);
        assert_eq!(Security::parse("Unknown"), Security::Unknown);
    }

    #[test]
    fn unknown_age_or_replay_is_not_a_current_mitm_indicator() {
        let raw = br#"[{"bssid":"3c:5a:b4:11:22:33","ssid":"Corp","rssi":-50,"timestamp":980000000,"capabilities":"[ESS]"}]"#;
        let baseline = parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
        let unknown_age = crate::wifi_radar::parse_scan(raw, None).unwrap();
        let replay = crate::wifi_radar::parse_replay(raw).unwrap();
        for scan in [&unknown_age, &replay] {
            let result = from_wifi_scan(scan, Some(&baseline));
            assert_eq!(result.status, "inconclusive");
            assert_eq!(result.evaluated_access_points, 0);
            assert!(result.findings.is_empty());
            assert!(!result.mitm_confirmed);
        }
        let current = crate::wifi_radar::parse_scan(raw, Some(1000.0)).unwrap();
        let result = from_wifi_scan(&current, Some(&baseline));
        assert_eq!(result.status, "unconfirmed_indicators");
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn rsn_psk_is_not_legacy_wpa_and_unknown_security_is_review_only() {
        assert_eq!(Security::parse("[RSN-PSK-CCMP][ESS]"), Security::Wpa2);
        assert_eq!(Security::parse("[WPA-PSK][WPA2-PSK][ESS]"), Security::Wpa);
        let baseline = parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
        let report = assess(
            &[ap("Corp", "3c:5a:b4:11:22:33", Security::Unknown)],
            Some(&baseline),
            "fixture",
            0,
        );
        assert_eq!(report.findings[0].code, "trusted_ssid_security_unverified");
        assert_eq!(report.findings[0].severity, "review");
        assert!(!report.mitm_confirmed);
        assert!(parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3+OPEN"}]}"#).is_err());
    }

    #[test]
    fn replay_is_historical_not_a_live_warning() {
        let raw =
            br#"[{"bssid":"3c:5a:b4:11:22:33","ssid":"Corp","rssi":-40,"capabilities":"[ESS]"}]"#;
        let baseline = parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
        let scan = crate::wifi_radar::parse_replay(raw).unwrap();
        let report = from_wifi_replay(&scan, Some(&baseline));
        assert_eq!(report.status, "historical_unconfirmed_indicators");
        assert_eq!(report.findings[0].code, "security_below_trusted_floor");
        assert!(!report.mitm_confirmed);
    }

    #[test]
    fn mixed_security_downgrade_and_unknown_capabilities_are_distinct() {
        assert_eq!(
            Security::parse("[WPA2-PSK-CCMP][RSN-SAE-CCMP][ESS]"),
            Security::Wpa2
        );
        assert_eq!(Security::parse("[RSN-SAE-CCMP][ESS]"), Security::Wpa3);
        assert_eq!(Security::parse("Unknown"), Security::Unknown);
        let baseline = parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
        let transition = assess(
            &[ap("Corp", "3c:5a:b4:11:22:33", Security::Wpa2)],
            Some(&baseline),
            "fixture",
            0,
        );
        assert_eq!(transition.findings[0].code, "security_below_trusted_floor");
        let missing = assess(
            &[ap("Corp", "3c:5a:b4:11:22:33", Security::Unknown)],
            Some(&baseline),
            "fixture",
            0,
        );
        assert_eq!(missing.findings[0].code, "trusted_ssid_security_unverified");
    }

    #[test]
    fn no_derived_finding_proves_mitm() {
        let r = assess(&[], None, "fixture", 0);
        assert_eq!(r.status, "inconclusive");
        assert!(r.findings.is_empty());
        assert!(!r.mitm_confirmed);
    }
}
