//! Evidence-gated, advisory MITM/evil-twin Wi-Fi assessment for rootless Android.
//! Only scans and operator-supplied baselines are used; no packet injection,
//! deauthentication, raw monitor mode, forced disconnect, or credential collection.
//! Research: arxiv.org/abs/2203.00579, 2302.00338, 2505.07724, 2512.10470.
//! A scan cannot establish interception: all output is explicitly unconfirmed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::wifi_radar::{WifiScan, valid_wifi_bssid};

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
        if u.contains("WPA3") || u.contains("SAE") {
            Self::Wpa3
        } else if u.contains("WPA2") || u.contains("RSN") {
            Self::Wpa2
        } else if u.contains("WPA") {
            Self::Wpa
        } else if u.contains("WEP") {
            Self::Wep
        } else if u.trim() == "OPEN" || (u.contains("[ESS]") && !u.contains("PSK")) {
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
    if bytes.len() > MAX_BASELINE_BYTES as usize {
        return Err("baseline exceeds 128 KiB".into());
    }
    let baseline: Baseline = serde_json::from_slice(bytes)
        .map_err(|e| format!("invalid baseline JSON: {e}"))?;
    if baseline.networks.len() > 512 {
        return Err("baseline contains too many SSIDs".into());
    }
    let mut ssids = BTreeSet::new();
    for n in &baseline.networks {
        if n.ssid.is_empty() || n.ssid.len() > 32 || !ssids.insert(n.ssid.as_str()) {
            return Err("baseline SSIDs must be unique and 1..32 bytes".into());
        }
        if n.bssids.is_empty() || n.bssids.len() > 256
            || n.bssids.iter().any(|s| !valid_wifi_bssid(s))
        {
            return Err("baseline requires 1..256 valid individual BSSIDs per SSID".into());
        }
        if Security::parse(&n.minimum_security).ordinal().is_none() {
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
    let mut by_ssid: BTreeMap<&str, BTreeMap<&str, &AccessPoint>> = BTreeMap::new();
    for ap in observations {
        if ap.ssid.is_empty() || ap.ssid.len() > 32 || !valid_wifi_bssid(&ap.bssid) {
            continue;
        }
        by_ssid.entry(&ap.ssid).or_default().entry(&ap.bssid).or_insert(ap);
    }
    let accepted = by_ssid.values().map(BTreeMap::len).sum::<usize>();
    let mut findings = Vec::new();
    let trusted: BTreeMap<&str, &TrustedNetwork> = baseline
        .map(|b| b.networks.iter().map(|n| (n.ssid.as_str(), n)).collect())
        .unwrap_or_default();

    for (ssid, aps) in &by_ssid {
        if let Some(policy) = trusted.get(ssid) {
            let minimum = Security::parse(&policy.minimum_security).ordinal();
            for ap in aps.values() {
                let enrolled = policy.bssids.iter().any(|b| b.eq_ignore_ascii_case(&ap.bssid));
                let downgrade = minimum.zip(ap.security.ordinal())
                    .is_some_and(|(min, current)| current < min);
                if downgrade {
                    findings.push(Finding {
                        code: "security_below_trusted_floor",
                        severity: "high",
                        ssid: (*ssid).to_owned(),
                        bssid: Some(ap.bssid.clone()),
                        evidence: format!(
                            "Observed {:?} below operator baseline {} (authorised BSSID: {}). Baseline authenticity must be independently verified.",
                            ap.security, policy.minimum_security, enrolled
                        ),
                        resolution: "Do not authenticate via this access point. Manually leave/forget the network and verify the BSSID, WPA mode and enterprise certificate with its administrator.",
                    });
                } else if !enrolled {
                    findings.push(Finding {
                        code: "bssid_not_on_operator_allowlist",
                        severity: "review",
                        ssid: (*ssid).to_owned(),
                        bssid: Some(ap.bssid.clone()),
                        evidence: "SSID appears in the operator baseline but this BSSID is not authorised there; mesh expansion or equipment replacement is also possible.".into(),
                        resolution: "Verify the network inventory with its administrator before trusting or updating the allowlist.",
                    });
                }
            }
        } else {
            let modes: BTreeSet<_> = aps.values().filter_map(|a| a.security.ordinal()).collect();
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
        (a.ssid.as_str(), a.code, a.bssid.as_deref())
            .cmp(&(b.ssid.as_str(), b.code, b.bssid.as_deref()))
    });
    let status = if accepted == 0 {
        "inconclusive"
    } else if findings.is_empty() {
        "no_specific_indicators_observed"
    } else {
        "unconfirmed_indicators"
    };
    Report {
        source,
        status,
        evaluated_access_points: accepted,
        rejected_records: rejected,
        trusted_baseline_supplied: baseline.is_some(),
        mitm_confirmed: false,
        findings,
        capability_limit: "Passive scan heuristics cannot prove interception, validate AP ownership, read 802.11 management frames, observe ARP/TLS tampering, or forcibly disconnect Wi-Fi on unprivileged Android.",
    }
}

/// Uses the existing live scan model. Stale cached observations cannot be
/// promoted to current evidence. A replay lacking a boot clock is unverified.
#[must_use]
pub fn from_wifi_scan(scan: &WifiScan, baseline: Option<&Baseline>) -> Report {
    let observations: Vec<_> = scan.observations.iter()
        .filter(|row| row.freshness != "stale")
        .map(|row| AccessPoint {
            ssid: row.sighting.name.clone().unwrap_or_default(),
            bssid: row.sighting.network_id.clone(),
            security: Security::parse(row.capabilities.as_deref()
                .or(row.sighting.encryption.as_deref()).unwrap_or("")),
            frequency_mhz: row.frequency_mhz,
        })
        .collect();
    assess(&observations, baseline, scan.source, scan.rejected)
}

/// Reads the normalized WiGLE JSONL export without treating Bluetooth/cell
/// records as Wi-Fi. Bounded input is enforced here and again at the CLI.
pub fn from_wigle_jsonl(bytes: &[u8], baseline: Option<&Baseline>) -> Result<Report, String> {
    if bytes.len() > MAX_IMPORT_BYTES as usize {
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
        let name = value.get("name").and_then(serde_json::Value::as_str).unwrap_or("");
        let bssid = value.get("network_id").and_then(serde_json::Value::as_str).unwrap_or("");
        if name.len() > 32 || !valid_wifi_bssid(bssid) {
            rejected += 1;
            continue;
        }
        observations.push(AccessPoint {
            ssid: name.to_owned(),
            bssid: bssid.to_ascii_lowercase(),
            security: Security::parse(value.get("encryption")
                .and_then(serde_json::Value::as_str).unwrap_or("")),
            frequency_mhz: value.get("frequency_mhz").and_then(serde_json::Value::as_i64),
        });
    }
    Ok(assess(&observations, baseline, "wigle_jsonl_unverified", rejected))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(ssid: &str, bssid: &str, security: Security) -> AccessPoint {
        AccessPoint { ssid: ssid.into(), bssid: bssid.into(), security, frequency_mhz: Some(2412) }
    }

    #[test]
    fn mixed_security_is_review_not_proof() {
        let r = assess(&[
            ap("Aspley Carsel", "9c:05:d6:7a:9b:e1", Security::Wpa2),
            ap("Aspley Carsel", "c4:f1:74:6d:8f:e7", Security::Wpa3),
        ], None, "fixture", 0);
        assert!(!r.mitm_confirmed);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].code, "unverified_ssid_security_variation");
        assert_eq!(r.findings[0].severity, "review");
    }

    #[test]
    fn duplicate_name_same_security_is_not_evil_twin() {
        let r = assess(&[
            ap("Pretty Fly for a Wifi", "58:04:4f:d9:df:0e", Security::Wpa2),
            ap("Pretty Fly for a Wifi", "cc:ba:bd:e0:43:56", Security::Wpa2),
        ], None, "fixture", 0);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn trusted_floor_and_unknown_bssid_trigger_findings() {
        let baseline = parse_baseline(br#"{"networks":[{"ssid":"Corp","bssids":["3c:5a:b4:11:22:33"],"minimum_security":"WPA3"}]}"#).unwrap();
        let r = assess(&[ap("Corp","3c:5a:b4:22:33:44",Security::Wpa2)],Some(&baseline),"fixture",0);
        assert_eq!(r.findings.len(),1);
        assert_eq!(r.findings[0].severity,"high");
        assert!(!r.mitm_confirmed);
    }

    #[test]
    fn unknown_is_not_open_and_missing_data_is_inconclusive() {
        assert_eq!(Security::parse("Unknown"), Security::Unknown);
        assert_eq!(Security::parse("[ESS]"), Security::Open);
        assert_eq!(Security::parse("[WPA2-PSK][ESS]"), Security::Wpa2);
        let r = from_wigle_jsonl(br#"{"type":"BLE","network_id":"3c:5a:b4:11:22:33"}"#,None).unwrap();
        assert_eq!(r.status,"inconclusive");
    }

    #[test]
    fn baseline_validation_rejects_redacted_or_multicast_mac() {
        assert!(parse_baseline(br#"{"networks":[{"ssid":"X","bssids":["02:00:00:00:00:00"],"minimum_security":"WPA2"}]}"#).is_err());
        assert!(parse_baseline(br#"{"networks":[{"ssid":"X","bssids":["01:00:5e:00:00:01"],"minimum_security":"WPA2"}]}"#).is_err());
    }

    #[test]
    fn wigle_data_is_filtered_and_validated() {
        let raw = b"{\"type\":\"WIFI\",\"name\":\"Cafe\",\"network_id\":\"3C:5A:B4:11:22:33\",\"encryption\":\"WPA2\"}\n{\"type\":\"LTE\",\"network_id\":\"cell\"}\n";
        let r = from_wigle_jsonl(raw,None).unwrap();
        assert_eq!(r.evaluated_access_points,1);
        assert_eq!(r.rejected_records,0);
    }

    #[test]
    fn no_derived_finding_proves_mitm() {
        let r = assess(&[],None,"fixture",0);
        assert_eq!(r.status,"inconclusive");
        assert!(r.findings.is_empty());
        assert!(!r.mitm_confirmed);
    }
}
