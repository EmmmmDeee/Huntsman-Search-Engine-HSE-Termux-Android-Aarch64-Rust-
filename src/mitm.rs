//! Passive, evidence-gated Wi-Fi evil-twin screening for unprivileged Android Termux.
//!
//! MITM cannot be proved from an OS-cached Wi-Fi scan. This module compares
//! observations to a user-verified trusted baseline. No traffic interception,
//! automated disassociation, or claims of cellular/ARP/TLS inspection.
//!
//! Research context (not direct algorithm reproductions):
//! arXiv:2406.01927, arXiv:2505.07724, arXiv:2401.04958,
//! arXiv:2605.19232.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::wifi_radar::{WifiScan, valid_wifi_bssid};

const MAX_ANCHORS: usize = 128;
const MAX_OBSERVATIONS: usize = 4096;

/// A conservative classification of Android capabilities, not a complete RSN parse.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    Open,
    EnhancedOpen,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    Enterprise,
    Unknown,
}
impl Security {
    const fn protected(self) -> bool {
        matches!(
            self,
            Self::EnhancedOpen | Self::Wpa | Self::Wpa2 | Self::Wpa3 | Self::Enterprise
        )
    }
}

/// Unknown/missing capabilities are never silently interpreted as "open".
#[must_use]
pub fn classify_capabilities(value: Option<&str>) -> Security {
    let Some(raw) = value else {
        return Security::Unknown;
    };
    let caps = raw.trim().to_ascii_uppercase();
    if caps.is_empty() {
        return Security::Unknown;
    }
    if caps.contains("EAP") || caps.contains("802.1X") || caps.contains("SUITE_B") {
        return Security::Enterprise;
    }
    if caps.contains("SAE") || caps.contains("WPA3") {
        return Security::Wpa3;
    }
    if caps.contains("OWE") {
        return Security::EnhancedOpen;
    }
    if caps.contains("WPA2") || caps.contains("RSN") {
        return Security::Wpa2;
    }
    if caps.contains("WPA") {
        return Security::Wpa;
    }
    if caps.contains("WEP") {
        return Security::Wep;
    }
    if caps == "[ESS]" || caps == "ESS" || caps == "[IBSS]" || caps == "IBSS" {
        return Security::Open;
    }
    Security::Unknown
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub bssid: String,
    pub security: Security,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedBaseline {
    pub format: u8,
    pub ssid: String,
    pub anchors: Vec<Anchor>,
}

impl TrustedBaseline {
    /// Enrolment does not *establish* authenticity. The operator MUST have verified
    /// this SSID and its permitted BSSIDs with the router or network administrator.
    pub fn enroll(scan: &WifiScan, ssid: &str) -> Result<Self, String> {
        if ssid.is_empty() || ssid.len() > 32 {
            return Err("SSID must contain between 1 and 32 UTF-8 bytes".into());
        }
        if scan.observations.len() > MAX_OBSERVATIONS {
            return Err("too many observations".into());
        }
        let mut anchors = BTreeMap::new();
        for obs in &scan.observations {
            if obs.freshness == "stale" || obs.sighting.name.as_deref() != Some(ssid) {
                continue;
            }
            let bssid = obs.sighting.network_id.to_ascii_lowercase();
            if !valid_wifi_bssid(&bssid) {
                continue;
            }
            let security = classify_capabilities(obs.capabilities.as_deref());
            if let Some(previous) = anchors.insert(bssid, security) {
                if previous != security {
                    return Err("conflicting security for one BSSID in baseline".into());
                }
            }
        }
        if anchors.is_empty() {
            return Err("the named SSID was not present in the usable scan".into());
        }
        if anchors.len() > MAX_ANCHORS {
            return Err("too many BSSIDs for one baseline".into());
        }
        if anchors.values().any(|security| *security == Security::Unknown) {
            return Err("unknown security: cannot create verified baseline".into());
        }
        let baseline = Self {
            format: 1,
            ssid: ssid.to_owned(),
            anchors: anchors
                .into_iter()
                .map(|(bssid, security)| Anchor { bssid, security })
                .collect(),
        };
        baseline.validate()?;
        Ok(baseline)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format != 1 || self.ssid.is_empty() || self.ssid.len() > 32 {
            return Err("invalid or unsupported MITM baseline".into());
        }
        if self.anchors.is_empty() || self.anchors.len() > MAX_ANCHORS {
            return Err("baseline must have 1..=128 trusted addresses".into());
        }
        let mut seen = BTreeSet::new();
        for anchor in &self.anchors {
            if !valid_wifi_bssid(&anchor.bssid)
                || anchor.bssid != anchor.bssid.to_ascii_lowercase()
                || anchor.security == Security::Unknown
                || !seen.insert(&anchor.bssid)
            {
                return Err("invalid, duplicate, or ambiguous baseline BSSID".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: &'static str,
    pub severity: &'static str,
    pub ssid: String,
    pub bssid: String,
    pub evidence: String,
    pub recommended_action: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub status: &'static str,
    pub source: &'static str,
    pub source_status: &'static str,
    pub baseline_ssid: String,
    pub inspected: usize,
    pub trusted_bssids_seen: usize,
    pub findings: Vec<Finding>,
    pub limitations: Vec<&'static str>,
}

/// Check only exact SSID matches. One scan is NOT a time-series, and
/// unrecognised BSSIDs in enterprise/mesh networks are commonplace.
/// Never classify a network as a confirmed MITM from these observations.
pub fn assess(scan: &WifiScan, baseline: &TrustedBaseline) -> Result<Report, String> {
    baseline.validate()?;
    if scan.observations.len() > MAX_OBSERVATIONS {
        return Err("too many observations".into());
    }
    let anchors: BTreeMap<&str, Security> = baseline
        .anchors
        .iter()
        .map(|a| (a.bssid.as_str(), a.security))
        .collect();
    let mut seen = BTreeMap::<String, BTreeSet<String>>::new();
    let mut trusted_seen = BTreeSet::new();
    let mut findings = Vec::new();
    let mut inspected = 0;
    let mut any_unknown = false;
    for obs in &scan.observations {
        if obs.freshness == "stale" || obs.sighting.name.as_deref() != Some(baseline.ssid.as_str()) {
            continue;
        }
        let bssid = obs.sighting.network_id.to_ascii_lowercase();
        if !valid_wifi_bssid(&bssid) {
            continue;
        }
        inspected += 1;
        let observed = classify_capabilities(obs.capabilities.as_deref());
        if observed == Security::Unknown {
            any_unknown = true;
        }
        seen.entry(bssid.clone())
            .or_default()
            .insert(format!("{observed:?}"));
        let (kind, severity, action) = match anchors.get(bssid.as_str()) {
            Some(expected) => {
                trusted_seen.insert(bssid.clone());
                if observed == Security::Unknown {
                    (
                        "security_unavailable",
                        "review",
                        "Inspect the access point's current security configuration from its trusted management interface.",
                    )
                } else if expected.protected() && !observed.protected() {
                    (
                        "security_downgrade",
                        "high",
                        "Avoid joining this SSID until the approved router configuration and BSSID are verified.",
                    )
                } else if expected != &observed {
                    (
                        "security_changed",
                        "review",
                        "Verify whether the network administrator changed its authentication or transition-mode configuration.",
                    )
                } else {
                    continue;
                }
            }
            None => {
                if observed == Security::Open && anchors.values().any(|s| s.protected()) {
                    (
                        "unrecognized_open_ap",
                        "high",
                        "Do not join the open network with this name; confirm the BSSID with the trusted network administrator.",
                    )
                } else {
                    (
                        "unrecognized_bssid",
                        "review",
                        "Compare the BSSID to the approved access-point inventory; mesh nodes or new radios may be legitimate.",
                    )
                }
            }
        };
        findings.push(Finding {
            kind,
            severity,
            ssid: baseline.ssid.clone(),
            bssid,
            evidence: format!(
                "observed={observed:?}; baseline={:?}; freshness={}; scan_source={}",
                anchors.get(obs.sighting.network_id.to_ascii_lowercase().as_str()),
                obs.freshness,
                scan.source
            ),
            recommended_action: action,
        });
    }

    // Conflicting security for one BSSID within a capture is a reason to
    // investigate, not proof that the radio was impersonated.
    for (bssid, securities) in seen {
        if securities.len() > 1 {
            findings.push(Finding {
                kind: "conflicting_advertisement",
                severity: "high",
                ssid: baseline.ssid.clone(),
                bssid,
                evidence: format!("same scan, conflicting capability classes: {securities:?}"),
                recommended_action:
                    "Confirm with an authorised AP controller or monitor-mode capture before attributing the anomaly.",
            });
        }
    }

    findings.sort_by(|a, b| {
        (&a.bssid, a.kind, a.evidence.as_str())
            .cmp(&(&b.bssid, b.kind, b.evidence.as_str()))
    });
    findings.dedup_by(|a, b| a.bssid == b.bssid && a.kind == b.kind);
    let incomplete = inspected == 0 || scan.status == "inconclusive" || scan.status == "stale_only";
    let status = if incomplete {
        "inconclusive"
    } else if findings.iter().any(|f| f.severity == "high") {
        "suspected"
    } else if !findings.is_empty() {
        "review"
    } else {
        "no_indicators_observed"
    };
    let mut limitations = vec![
        "No finding proves an active man-in-the-middle attack.",
        "Android Wi-Fi results are cached; a replay file does not establish live location or freshness.",
        "ARP spoofing, DHCP, DNS, TLS interception, deauthentication and cellular signalling were not measured.",
        "Only SSID, BSSID, and advertised capability classes are compared; signal power is not identity proof.",
    ];
    if any_unknown {
        limitations.push("At least one security advertisement could not be classified.");
    }
    if trusted_seen.is_empty() {
        limitations.push("No trusted BSSID was observed: the baseline cannot be independently confirmed.");
    }
    Ok(Report {
        status,
        source: scan.source,
        source_status: scan.status,
        baseline_ssid: baseline.ssid.clone(),
        inspected,
        trusted_bssids_seen: trusted_seen.len(),
        findings,
        limitations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(rows: &str) -> WifiScan {
        crate::wifi_radar::parse_replay(rows.as_bytes()).expect("valid scan")
    }
    const GOOD: &str = r#"[{"ssid":"Home","bssid":"a0:11:22:33:44:55","rssi":-60,"capabilities":"[WPA2-PSK-CCMP][ESS]"}]"#;

    #[test]
    fn baseline_and_no_indicators() {
        let s = scan(GOOD);
        let b = TrustedBaseline::enroll(&s, "Home").unwrap();
        let r = assess(&s, &b).unwrap();
        assert_eq!(r.status, "no_indicators_observed");
        assert_eq!(r.trusted_bssids_seen, 1);
    }

    #[test]
    fn spoofed_name_open_is_high_but_not_confirmed() {
        let b = TrustedBaseline::enroll(&scan(GOOD), "Home").unwrap();
        let s = scan(r#"[{"ssid":"Home","bssid":"a0:11:22:33:44:66","rssi":-20,"capabilities":"[ESS]"}]"#);
        let r = assess(&s, &b).unwrap();
        assert_eq!(r.status, "suspected");
        assert_eq!(r.findings[0].kind, "unrecognized_open_ap");
    }

    #[test]
    fn a_new_protected_mesh_radio_is_only_review() {
        let b = TrustedBaseline::enroll(&scan(GOOD), "Home").unwrap();
        let s = scan(r#"[{"ssid":"Home","bssid":"a0:11:22:33:44:66","rssi":-20,"capabilities":"[WPA2-PSK-CCMP][ESS]"}]"#);
        let r = assess(&s, &b).unwrap();
        assert_eq!(r.status, "review");
    }

    #[test]
    fn security_change_on_known_bssid() {
        let b = TrustedBaseline::enroll(&scan(GOOD), "Home").unwrap();
        let s = scan(r#"[{"ssid":"Home","bssid":"a0:11:22:33:44:55","rssi":-60,"capabilities":"[ESS]"}]"#);
        assert_eq!(assess(&s, &b).unwrap().findings[0].kind, "security_downgrade");
    }

    #[test]
    fn unknown_not_open_and_no_match_not_safe() {
        assert_eq!(classify_capabilities(None), Security::Unknown);
        assert_eq!(classify_capabilities(Some("[OWE_TRANSITION][ESS]")), Security::EnhancedOpen);
        let b = TrustedBaseline::enroll(&scan(GOOD), "Home").unwrap();
        assert_eq!(assess(&scan("[]"), &b).unwrap().status, "inconclusive");
    }

    #[test]
    fn bad_baseline_rejected() {
        let mut b = TrustedBaseline::enroll(&scan(GOOD), "Home").unwrap();
        b.anchors.push(b.anchors[0].clone());
        assert!(b.validate().is_err());
        assert!(TrustedBaseline::enroll(&scan(GOOD), "").is_err());
    }

    #[test]
    fn conflicting_capabilities_reported() {
        let b = TrustedBaseline::enroll(&scan(GOOD), "Home").unwrap();
        let s = scan(r#"[
            {"ssid":"Home","bssid":"a0:11:22:33:44:55","rssi":-60,"capabilities":"[WPA2-PSK-CCMP][ESS]"},
            {"ssid":"Home","bssid":"a0:11:22:33:44:55","rssi":-60,"capabilities":"[ESS]"}]"#);
        assert!(assess(&s, &b).unwrap().findings.iter().any(|f| f.kind == "conflicting_advertisement"));
    }
}
