//! Unified WiFi intelligence — access-point survey **and** BSSID geolocation
//! in a single `termux-wifi-scaninfo` invocation.
//!
//! Merges the former `wifi_scan` (AP enumeration → `MacAddress` entities) and
//! `bssid_locate` (top-N strongest BSSIDs → WiGLE detail → `Coordinates` +
//! `Address` entities) into one module that calls the Termux API **once**,
//! halving the radio scan overhead on-device.
//!
//! Auth: HTTP Basic — `HUNTSMAN_WIGLE_USER` / `HUNTSMAN_WIGLE_TOKEN` with
//! hardcoded fallback, same as the `wigle` module.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::Target,
};
use crate::util::http::error_snippet;
use crate::util::termux::termux_cmd;

// ── WiGLE credentials ──────────────────────────────────────────────────

const USER_ENV: &str = "HUNTSMAN_WIGLE_USER";
const TOKEN_ENV: &str = "HUNTSMAN_WIGLE_TOKEN";
const HARDCODED_USER: &str = "AID4493a33e2df9d07ab9666a27c8aead17";
const HARDCODED_TOKEN: &str = "1aedb7ad0171ff3d6be5a844cca5d977";

/// How many of the strongest APs to query WiGLE for.
const MAX_BSSIDS: usize = 5;

/// Evidence source tag used throughout this module.
const SOURCE: &str = "wifi_intel";

// ── Termux scan-info deserialization ────────────────────────────────────

#[derive(Deserialize)]
struct Ap {
    bssid: String,
    ssid: Option<String>,
    frequency: Option<i64>,
    rssi: Option<i64>,
    timestamp: Option<i64>,
}

// ── WiGLE detail-API response ──────────────────────────────────────────

#[derive(Deserialize)]
struct DetailResp {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    results: Vec<DetailNetwork>,
}

#[derive(Deserialize)]
struct DetailNetwork {
    #[serde(default)]
    trilat: Option<f64>,
    #[serde(default)]
    trilong: Option<f64>,
    #[serde(default)]
    ssid: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    postalcode: Option<String>,
    #[serde(default)]
    lastupdt: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
}

// ── Module implementation ──────────────────────────────────────────────

pub struct WifiIntel;

#[async_trait]
impl Module for WifiIntel {
    fn name(&self) -> &'static str {
        "wifi_intel"
    }

    fn description(&self) -> &'static str {
        "WiFi AP survey and BSSID geolocation via Termux + WiGLE"
    }

    fn priority(&self) -> u8 {
        65
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::MacAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let user = ctx.key_opt(USER_ENV).unwrap_or(HARDCODED_USER);
        let token = ctx.key_opt(TOKEN_ENV).unwrap_or(HARDCODED_TOKEN);

        // ── Single termux-wifi-scaninfo call ────────────────────────────
        let Some(stdout) = termux_cmd("termux-wifi-scaninfo", &[], 5000).await else {
            return Ok(ModuleResult::new());
        };

        let mut aps: Vec<Ap> = match serde_json::from_slice(&stdout) {
            Ok(v) => v,
            Err(_) => return Ok(ModuleResult::new()),
        };

        if aps.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Sort by signal strength (strongest first) so top-N selection is
        // deterministic; we walk the full list for MacAddress entities but
        // only query WiGLE for the first MAX_BSSIDS.
        aps.sort_by_key(|a| std::cmp::Reverse(a.rssi.unwrap_or(-100)));

        let mut result = ModuleResult::with_capacity(aps.len());

        // ── Phase 1: MacAddress entities for ALL APs ────────────────────
        for ap in &aps {
            let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
            let mut e = Entity::new(EntityKind::MacAddress, &ap.bssid, 0.95, &ctx.scan_id);
            e.tag("wifi-ap");
            e.add_evidence(
                Evidence::new(SOURCE, format!("Wi-Fi AP: {ssid}"))
                    .with_attr("ssid", ssid)
                    .with_attr("bssid", &ap.bssid)
                    .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
                    .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
                    .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string()),
            );
            result.push(e);
        }

        // ── Phase 2: WiGLE geolocation for top-N strongest APs ─────────
        for ap in aps.iter().take(MAX_BSSIDS) {
            if ctx.cancel.is_cancelled() {
                break;
            }

            if ap.bssid.len() < 12 {
                continue;
            }

            if let Ok(Some(detail)) = query_wigle_detail(&ctx.http, user, token, &ap.bssid).await
                && let (Some(lat), Some(lon)) = (detail.trilat, detail.trilong)
            {
                if lat == 0.0 && lon == 0.0 {
                    continue;
                }

                let coords = format!("{lat:.6},{lon:.6}");
                let ssid = detail
                    .ssid
                    .as_deref()
                    .or(ap.ssid.as_deref())
                    .unwrap_or("<hidden>");

                let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.80, &ctx.scan_id);
                e.tag("geoint");
                e.tag("wifi-ap");
                e.tag("bssid-located");

                let mut ev = Evidence::new(
                    SOURCE,
                    format!("BSSID {} ({ssid}) \u{2192} {coords}", ap.bssid),
                )
                .with_attr("bssid", &ap.bssid)
                .with_attr("ssid", ssid)
                .with_attr("latitude", lat.to_string())
                .with_attr("longitude", lon.to_string())
                .with_attr("source", "WiGLE");

                if let Some(rssi) = ap.rssi {
                    ev = ev.with_attr("rssi_dbm", rssi.to_string());
                }
                if let Some(c) = detail.city.as_deref() {
                    ev = ev.with_attr("city", c);
                }
                if let Some(r) = detail.region.as_deref() {
                    ev = ev.with_attr("region", r);
                }
                if let Some(c) = detail.country.as_deref() {
                    ev = ev.with_attr("country", c);
                }
                if let Some(p) = detail.postalcode.as_deref() {
                    ev = ev.with_attr("postcode", p);
                }
                if let Some(t) = detail.lastupdt.as_deref() {
                    ev = ev.with_attr("last_updated", t);
                }
                if let Some(enc) = detail.encryption.as_deref() {
                    ev = ev.with_attr("encryption", enc);
                }

                e.add_evidence(ev);
                result.push(e);

                // Also emit an Address entity if we have city + country
                let addr_parts: Vec<&str> = [
                    detail.city.as_deref(),
                    detail.region.as_deref(),
                    detail.country.as_deref(),
                ]
                .iter()
                .filter_map(|p| *p)
                .filter(|p| !p.is_empty())
                .collect();

                if addr_parts.len() >= 2 {
                    let mut addr_str = addr_parts.join(", ");
                    if let Some(p) = detail.postalcode.as_deref()
                        && !p.is_empty()
                    {
                        addr_str = format!("{addr_str} {p}");
                    }
                    let mut addr = Entity::new(EntityKind::Address, &addr_str, 0.60, &ctx.scan_id);
                    addr.tag("geoint");
                    addr.tag("bssid-derived");
                    addr.add_evidence(
                        Evidence::new(SOURCE, format!("Address from BSSID {} location", ap.bssid))
                            .with_attr("bssid", &ap.bssid),
                    );
                    result.push(addr);
                }
            }
        }

        Ok(result)
    }
}

// ── WiGLE detail query ─────────────────────────────────────────────────

async fn query_wigle_detail(
    http: &reqwest::Client,
    user: &str,
    token: &str,
    bssid: &str,
) -> Result<Option<DetailNetwork>> {
    let encoded = crate::util::http::urlencode(bssid);
    let url = format!("https://api.wigle.net/api/v2/network/detail?netid={encoded}&type=wifi");

    let resp = http
        .get(&url)
        .basic_auth(user, Some(token))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::module(SOURCE, e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 429 {
        let retry_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);
        tracing::warn!("WiGLE 429 — backing off {retry_secs}s");
        tokio::time::sleep(std::time::Duration::from_secs(retry_secs.min(120))).await;
        return Err(Error::module(SOURCE, "rate-limited (429)"));
    }
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return Err(Error::module(
            SOURCE,
            format!("WiGLE auth failed (HTTP {status}): check HUNTSMAN_WIGLE_USER/TOKEN"),
        ));
    }
    if !status.is_success() {
        return Err(Error::module(
            SOURCE,
            format!("WiGLE HTTP {status}: {}", error_snippet(resp).await),
        ));
    }

    let body: DetailResp = resp
        .json()
        .await
        .map_err(|e| Error::module(SOURCE, e.to_string()))?;

    if body.success != Some(true) {
        return Ok(None);
    }

    Ok(body.results.into_iter().next())
}

// ── Standalone AP parser (used by tests, mirrors old wifi_scan logic) ──

#[cfg(test)]
fn parse_aps(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let aps: Vec<Ap> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::with_capacity(aps.len());
    for ap in aps {
        let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
        let mut e = Entity::new(EntityKind::MacAddress, &ap.bssid, 0.95, scan_id);
        e.tag("wifi-ap");
        e.add_evidence(
            Evidence::new(SOURCE, format!("Wi-Fi AP: {ssid}"))
                .with_attr("ssid", ssid)
                .with_attr("bssid", ap.bssid)
                .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
                .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
                .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string()),
        );
        result.push(e);
    }
    result
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    // ── Module trait tests ──────────────────────────────────────────────

    #[test]
    fn is_passive() {
        assert!(WifiIntel.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(WifiIntel.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(WifiIntel.accepts(&Target::new(TargetKind::Domain, "x")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(WifiIntel.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(WifiIntel.name(), "wifi_intel");
        assert_eq!(WifiIntel.priority(), 65);
    }

    #[test]
    fn description_is_set() {
        assert_eq!(
            WifiIntel.description(),
            "WiFi AP survey and BSSID geolocation via Termux + WiGLE"
        );
    }

    #[test]
    fn max_timeout_is_20s() {
        assert_eq!(WifiIntel.max_timeout_ms(), 20_000);
    }

    // ── AP parsing ─────────────────────────────────────

    #[test]
    fn parses_sample_payload() {
        let json = br#"[
            {"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","frequency":2412,"rssi":-45,"timestamp":1},
            {"bssid":"11:22:33:44:55:66","ssid":null,"frequency":5180,"rssi":-72,"timestamp":2}
        ]"#;
        let r = parse_aps(json, "test");
        assert_eq!(r.entities.len(), 2);
        assert_eq!(r.entities[0].kind, EntityKind::MacAddress);
        assert_eq!(r.entities[0].value, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_aps(b"not json", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn parses_three_aps_with_all_fields() {
        let json = br#"[
            {"bssid":"aa:bb:cc:dd:ee:ff","ssid":"HomeNet","frequency":2437,"rssi":-42,"timestamp":100},
            {"bssid":"11:22:33:44:55:66","ssid":"Office5G","frequency":5745,"rssi":-68,"timestamp":200},
            {"bssid":"de:ad:be:ef:ca:fe","ssid":"CafeWifi","frequency":2462,"rssi":-55,"timestamp":300}
        ]"#;
        let r = parse_aps(json, "scan-001");
        assert_eq!(r.entities.len(), 3);

        // Verify first AP entity
        let ap0 = &r.entities[0];
        assert_eq!(ap0.kind, EntityKind::MacAddress);
        assert_eq!(ap0.value, "aa:bb:cc:dd:ee:ff");
        assert!((ap0.confidence - 0.95).abs() < 1e-6);
        assert!(ap0.has_tag("wifi-ap"));
        assert_eq!(ap0.scan_id, "scan-001");

        // Verify evidence attributes on first AP
        let ev0 = &ap0.evidence[0];
        assert_eq!(ev0.source, SOURCE);
        assert_eq!(ev0.attributes.get("ssid").unwrap(), "HomeNet");
        assert_eq!(ev0.attributes.get("bssid").unwrap(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(ev0.attributes.get("frequency_mhz").unwrap(), "2437");
        assert_eq!(ev0.attributes.get("rssi_dbm").unwrap(), "-42");
        assert_eq!(ev0.attributes.get("timestamp").unwrap(), "100");

        // Verify third AP (5 GHz band)
        let ap2 = &r.entities[2];
        assert_eq!(ap2.value, "de:ad:be:ef:ca:fe");
        assert_eq!(
            ap2.evidence[0].attributes.get("frequency_mhz").unwrap(),
            "2462"
        );
    }

    #[test]
    fn hidden_ssid_shows_placeholder() {
        let json = br#"[{"bssid":"ff:ff:ff:ff:ff:ff","ssid":null,"frequency":2412,"rssi":-80,"timestamp":0}]"#;
        let r = parse_aps(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.attributes.get("ssid").unwrap(), "<hidden>");
        assert!(ev.summary.contains("<hidden>"));
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let json = br#"[{"bssid":"ab:cd:ef:01:23:45"}]"#;
        let r = parse_aps(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.attributes.get("frequency_mhz").unwrap(), "0");
        assert_eq!(ev.attributes.get("rssi_dbm").unwrap(), "0");
        assert_eq!(ev.attributes.get("timestamp").unwrap(), "0");
    }

    #[test]
    fn empty_json_array_no_ops() {
        let r = parse_aps(b"[]", "test");
        assert_eq!(r.entities.len(), 0);
    }

    // ── WiGLE DetailResp deserialization (from bssid_locate) ────────────

    #[test]
    fn detail_resp_deserializes() {
        let json = r#"{
            "success": true,
            "results": [{
                "trilat": -27.4766,
                "trilong": 153.0166,
                "ssid": "TestNet",
                "city": "Brisbane",
                "region": "Queensland",
                "country": "AU",
                "postalcode": "4000",
                "lastupdt": "2024-12-01",
                "encryption": "wpa2"
            }]
        }"#;
        let r: DetailResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(true));
        assert_eq!(r.results.len(), 1);
        let net = &r.results[0];
        assert!((net.trilat.unwrap() - (-27.4766)).abs() < 0.001);
        assert_eq!(net.city.as_deref(), Some("Brisbane"));
    }

    #[test]
    fn detail_resp_handles_empty() {
        let json = r#"{"success": true, "results": []}"#;
        let r: DetailResp = serde_json::from_str(json).unwrap();
        assert!(r.results.is_empty());
    }

    #[test]
    fn detail_resp_handles_failure() {
        let json = r#"{"success": false}"#;
        let r: DetailResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.success, Some(false));
    }
}
