//! Device location sensors — WiFi connection info and GPS/network fix via Termux.
//!
//! Merges the former `wifi_connect` and `gps_fix` modules into a single
//! passive sensor pass.  Invokes `termux-wifi-connectioninfo` (3 s ceiling),
//! then a location fix: `termux-location -p gps` first (12 s), falling back to
//! `-p network` (8 s) when GPS yields no valid fix.
//!
//! Off-device behaviour: termux-api binary missing → no-op (no error).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::termux::termux_cmd;

const SRC: &str = "device_sensors";

pub struct DeviceSensors;

// ── WiFi deserialization ────────────────────────────────────────────────

#[derive(Deserialize)]
struct ConnInfo {
    bssid: Option<String>,
    ssid: Option<String>,
    ip: Option<String>,
    frequency_mhz: Option<i64>,
    rssi: Option<i64>,
    link_speed_mbps: Option<i64>,
    supplicant_state: Option<String>,
}

// ── GPS deserialization ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct Fix {
    latitude: f64,
    longitude: f64,
    altitude: Option<f64>,
    accuracy: Option<f64>,
    speed: Option<f64>,
    bearing: Option<f64>,
    provider: Option<String>,
}

// ── Module impl ─────────────────────────────────────────────────────────

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
        // Local sensors describe the OPERATOR's own device, not a remote
        // subject — engage only on a deliberately-local seed (coordinates / MAC)
        // so the device's GPS/Wi-Fi is never attributed to a name/email/domain/IP
        // subject (fault-tree cut set MCS-A). Expansion is already gated for
        // LOCAL_PASSIVE_MODULES, so this governs the seed round.
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

    /// termux-location network provider typically returns in 1-5 s but
    /// can take 15 s indoors. Bump to 20 s for headroom.
    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        // ── Step 1: WiFi connection info (3 s timeout) ──────────────
        if let Some(stdout) = termux_cmd("termux-wifi-connectioninfo", &[], 3000).await {
            let wifi = parse_conn(&stdout, &ctx.scan_id);
            for e in wifi.entities {
                result.push(e);
            }
        }

        // ── Step 2: location fix — GPS first, network fallback ──────
        // The brief requires gps_fix WITH a network-provider fallback. Try the
        // GPS provider first (highest accuracy; satellite acquisition can be
        // slow, so a ~12 s ceiling), and only if it yields no VALID fix fall
        // back to the network provider (~8 s; works indoors / cold-start).
        // Both calls are independently timeout-bounded and together stay
        // inside the module's 20 s max_timeout_ms. A GPS response that fails
        // validation (Null Island / out-of-range) correctly triggers the
        // fallback rather than being accepted.
        let gps = fetch_fix("gps", 12_000, &ctx.scan_id).await;
        let fix = if gps.entities.is_empty() {
            fetch_fix("network", 8_000, &ctx.scan_id).await
        } else {
            gps
        };
        for e in fix.entities {
            result.push(e);
        }

        Ok(result)
    }
}

/// Run `termux-location -p <provider> -r once`, bounded by `timeout_ms`, and
/// parse the result. Returns an empty `ModuleResult` off-device (binary
/// missing), on timeout, or on an invalid/no-fix payload — so the caller can
/// treat "no entities" as "try the next provider".
async fn fetch_fix(provider: &str, timeout_ms: u64, scan_id: &str) -> ModuleResult {
    match termux_cmd(
        "termux-location",
        &["-p", provider, "-r", "once"],
        timeout_ms,
    )
    .await
    {
        Some(stdout) => parse_fix(&stdout, scan_id),
        None => ModuleResult::new(),
    }
}

// ── WiFi parsing ────────────────────────────────────────────────────────

/// Classify an 802.11 channel centre frequency (MHz) into its band.
/// Returns `None` for absent/zero/unrecognised frequencies so callers emit
/// no band tag rather than a misleading one.
fn wifi_band(freq_mhz: Option<i64>) -> Option<&'static str> {
    match freq_mhz? {
        2400..=2500 => Some("2.4GHz"),
        4900..=5900 => Some("5GHz"),
        5925..=7125 => Some("6GHz"),
        _ => None,
    }
}

fn parse_conn(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let info: ConnInfo = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::new();
    let ssid = info.ssid.as_deref().unwrap_or("<hidden>");

    if let Some(ref bssid) = info.bssid
        && !bssid.is_empty()
        && bssid != "00:00:00:00:00:00"
        && bssid != "02:00:00:00:00:00"
    // "MAC restricted" placeholder
    {
        let mut e = Entity::new(EntityKind::MacAddress, bssid.as_str(), 0.95, scan_id);
        e.tag("wifi-connected");
        // The connected-AP BSSID is the single highest-value WiFi-geolocation
        // seed available on an unrooted device. It already expands into the
        // wigle / mylnikov BSSID→coordinates pivot (both accept MacAddress and
        // the engine weights MacAddress expansion 2.0×); tag it explicitly so
        // the intent is legible and so geo-aware consumers can prioritise it.
        e.tag("geolocatable");
        let mut bssid_ev = Evidence::new(SRC, format!("Connected to: {ssid}"))
            .with_attr("ssid", ssid)
            .with_attr("frequency_mhz", info.frequency_mhz.unwrap_or(0).to_string())
            .with_attr("rssi_dbm", info.rssi.unwrap_or(0).to_string())
            .with_attr(
                "link_speed_mbps",
                info.link_speed_mbps.unwrap_or(0).to_string(),
            )
            .with_attr(
                "supplicant_state",
                info.supplicant_state.as_deref().unwrap_or("-"),
            );
        // Classify the 802.11 band from the channel frequency — useful AP
        // context (6 GHz ⇒ Wi-Fi 6E/7 hardware, etc.) the raw MHz didn't give.
        if let Some(band) = wifi_band(info.frequency_mhz) {
            e.tag(format!("band:{band}"));
            bssid_ev = bssid_ev.with_attr("band", band);
        }
        e.add_evidence(bssid_ev);
        result.push(e);
    }

    if let Some(ref ip) = info.ip
        && !ip.is_empty()
        && ip != "0.0.0.0"
    {
        let mut e = Entity::new(EntityKind::IpAddress, ip.as_str(), 0.90, scan_id);
        e.tag("local-wifi");
        let mut ip_ev = Evidence::new(SRC, format!("Local IP on {ssid}")).with_attr("ssid", ssid);
        if let Some(ref bssid) = info.bssid {
            ip_ev = ip_ev.with_attr("bssid", bssid.as_str());
        }
        ip_ev = ip_ev
            .with_attr("frequency_mhz", info.frequency_mhz.unwrap_or(0).to_string())
            .with_attr("rssi_dbm", info.rssi.unwrap_or(0).to_string())
            .with_attr(
                "link_speed_mbps",
                info.link_speed_mbps.unwrap_or(0).to_string(),
            )
            .with_attr(
                "supplicant_state",
                info.supplicant_state.as_deref().unwrap_or("-"),
            );
        e.add_evidence(ip_ev);
        result.push(e);
    }

    result
}

// ── GPS parsing ─────────────────────────────────────────────────────────

/// True if `(lat, lon)` is a usable geographic fix.
///
/// Rejects two failure modes a real `termux-location` payload can produce:
/// out-of-range values (`|lat| > 90`, `|lon| > 180`) from a malformed or
/// sensor-error response, and the `0.0, 0.0` "Null Island" sentinel that the
/// Android location stack emits when it has no actual fix but still returns a
/// (zeroed) object. Without this, either becomes a high-confidence
/// `Coordinates` entity and poisons the geolocation pipeline with a false
/// position.
///
/// Also rejects non-finite values (NaN/±inf) defensively.
///
/// Delegates to the canonical `util::geo::is_valid_coords` so on-device GPS
/// fixes are validated by exactly the same policy as the network-geo modules
/// (geo_intel, ip_whois_geo, cell_intel, wifi_intel, mylnikov).
fn is_valid_fix(lat: f64, lon: f64) -> bool {
    crate::util::geo::is_valid_coords(lat, lon)
}

/// Confidence for an on-device location fix.
///
/// The provider sets the ceiling — GPS (0.90) can reach metre/cm scale,
/// network (0.65) is tens-of-metres at best — and the device-reported
/// `accuracy_m` radius scales it down when the fix is imprecise, so a 2 km
/// "GPS" fix can't masquerade as a tight one. Accuracy of 0 / absent means
/// "unreported", not "perfect", so it leaves the provider ceiling untouched.
fn fix_confidence(provider: &str, accuracy_m: Option<f64>) -> f64 {
    let ceiling: f64 = if provider == "gps" { 0.90 } else { 0.65 };
    match accuracy_m {
        Some(a) if a > 0.0 => {
            let scaled = if a <= 20.0 {
                ceiling
            } else if a <= 100.0 {
                ceiling - 0.05
            } else if a <= 500.0 {
                ceiling - 0.15
            } else if a <= 2000.0 {
                ceiling - 0.25
            } else {
                ceiling - 0.35
            };
            scaled.clamp(0.30, 0.90)
        }
        _ => ceiling,
    }
}

fn parse_fix(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let fix: Fix = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    // Reject out-of-range / Null-Island / non-finite fixes before they become
    // a high-confidence Coordinates entity.
    if !is_valid_fix(fix.latitude, fix.longitude) {
        tracing::debug!(
            lat = fix.latitude,
            lon = fix.longitude,
            "device_sensors: rejecting invalid location fix"
        );
        return ModuleResult::new();
    }

    let provider = fix.provider.as_deref().unwrap_or("network");
    let confidence = fix_confidence(provider, fix.accuracy);
    let coords = format!("{:.7},{:.7}", fix.latitude, fix.longitude);

    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
    e.tag("geoint");
    e.tag("device-sensor");
    e.tag(format!("provider:{provider}"));
    if let Some(a) = fix.accuracy.filter(|a| *a > 0.0) {
        e.tag(format!("accuracy:{}m", a as u64));
    }
    e.add_evidence(
        Evidence::new(SRC, format!("Location fix via {provider}"))
            .with_attr("latitude", fix.latitude.to_string())
            .with_attr("longitude", fix.longitude.to_string())
            .with_attr("altitude", fix.altitude.unwrap_or(0.0).to_string())
            .with_attr("accuracy_m", fix.accuracy.unwrap_or(0.0).to_string())
            .with_attr("speed", fix.speed.unwrap_or(0.0).to_string())
            .with_attr("bearing", fix.bearing.unwrap_or(0.0).to_string())
            .with_attr("provider", provider),
    );

    let mut result = ModuleResult {
        entities: Vec::with_capacity(1),
    };
    result.push(e);
    result
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    // ── DeviceSensors trait tests ───────────────────────────────────

    #[test]
    fn is_passive() {
        assert!(DeviceSensors.is_passive());
    }

    #[test]
    fn accepts_only_local_physical_seeds() {
        // Engages on deliberately-local seeds…
        assert!(DeviceSensors.accepts(&Target::new(TargetKind::Coordinates, "-27.47,153.02")));
        assert!(DeviceSensors.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
        // …never attaches the operator's device data to a remote subject (MCS-A).
        assert!(!DeviceSensors.accepts(&Target::new(TargetKind::FullName, "Jane Doe")));
        assert!(!DeviceSensors.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!DeviceSensors.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(!DeviceSensors.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!DeviceSensors.accepts(&Target::new(TargetKind::Username, "user")));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(DeviceSensors.name(), "device_sensors");
        assert_eq!(DeviceSensors.priority(), 70);
    }

    #[test]
    fn max_timeout_is_20s() {
        assert_eq!(DeviceSensors.max_timeout_ms(), 20_000);
    }

    // ── WiFi parsing tests (from wifi_connect) ─────────────────────

    #[test]
    fn parses_connected_state() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","ip":"192.168.1.42",
            "frequency_mhz":2412,"rssi":-45,"link_speed_mbps":866,
            "supplicant_state":"COMPLETED"}"#;
        let r = parse_conn(json, "test");
        assert_eq!(r.entities.len(), 2); // MAC + IP
    }

    #[test]
    fn parses_disconnected_state() {
        let json = br#"{"bssid":"02:00:00:00:00:00","ssid":"<unknown ssid>","ip":"0.0.0.0",
            "supplicant_state":"DISCONNECTED"}"#;
        let r = parse_conn(json, "test");
        assert_eq!(r.entities.len(), 0); // both placeholders filtered
    }

    #[test]
    fn wifi_filters_all_zero_mac() {
        let json = br#"{"bssid":"00:00:00:00:00:00","ssid":"Test","ip":"10.0.0.1"}"#;
        let r = parse_conn(json, "test");
        // MAC filtered out, IP kept
        assert_eq!(r.entities.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::IpAddress);
    }

    #[test]
    fn wifi_band_classification() {
        assert_eq!(wifi_band(Some(2412)), Some("2.4GHz"));
        assert_eq!(wifi_band(Some(5180)), Some("5GHz"));
        assert_eq!(wifi_band(Some(5955)), Some("6GHz"));
        assert_eq!(wifi_band(Some(0)), None);
        assert_eq!(wifi_band(None), None);
        assert_eq!(wifi_band(Some(1234)), None);
    }

    #[test]
    fn connected_bssid_is_geolocatable_and_banded() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","ip":"192.168.1.42",
            "frequency_mhz":5180,"supplicant_state":"COMPLETED"}"#;
        let r = parse_conn(json, "test");
        let mac = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::MacAddress)
            .expect("BSSID entity");
        // Tagged for the wigle/mylnikov BSSID→coords pivot and banded.
        assert!(mac.has_tag("geolocatable"));
        assert!(mac.has_tag("band:5GHz"));
        assert_eq!(mac.evidence[0].attributes.get("band").unwrap(), "5GHz");
    }

    #[test]
    fn wifi_ssid_in_evidence() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"CafeNet","ip":"192.168.0.5",
            "frequency_mhz":5180,"rssi":-60,"link_speed_mbps":400,
            "supplicant_state":"COMPLETED"}"#;
        let r = parse_conn(json, "test");
        let mac_ev = &r.entities[0].evidence[0];
        assert_eq!(mac_ev.attributes.get("ssid").unwrap(), "CafeNet");
        assert_eq!(mac_ev.attributes.get("frequency_mhz").unwrap(), "5180");
    }

    #[test]
    fn wifi_evidence_source_is_device_sensors() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"Net","ip":"10.0.0.1"}"#;
        let r = parse_conn(json, "test");
        assert_eq!(r.entities[0].evidence[0].source, "device_sensors");
        assert_eq!(r.entities[1].evidence[0].source, "device_sensors");
    }

    // ── GPS parsing tests (from gps_fix) ────────────────────────────

    #[test]
    fn network_fix_gets_lower_confidence() {
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":12.5,
            "provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities.len(), 1);
        assert!((r.entities[0].confidence - 0.65).abs() < 1e-6);
    }

    #[test]
    fn gps_fix_gets_higher_confidence() {
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":2.0,
            "provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!((r.entities[0].confidence - 0.90).abs() < 1e-6);
    }

    #[test]
    fn coordinate_value_is_fixed_precision() {
        let json = br#"{"latitude":-27.469824123,"longitude":153.025198765,
            "provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities[0].value, "-27.469824,153.025199");
    }

    #[test]
    fn entity_tags_and_kind() {
        let json = br#"{"latitude":51.5074,"longitude":-0.1278,"provider":"network"}"#;
        let r = parse_fix(json, "scan-gps");
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("geoint"));
        assert!(e.has_tag("provider:network"));
        assert_eq!(e.scan_id, "scan-gps");
    }

    #[test]
    fn gps_provider_tag() {
        // Use a real coordinate — 0,0 is now rejected as Null Island.
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!(r.entities[0].has_tag("provider:gps"));
        assert!(r.entities[0].has_tag("device-sensor"));
    }

    #[tokio::test]
    async fn fetch_fix_is_empty_off_device() {
        // Off-device (no termux-location binary), fetch_fix returns empty —
        // which is exactly the signal process() uses to fall back from the
        // GPS provider to the network provider. Proves the fallback trigger
        // is wired without requiring a device.
        let r = fetch_fix("gps", 1000, "test").await;
        assert!(r.entities.is_empty());
    }

    #[test]
    fn null_island_rejected() {
        // The Android location stack returns 0,0 when it has no real fix.
        let json = br#"{"latitude":0.0,"longitude":0.0,"provider":"gps"}"#;
        assert_eq!(parse_fix(json, "test").entities.len(), 0);
    }

    #[test]
    fn out_of_range_coords_rejected() {
        for json in [
            &br#"{"latitude":91.0,"longitude":10.0}"#[..],
            &br#"{"latitude":-90.1,"longitude":10.0}"#[..],
            &br#"{"latitude":10.0,"longitude":181.0}"#[..],
            &br#"{"latitude":10.0,"longitude":-180.5}"#[..],
        ] {
            assert_eq!(
                parse_fix(json, "test").entities.len(),
                0,
                "out-of-range fix must be rejected: {}",
                String::from_utf8_lossy(json)
            );
        }
    }

    #[test]
    fn boundary_coords_accepted() {
        // Exact poles / antimeridian are valid.
        let json = br#"{"latitude":90.0,"longitude":180.0,"provider":"gps"}"#;
        assert_eq!(parse_fix(json, "test").entities.len(), 1);
    }

    #[test]
    fn accuracy_scales_confidence_below_provider_ceiling() {
        // A wide-radius "gps" fix must score below a tight one.
        let tight = br#"{"latitude":-27.47,"longitude":153.02,"accuracy":5.0,"provider":"gps"}"#;
        let wide = br#"{"latitude":-27.47,"longitude":153.02,"accuracy":3000.0,"provider":"gps"}"#;
        let ct = parse_fix(tight, "t").entities[0].confidence;
        let cw = parse_fix(wide, "t").entities[0].confidence;
        assert!(
            (ct - 0.90).abs() < 1e-6,
            "tight gps fix keeps ceiling: {ct}"
        );
        assert!(cw < ct, "wide fix ({cw}) must score below tight ({ct})");
        assert!(cw >= 0.30, "confidence floored: {cw}");
    }

    #[test]
    fn accuracy_tag_emitted() {
        let json = br#"{"latitude":-27.47,"longitude":153.02,"accuracy":42.0,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!(r.entities[0].has_tag("accuracy:42m"));
    }

    #[test]
    fn evidence_attributes_populated() {
        let json = br#"{"latitude":37.7749,"longitude":-122.4194,"altitude":15.5,
            "accuracy":8.2,"speed":1.5,"bearing":90.0,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.source, "device_sensors");
        assert_eq!(ev.attributes.get("latitude").unwrap(), "37.7749");
        assert_eq!(ev.attributes.get("longitude").unwrap(), "-122.4194");
        assert_eq!(ev.attributes.get("altitude").unwrap(), "15.5");
        assert_eq!(ev.attributes.get("accuracy_m").unwrap(), "8.2");
        assert_eq!(ev.attributes.get("speed").unwrap(), "1.5");
        assert_eq!(ev.attributes.get("bearing").unwrap(), "90");
        assert_eq!(ev.attributes.get("provider").unwrap(), "gps");
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let json = br#"{"latitude":10.0,"longitude":20.0}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        // Missing provider defaults to "network"
        assert_eq!(ev.attributes.get("provider").unwrap(), "network");
        assert_eq!(ev.attributes.get("altitude").unwrap(), "0");
        assert_eq!(ev.attributes.get("accuracy_m").unwrap(), "0");
        assert_eq!(ev.attributes.get("speed").unwrap(), "0");
        assert_eq!(ev.attributes.get("bearing").unwrap(), "0");
        // Missing provider means network confidence
        assert!((r.entities[0].confidence - 0.65).abs() < 1e-6);
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_fix(b"not json at all", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn empty_object_fails_missing_required_fields() {
        let r = parse_fix(b"{}", "test");
        // latitude and longitude are required (f64, not Option), so {} should fail deserialization
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn negative_coordinates_handled() {
        let json = br#"{"latitude":-33.8688,"longitude":151.2093,"provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities[0].value, "-33.868800,151.209300");
    }
}
