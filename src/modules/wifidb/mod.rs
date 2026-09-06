//! WiFiDB — free, keyless BSSID-to-coordinates wardriving corpus.
//!
//! Endpoint: `GET https://wifidb.net/api/geojson.php?func=exp_search&mac=<BSSID>`.
//! No API key, no auth header. The response is a GeoJSON `FeatureCollection`;
//! each `features[]` entry for the queried BSSID carries
//! `geometry.coordinates = [lon, lat]` (GeoJSON order) plus corroborating
//! `properties` (ssid, manuf, radio, chan, auth, encry, `fa`/`la` first/last-seen,
//! user). Contract verified live against a real response (2026-09):
//! `mac=00:13:10:69:EF:11` → HTTP 200 GeoJSON with a real
//! `geometry.coordinates` and ssid `cryptic24g`.
//!
//! This is HSE's **first keyless wardriving corpus**, sitting beside keyed WiGLE
//! (`wigle`/`wifi_intel`) and the keyless `mylnikov`/`beacondb` BSSID lookups —
//! the same independent-free-corpus pattern the codebase already uses. It answers
//! the WiGLE question ("where has this access point been observed?") with no
//! account or key, so a WiGLE-quota exhaustion or miss still leaves the radar a
//! way to locate an observed AP.
//!
//! Precision + honesty: it emits a `Coordinates` fix ONLY for a feature whose
//! `mac` matches the queried BSSID and whose lat/lon pass the shared
//! [`crate::util::geo::is_valid_coords`] validator (Null Island / out-of-range /
//! non-finite rejected), exactly as `mylnikov` does. An empty FeatureCollection
//! is a clean negative; a non-2xx/outage is a real `ModuleError`, never a false
//! "no location". WiFiDB publishes no per-record public page, so no URL is
//! fabricated. The documented `ssid=` selector is intentionally not wired — it
//! returned an unbounded result on live test (RULE.md: only verified shapes).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::is_valid_coords;
use crate::util::http::{fetch_json_or_404, urlencode};

/// Stable evidence-source string.
pub(crate) const SRC: &str = "wifidb";

/// A GeoJSON `FeatureCollection`. Every field optional/defaulted so a schema
/// change never fails the whole parse into a false miss.
#[derive(Deserialize, Default)]
#[serde(default)]
struct FeatureCollection {
    features: Vec<Feature>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Feature {
    geometry: Option<Geometry>,
    properties: Option<Props>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Geometry {
    /// GeoJSON `[longitude, latitude]`.
    coordinates: Option<Vec<f64>>,
}

/// The corroborating WiFiDB record fields (all string-typed in the live JSON).
#[derive(Deserialize, Default)]
#[serde(default)]
struct Props {
    mac: Option<String>,
    ssid: Option<String>,
    manuf: Option<String>,
    chan: Option<String>,
    radio: Option<String>,
    auth: Option<String>,
    encry: Option<String>,
    /// First-seen timestamp.
    fa: Option<String>,
    /// Last-seen timestamp.
    la: Option<String>,
    /// Fallback lat/lon (strings), used when `geometry.coordinates` is absent.
    lat: Option<String>,
    lon: Option<String>,
}

/// WiFiDB keyless BSSID → coordinates wardriving module.
pub struct WifiDb;

#[async_trait]
impl Module for WifiDb {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "WiFiDB wardriving lookup — keyless BSSID → coordinates, a free WiGLE alternative"
    }

    fn priority(&self) -> u8 {
        // Same BSSID-geolocation tier as the other keyless corpora (mylnikov).
        17
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Queries a crowdsourced open technical database (WiGLE/OpenCelliD-like)
        // to resolve a BSSID to Coordinates — the same mapping `mylnikov` uses:
        // the Geo category default (T1591.001) plus T1596 for the named-DB
        // mechanism, stopping at the parent.
        &["T1591.001", "T1596"]
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let bssid = target.value.trim();
        if bssid.len() < 12 {
            return Ok(ModuleResult::new());
        }
        let url = format!(
            "https://wifidb.net/api/geojson.php?func=exp_search&mac={}",
            urlencode(bssid)
        );
        // 404 → clean miss; any other non-2xx → real ModuleError (fail-closed).
        let Some(fc): Option<FeatureCollection> = fetch_json_or_404(&ctx.http, SRC, &url).await?
        else {
            return Ok(ModuleResult::new());
        };
        Ok(build_result(&fc, bssid, &ctx.scan_id))
    }
}

/// Extract a `(lat, lon)` pair from a feature — preferring GeoJSON
/// `geometry.coordinates` (`[lon, lat]`), falling back to the string
/// `properties.lat`/`lon`.
fn feature_coords(f: &Feature) -> Option<(f64, f64)> {
    if let Some(c) = f.geometry.as_ref().and_then(|g| g.coordinates.as_ref())
        && c.len() >= 2
        && c[0].is_finite()
        && c[1].is_finite()
    {
        // GeoJSON is [lon, lat].
        return Some((c[1], c[0]));
    }
    let p = f.properties.as_ref()?;
    let lat = p.lat.as_deref()?.trim().parse::<f64>().ok()?;
    let lon = p.lon.as_deref()?.trim().parse::<f64>().ok()?;
    Some((lat, lon))
}

/// Build the BSSID-location entity from the FeatureCollection. Pure of I/O so it
/// is unit-tested against fixtures. Emits one `Coordinates` fix from the first
/// feature that (a) reports the queried BSSID and (b) carries in-range
/// coordinates — WiFiDB may hold many sightings of one AP clustered at a place;
/// the first valid one is the representative fix.
fn build_result(fc: &FeatureCollection, bssid: &str, scan_id: &str) -> ModuleResult {
    let mut result = ModuleResult::new();

    for f in &fc.features {
        // Precision guard: emit a fix ONLY for a feature that positively
        // reports the queried BSSID. The search is by mac so this should always
        // hold; a feature whose `mac` is absent (or mismatched) cannot be
        // confirmed to be this AP, so it is skipped rather than located on
        // coordinates alone — never attribute a location we cannot tie to the
        // queried BSSID.
        let matches_bssid = f
            .properties
            .as_ref()
            .and_then(|p| p.mac.as_deref())
            .is_some_and(|mac| mac.trim().eq_ignore_ascii_case(bssid));
        if !matches_bssid {
            continue;
        }
        let Some((lat, lon)) = feature_coords(f) else {
            continue;
        };
        if !is_valid_coords(lat, lon) {
            continue;
        }

        let coords = format!("{lat:.6},{lon:.6}");
        let mut e = Entity::new(EntityKind::Coordinates, &coords, confidence::HIGH, scan_id);
        e.tag(SRC);
        e.tag("geoint");
        e.tag("bssid-located");
        crate::util::geo::tag_au_state(&mut e, lat, lon);

        let p = f.properties.as_ref();
        let ev = Evidence::new(SRC, format!("WiFiDB BSSID {bssid} -> {coords}"))
            .with_attr("bssid", bssid)
            .with_attr("latitude", format!("{lat:.6}"))
            .with_attr("longitude", format!("{lon:.6}"))
            .with_optional_attrs([
                ("ssid", p.and_then(|p| p.ssid.as_deref())),
                ("manuf", p.and_then(|p| p.manuf.as_deref())),
                ("channel", p.and_then(|p| p.chan.as_deref())),
                ("radio", p.and_then(|p| p.radio.as_deref())),
                ("auth", p.and_then(|p| p.auth.as_deref())),
                ("encryption", p.and_then(|p| p.encry.as_deref())),
                ("first_seen", p.and_then(|p| p.fa.as_deref())),
                ("last_seen", p.and_then(|p| p.la.as_deref())),
            ]);
        e.add_evidence(ev);
        result.push(e);
        // One representative fix per BSSID.
        break;
    }

    result
}

#[cfg(test)]
mod tests;
