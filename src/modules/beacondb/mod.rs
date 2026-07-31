//! beaconDB — free BSSID-to-coordinates resolution. **No API key.**
//!
//! Endpoint: `POST https://beacondb.net/v1/geolocate`
//!
//! The public-domain successor to Mozilla Location Services (retired 2024),
//! speaking the same MLS/Google Geolocation request shape. It exists here
//! because the radar's BSSID→location capability had quietly gone to zero: the
//! keyed provider (`wigle`) answers 429 once its daily allowance is spent, and
//! the keyless one (`mylnikov`) has been returning HTTP 523 — its origin is
//! unreachable, not merely slow. Both were observed failing in the same live
//! `hse radar` session, which left an observed access point resolvable to
//! nothing. This module needs no credential, so it works on a fresh install
//! with no configuration.
//!
//! ## The IP-fallback trap — why [`CONSIDER_IP`] is not optional
//!
//! beaconDB documents a fallback chain: a wifi fix if it has one, else an
//! approximate cell-tower position from the final MLS data dump, else **an
//! IP-based estimate of the caller**. That last one is the dangerous case. Live
//! against this endpoint, a query for two BSSIDs it has never seen returned
//! `HTTP 200` with a perfectly well-formed position — which was the *scanner's
//! own egress IP*, 25 km wide, on another continent from the access points:
//!
//! ```text
//! {"accuracy":25000,"fallback":"ipf","location":{"lat":37.7901,"lng":-122.401}}
//! ```
//!
//! Consumed naively that is a fabricated finding of the worst kind: it reports
//! where the *operator* is as though it were where the *target* is, at a
//! confidence the accuracy radius alone would not flag. So every request pins
//! `considerIp:false`, which turns that same query into a clean `404
//! notFound` (verified live), and the decoder additionally rejects any response
//! carrying a `fallback` marker whatever its value. The two guards are
//! deliberately redundant: one is a request the server must honour, the other
//! holds even if it does not.
//!
//! Coverage is crowd-sourced and self-described as experimental, so a miss is
//! ordinary and returns an empty result rather than an error.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::{confidence_for_accuracy_m, is_valid_coords};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "beacondb";

const ENDPOINT: &str = "https://beacondb.net/v1/geolocate";

/// Sent as `considerIp` on every request, and never `true`. See this module's
/// header: with IP fallback enabled, an unknown BSSID resolves to the caller's
/// own location instead of failing, which would publish the operator's position
/// as the target's.
const CONSIDER_IP: bool = false;

pub struct BeaconDb;

/// A geolocate response. `fallback` is present only when the server answered
/// from something other than the wireless data we asked about.
#[derive(Deserialize)]
struct GeolocateResp {
    #[serde(default)]
    location: Option<Location>,
    #[serde(default)]
    accuracy: Option<f64>,
    /// `"ipf"` for an IP-derived estimate, or a cell-fallback marker. Any value
    /// here means the answer is not a BSSID fix. Kept as a free-form `String`
    /// rather than an enum so an unrecognised future marker still disqualifies
    /// the response instead of deserialising to "no fallback".
    #[serde(default)]
    fallback: Option<String>,
}

#[derive(Deserialize)]
struct Location {
    #[serde(default)]
    lat: Option<f64>,
    /// beaconDB follows the Google/MLS shape, which spells longitude `lng`.
    #[serde(default)]
    lng: Option<f64>,
}

/// Build the BSSID-location entity from a decoded response. **Pure** (no
/// network/IO). Returns `None` — an honest "no fix", not an error — when:
///
/// * the answer carries a `fallback` marker (it describes the caller or a
///   cell tower, not this access point);
/// * the position is missing a component; or
/// * the coordinates fail the shared validator (Null Island, out of range,
///   non-finite).
fn build_location_entity(bssid: &str, resp: &GeolocateResp, scan_id: &str) -> Option<Entity> {
    if let Some(kind) = resp.fallback.as_deref() {
        // Not an error: the server answered honestly, it just answered a
        // different question than the one asked.
        tracing::debug!(
            bssid,
            fallback = kind,
            "beacondb: discarding non-wireless fallback fix"
        );
        return None;
    }
    let loc = resp.location.as_ref()?;
    let (lat, lon) = (loc.lat?, loc.lng?);
    if !is_valid_coords(lat, lon) {
        return None;
    }

    let coords = format!("{lat:.6},{lon:.6}");
    let mut e = Entity::new(
        EntityKind::Coordinates,
        &coords,
        confidence_for_accuracy_m(resp.accuracy),
        scan_id,
    );
    e.tag("beacondb");
    e.tag("geoint");
    e.tag("bssid-located");
    crate::util::geo::tag_au_state(&mut e, lat, lon);

    let mut ev = Evidence::new(SRC, format!("beaconDB BSSID {bssid} -> {coords}"))
        .with_attr("bssid", bssid)
        .with_attr("latitude", format!("{lat:.6}"))
        .with_attr("longitude", format!("{lon:.6}"));
    if let Some(accuracy) = resp.accuracy {
        ev = ev.with_attr("accuracy_m", format!("{accuracy:.0}"));
    }
    e.add_evidence(ev);
    Some(e)
}

#[async_trait]
impl Module for BeaconDb {
    fn name(&self) -> &'static str {
        "beacondb"
    }
    fn description(&self) -> &'static str {
        "beaconDB WiFi geolocation — resolves a BSSID to coordinates (free, no key)"
    }
    fn priority(&self) -> u8 {
        // Peer of `mylnikov`: the same question, the same cost, no credential.
        17
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::MacAddress)
    }
    fn max_timeout_ms(&self) -> u64 {
        // One request, but above the 3s default `MODULE_TIMEOUT_MS`: at the
        // default the engine kills a slow-but-connected response as a spurious
        // timeout before the fix can return (the defect `mylnikov` shipped).
        10_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
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

        let resp = ctx
            .http
            .post(ENDPOINT)
            .json(&serde_json::json!({
                "considerIp": CONSIDER_IP,
                "wifiAccessPoints": [{ "macAddress": bssid }],
            }))
            .send_tagged(SRC)
            .await?;

        // 404 is this API's documented "no location could be estimated" — the
        // ordinary outcome for a BSSID outside a crowd-sourced corpus, and a
        // clean empty result rather than a module error.
        if resp.status().as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !resp.status().is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let body: GeolocateResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        if let Some(e) = build_location_entity(bssid, &body, &ctx.scan_id) {
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
