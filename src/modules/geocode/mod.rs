//! Bidirectional geocoding via OpenStreetMap Nominatim.
//!
//! Merges forward (Address → Coordinates) and reverse (Coordinates → Address)
//! geocoding into a single module.  The process() method dispatches based on
//! target kind:
//!
//!   * `TargetKind::Address`     → forward geocode (Nominatim /search)
//!   * `TargetKind::Coordinates` → reverse geocode (Nominatim /reverse)
//!
//! Free, no API key.  Nominatim usage policy: max 1 request per second,
//! must include a valid User-Agent identifying the application.

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

// ── Nominatim response types (forward) ──────────────────────────────

#[derive(Deserialize)]
pub(super) struct NominatimResult {
    #[serde(default)]
    pub(super) lat: Option<String>,
    #[serde(default)]
    pub(super) lon: Option<String>,
    #[serde(default)]
    pub(super) display_name: Option<String>,
    #[serde(default, rename = "type")]
    pub(super) place_type: Option<String>,
    /// Only populated when the request carries `addressdetails=1` (the forward
    /// `/search` call always sets it) — same shared shape as the reverse
    /// `/reverse` response, folded via [`fold_address_attrs`].
    #[serde(default)]
    pub(super) address: Option<NominatimAddr>,
}

// ── Nominatim response types (reverse) ──────────────────────────────

#[derive(Deserialize)]
pub(super) struct NominatimResp {
    pub(super) display_name: Option<String>,
    pub(super) address: Option<NominatimAddr>,
}

#[derive(Deserialize)]
pub(super) struct NominatimAddr {
    pub(super) road: Option<String>,
    pub(super) house_number: Option<String>,
    pub(super) suburb: Option<String>,
    pub(super) city: Option<String>,
    pub(super) town: Option<String>,
    pub(super) village: Option<String>,
    pub(super) municipality: Option<String>,
    pub(super) county: Option<String>,
    pub(super) state: Option<String>,
    pub(super) postcode: Option<String>,
    pub(super) country: Option<String>,
    pub(super) country_code: Option<String>,
}

// ── Module ──────────────────────────────────────────────────────────

pub(super) const SRC: &str = "geocode";

/// Returned when Nominatim answers 2xx with a body that will not decode AND the
/// curl fallback also fails to produce one.
///
/// A `const`, not a `format!`, and deliberately so — see the call site: the
/// serde message would both trip the engine's text-matched rate-limit heuristic
/// and quote the response body into a persisted event.
const UNDECODABLE_MSG: &str = "Nominatim returned a success status whose body did not decode, and the curl fallback did not produce a usable answer either";

/// Returned when neither transport answered at all.
const NO_ANSWER_MSG: &str =
    "Nominatim did not answer and the curl fallback did not produce a usable answer either";

pub struct Geocode;

#[async_trait]
impl Module for Geocode {
    fn name(&self) -> &'static str {
        "geocode"
    }

    fn description(&self) -> &'static str {
        "Bidirectional geocoding via OpenStreetMap Nominatim — resolves Address ↔ Coordinates both ways"
    }

    fn priority(&self) -> u8 {
        21
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address | TargetKind::Coordinates)
    }

    fn category(&self) -> ModuleCategory {
        // The module does exactly one thing bidirectionally: resolve
        // Address↔Coordinates via OSM Nominatim, producing Coordinates/Address
        // entities with street/suburb/city/state/postcode/country evidence — a
        // direct, tight fit for "Determine Physical Locations." It touches no
        // DNS/WHOIS/certificate/CDN/scan database (Nominatim is a geocoding
        // lookup, not one of the T1596 technical-database subtypes), no
        // identity/employee/network data, so no additional technique is
        // implicated.
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates, EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        match target.kind {
            TargetKind::Address => self.forward(target, ctx).await,
            TargetKind::Coordinates => self.reverse(target, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Geocode {
    // ── Forward geocode: Address → Coordinates ──────────────────────

    async fn forward(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let addr = target.value.trim();
        if addr.is_empty() || addr.len() <= 2 {
            return Ok(ModuleResult::new());
        }
        // A bare country name geocodes to the country CENTROID — the middle of
        // the whole nation, not the subject's location — yet it arrives as a
        // precise-looking fix and cascades into the geo-convergence rules (a
        // coarse carrier-country signal inventing a street-level location, as a
        // live +61 phone scan reproduced). Refuse to mint a coordinate from it;
        // a finer address (street / suburb / comma-qualified) still geocodes.
        if crate::util::place_grain::is_bare_country(addr) {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://nominatim.openstreetmap.org/search?q={}&format=json&limit=1&addressdetails=1",
            urlencode(addr)
        );

        let resp = ctx
            .http
            .get(&url)
            .header(
                "User-Agent",
                "huntsman-search-engine/1.0 (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)",
            )
            .send()
            .await;

        // The `reverse` leg below already gets this right — `send_tagged` + `?`, an
        // explicit status check, and a `map_err` on the decode. This leg, in the
        // same module, used `unwrap_or_default()` on BOTH decodes and
        // `Ok(ModuleResult::new())` when the fallback found nothing, so provider
        // drift, a throttle and a total outage all arrived as "this address does
        // not geocode" — a substantive negative about the subject's location.
        //
        // The curl fallback is deliberate and kept: Nominatim throttles the
        // shared client hard enough that a second transport genuinely rescues
        // the answer. What changes is only what happens when it does not.
        //
        // The line drawn here is decode-SUCCESS-with-zero-results (Nominatim
        // answering `[]` for an address it cannot place — a real negative, and
        // the common case) versus decode-FAILURE (a WAF interstitial or a schema
        // change — not an answer at all). Same distinction as opencellid's
        // 404-versus-401.
        let results: Vec<NominatimResult> = match resp {
            Ok(r) if r.status().is_success() => {
                match crate::util::http::json_scanned::<Vec<NominatimResult>>(r, SRC).await {
                    Ok(v) => v,
                    // A clean 2xx whose body will not parse: try the other
                    // transport before concluding anything, then fail closed.
                    //
                    // The serde message is deliberately NOT interpolated, for two
                    // separate reasons. Its Display ends "at line 1 column N", and
                    // the engine classifies module errors by TEXT — `is_rate_limited`
                    // splits on non-alphanumerics and matches the bare tokens `429`
                    // and `402`, so a decode failure at column 429 would trip a
                    // 600-second rate-limit cooldown on a schema-drift coincidence.
                    // And serde's `invalid type` errors quote the offending VALUE,
                    // which lands in a `ModuleError` event persisted to the events
                    // table; `json_scanned` is also the one JSON helper that does not
                    // run `redact_credentials`. The decode error is still visible in
                    // the log via `json_scanned` itself.
                    Err(_) => forward_via_curl(&url)
                        .await
                        .ok_or_else(|| Error::module(SRC, UNDECODABLE_MSG))?,
                }
            }
            // Transport error or a non-success status. Deliberately does NOT
            // format the `reqwest::Error`: its Display embeds the request URL,
            // which here carries the searched address.
            _ => forward_via_curl(&url)
                .await
                .ok_or_else(|| Error::module(SRC, NO_ANSWER_MSG))?,
        };

        let mut result = ModuleResult::new();

        if let Some(first) = results.first()
            && let (Some(lat_str), Some(lon_str)) = (&first.lat, &first.lon)
            && let (Ok(lat), Ok(lon)) = (lat_str.parse::<f64>(), lon_str.parse::<f64>())
            && crate::util::geo::is_valid_coords(lat, lon)
        {
            let coords = format!("{lat:.6},{lon:.6}");
            let mut e =
                build_forward_entity(lat, lon, &coords, first.address.as_ref(), &ctx.scan_id);
            let mut ev = Evidence::new(SRC, format!("Geocoded \"{addr}\" \u{2192} {coords}"))
                .with_attr("input_address", addr)
                .with_attr("latitude", lat_str)
                .with_attr("longitude", lon_str);
            if let Some(dn) = &first.display_name {
                ev = ev.with_attr("display_name", dn);
            }
            if let Some(pt) = &first.place_type {
                ev = ev.with_attr("place_type", pt);
            }
            if let Some(addr) = &first.address {
                ev = fold_address_attrs(ev, addr);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        Ok(result)
    }

    // ── Reverse geocode: Coordinates → Address ──────────────────────

    async fn reverse(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let (lat, lon) = crate::util::geo::parse_coords(&target.value)?;

        let url = format!(
            "https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}&zoom=18&addressdetails=1"
        );

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged("geocode")
            .await?;

        if !resp.status().is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let data: NominatimResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result.push(build_reverse_entity(lat, lon, &data, &ctx.scan_id));
        Ok(result)
    }
}

/// The fallback transport for the forward leg: fetch through `curl` and decode.
///
/// `Some` only on a SUCCESSFUL decode — `None` covers both "curl could not
/// reach Nominatim" and "curl returned something that is not a Nominatim
/// response". Collapsing those two into one `None` is deliberate: the caller
/// treats either as "the fallback did not answer", and neither is evidence
/// about the address itself.
///
/// Note that an empty result list is `Some(vec![])`, NOT `None`. Nominatim
/// answering `[]` is a real, decodable negative about an address it cannot
/// place, and must stay distinguishable from a transport or parse failure.
async fn forward_via_curl(url: &str) -> Option<Vec<NominatimResult>> {
    let body = crate::util::curl::fetch(url, crate::MODULE_TIMEOUT_MS).await?;
    decode_forward_body(&body)
}

/// The decode half of [`forward_via_curl`], split out so the `Some`/`None`
/// boundary is unit-testable without spawning curl.
///
/// This is the boundary the whole fail-closed change turns on: `Some(vec![])`
/// for a decodable empty answer (a real negative about the address) versus
/// `None` for a body that is not a Nominatim response at all.
fn decode_forward_body(body: &str) -> Option<Vec<NominatimResult>> {
    serde_json::from_str(body).ok()
}

/// Build the forward-geocode Coordinates entity, shaping confidence and tags by
/// AU relevance of the resolved point via [`au_relevance`] — the same
/// country-code-first classification `build_reverse_entity` uses, rather than
/// the offline [`crate::util::geo::is_in_australia`] bounding box alone.
/// Regression: the box is deliberately coarse and has a known false-positive
/// band (e.g. Rote Island/West Timor, Indonesia) that it misreads as Western
/// Australia; Nominatim's own `address.country_code` is authoritative when
/// present and must win over the box, exactly as the reverse leg already does.
/// A fix classified `InAustralia` is a strong on-region anchor
/// (confidence::HIGH_PLUS, `au-relevant`); anything else (a genuinely
/// off-region country, or no country code and outside the box) is demoted to
/// a candidate (confidence::LOW, `off-region` + `candidate`) so it sits below
/// the confidence::MEDIUM expansion floor and is quarantined from confirmed
/// correlations — an ambiguous address string can't drag an AU-focused scan
/// off-region. Pure (no I/O); the caller attaches evidence.
#[must_use]
pub(super) fn build_forward_entity(
    lat: f64,
    lon: f64,
    coords: &str,
    addr: Option<&NominatimAddr>,
    scan_id: &str,
) -> Entity {
    let in_au = au_relevance(lat, lon, addr) == AuRelevance::InAustralia;
    let confidence = if in_au {
        confidence::HIGH_PLUS
    } else {
        confidence::LOW
    };
    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
    e.tag("geocoded");
    if in_au {
        e.tag("au-relevant");
        if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
            e.tag(format!("au-state:{state}"));
        }
    } else {
        e.tag("off-region");
        e.tag("candidate");
    }
    e
}

/// AU-relevance verdict for a reverse-geocoded coordinate, deciding how much an
/// off-region fix may anchor an Australia-focused scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuRelevance {
    /// Resolved in Australia (by Nominatim country code, or by bounding box when
    /// the code is absent) — a strong, on-region anchor.
    InAustralia,
    /// Resolved to a known country that is not Australia — a candidate-grade
    /// lead that AU-focused correlation rules (confidence ≥ confidence::MEDIUM) must not
    /// anchor on, so it can't pull an investigation off-region.
    OffRegion,
    /// Region could not be determined (no country code, not in the AU box) —
    /// kept at a neutral, middling confidence.
    Unknown,
}

/// Classify a reverse-geocoded fix for AU relevance. The Nominatim country code
/// is authoritative when present; otherwise we fall back to the offline
/// [`crate::util::geo::is_in_australia`] bounding box so a bare coordinate seed
/// is still gated.
pub(super) fn au_relevance(lat: f64, lon: f64, addr: Option<&NominatimAddr>) -> AuRelevance {
    match addr.and_then(|a| a.country_code.as_deref()) {
        Some(cc) if cc.eq_ignore_ascii_case("au") => AuRelevance::InAustralia,
        Some(_) => AuRelevance::OffRegion,
        None if crate::util::geo::is_in_australia(lat, lon) => AuRelevance::InAustralia,
        None => AuRelevance::Unknown,
    }
}

/// Build the reverse-geocode Address entity, shaping confidence and tags by
/// [`au_relevance`]. Pure (no I/O) so the AU-gating is unit-tested directly.
#[must_use]
pub(super) fn build_reverse_entity(
    lat: f64,
    lon: f64,
    data: &NominatimResp,
    scan_id: &str,
) -> Entity {
    let display = data.display_name.as_deref().unwrap_or("-");
    let relevance = au_relevance(lat, lon, data.address.as_ref());

    let confidence = match relevance {
        AuRelevance::InAustralia => confidence::STRONG,
        AuRelevance::Unknown => confidence::MEDIUM_HIGH,
        AuRelevance::OffRegion => confidence::LOW,
    };

    let mut entity = Entity::new(EntityKind::Address, display, confidence, scan_id);
    entity.tag("geoint");
    entity.tag("reverse-geocoded");
    match relevance {
        AuRelevance::InAustralia => {
            entity.tag("country:AU");
            entity.tag("au-relevant");
            if let Some(state) = crate::util::geo::au_state_for_coords(lat, lon) {
                entity.tag(format!("au-state:{state}"));
            }
        }
        AuRelevance::OffRegion => entity.tag("candidate"),
        AuRelevance::Unknown => {}
    }

    let mut ev = Evidence::new(SRC, format!("Reverse geocode for {lat},{lon}"))
        .with_attr("latitude", lat.to_string())
        .with_attr("longitude", lon.to_string())
        .with_attr("source", "OpenStreetMap Nominatim");

    if let Some(addr) = &data.address {
        ev = fold_address_attrs(ev, addr);
        // The on-region `country:AU` tag is set above; for off-region fixes
        // record the resolved country so the lead stays explainable.
        if let Some(cc) = addr.country_code.as_deref()
            && !cc.eq_ignore_ascii_case("au")
        {
            entity.tag(format!("country:{}", cc.to_uppercase()));
        }
    }

    entity.add_evidence(ev);
    entity
}

/// Fold a Nominatim `address` breakdown (city/state/country/postcode/street/
/// suburb/county) into evidence attributes. Shared by both the forward
/// (`/search?addressdetails=1`) and reverse (`/reverse?addressdetails=1`)
/// geocode paths so a structured address hit is reported identically
/// regardless of which direction produced it — single-sourced, not
/// hand-duplicated per call site. Pure (no I/O), directly unit-tested.
pub(super) fn fold_address_attrs(mut ev: Evidence, addr: &NominatimAddr) -> Evidence {
    let city = addr
        .city
        .as_deref()
        .or(addr.town.as_deref())
        .or(addr.village.as_deref())
        .or(addr.municipality.as_deref());

    if let Some(c) = city {
        ev = ev.with_attr("city", c);
    }
    if let Some(s) = addr.state.as_deref() {
        ev = ev.with_attr("state", s);
    }
    if let Some(c) = addr.country.as_deref() {
        ev = ev.with_attr("country", c);
    }
    if let Some(cc) = addr.country_code.as_deref() {
        ev = ev.with_attr("country_code", cc.to_uppercase());
    }
    if let Some(p) = addr.postcode.as_deref() {
        ev = ev.with_attr("postcode", p);
    }
    if let Some(r) = addr.road.as_deref() {
        let street = match addr.house_number.as_deref() {
            Some(n) => format!("{n} {r}"),
            None => r.to_string(),
        };
        ev = ev.with_attr("street", street);
    }
    if let Some(sub) = addr.suburb.as_deref() {
        ev = ev.with_attr("suburb", sub);
    }
    if let Some(county) = addr.county.as_deref() {
        ev = ev.with_attr("county", county);
    }
    ev
}
