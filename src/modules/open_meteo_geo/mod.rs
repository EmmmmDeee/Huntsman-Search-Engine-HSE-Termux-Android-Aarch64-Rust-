//! Open-Meteo Geocoding — free, keyless place-name → coordinates with rich
//! GEOINT enrichment.
//!
//! Endpoint: `GET https://geocoding-api.open-meteo.com/v1/search?name={q}` — the
//! GeoNames-backed geocoder Open-Meteo exposes without a key. It is the third
//! independent forward geocoder in the tree, alongside `geocode` (OSM Nominatim)
//! and `photon` (Komoot), and HSE's design deliberately runs several free corpora
//! against the same question so an outage or a miss in one still leaves an answer
//! (the `beacondb` + `mylnikov` precedent).
//!
//! What makes it *additive* rather than redundant: it returns signals the two
//! street-address geocoders do not — the place's **IANA timezone** (a
//! people-centric geolocation signal that corroborates `breach_timezone`), its
//! **population** and GeoNames **feature code** (which classify *what kind* of
//! place matched — a national capital vs a hamlet), **elevation**, and the
//! administrative hierarchy + postcodes. It resolves the coarse, city-level
//! locations people self-report on social profiles ("Golden, CO", "London, UK")
//! particularly well — exactly the `Address` entities `social_location`,
//! `gravatar`, and the developer-profile modules emit — turning a self-reported
//! string into a coordinate the whole geo-correlation stack can then anchor on.
//!
//! Regional weighting mirrors `geocode`: a match inside the Australian bounding
//! box is a strong on-region anchor ([`confidence::HIGH_PLUS`], `au-relevant`);
//! one abroad, and every ambiguous alternate, is demoted to a `candidate` below
//! the expansion floor so it is retained as a lead without driving expansion.
//!
//! Honesty discipline (Operational Constitution): a name search is inherently
//! ambiguous (many "Springfield"s), so only the best match is emitted with
//! weight; the rest are explicit `candidate`s. Every enrichment attribute is
//! written only when the provider actually returns it — never fabricated.
//! Keyless, one JSON GET per target, Termux-friendly.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::geo::{au_state_for_coords, is_in_australia, is_valid_coords};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "open_meteo_geo";
const BASE: &str = "https://geocoding-api.open-meteo.com/v1/search";

/// Matches requested and emitted per query. A name search returns candidates in
/// best-first order; we keep the top few (the first anchored, the rest flagged
/// `candidate`) rather than an unbounded list — bounded work for a Termux device
/// and honest about the ambiguity of name geocoding.
const RESULT_LIMIT: usize = 3;

pub struct OpenMeteoGeo;

/// The `v1/search` envelope. `results` is absent (not `[]`) on a no-match reply,
/// so `#[serde(default)]` yields an empty vec either way.
#[derive(Deserialize, Default)]
#[serde(default)]
struct GeoResponse {
    results: Vec<GeoResult>,
}

/// One geocoding hit. `latitude`/`longitude` are always present on a real hit;
/// every enrichment field is optional and emitted only when returned.
#[derive(Deserialize, Default)]
#[serde(default)]
struct GeoResult {
    name: String,
    latitude: f64,
    longitude: f64,
    elevation: Option<f64>,
    feature_code: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    admin1: Option<String>,
    admin2: Option<String>,
    timezone: Option<String>,
    population: Option<u64>,
    postcodes: Vec<String>,
}

/// Human label for the common GeoNames populated-place feature codes, so the
/// evidence says *what kind* of place matched (a capital vs a hamlet) rather than
/// an opaque code. Pure; returns `None` for codes outside the populated-place
/// family (which are still surfaced verbatim as `feature_code`).
fn place_class(feature_code: &str) -> Option<&'static str> {
    Some(match feature_code {
        "PPLC" => "national capital",
        "PPLA" => "first-order administrative capital",
        "PPLA2" => "second-order administrative capital",
        "PPLA3" => "third-order administrative capital",
        "PPLA4" => "fourth-order administrative capital",
        "PPLG" => "seat of government",
        "PPL" => "populated place",
        "PPLX" => "section of populated place",
        "PPLL" => "populated locality",
        "PPLW" => "destroyed populated place",
        "PPLQ" => "abandoned populated place",
        _ => return None,
    })
}

/// Map a geocoding response to `Coordinates` entities. **Pure** (no network), so
/// the ranking, regional weighting, and enrichment are unit-tested directly.
///
/// The first valid hit is the anchor: inside Australia it is a strong on-region
/// coordinate ([`confidence::HIGH_PLUS`], `au-relevant` + `au-state:*`); abroad it
/// is a [`confidence::LOW`] `candidate`. Every subsequent hit is an ambiguous
/// alternate — always a `candidate` — so a name with several matches keeps them
/// all as leads without any one masquerading as confirmed.
fn build_entities(results: &[GeoResult], query: &str, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();

    for r in results {
        // Cap on EMITTED (valid) hits, not raw results, so skipped invalid-coord
        // rows don't shrink the usable result set below RESULT_LIMIT.
        if out.len() >= RESULT_LIMIT {
            break;
        }
        if !is_valid_coords(r.latitude, r.longitude) {
            continue;
        }
        let coords = format!("{:.6},{:.6}", r.latitude, r.longitude);
        let in_au = r
            .country_code
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case("AU"))
            || is_in_australia(r.latitude, r.longitude);
        // The anchor is the first EMITTED (valid) hit — keyed on `out.is_empty()`,
        // not the raw result index, so an invalid-coord result that is skipped
        // above never consumes the anchor slot and demotes a valid in-AU hit
        // sitting behind it to a LOW candidate.
        let anchored = out.is_empty() && in_au;

        let conf = if anchored {
            confidence::HIGH_PLUS
        } else {
            confidence::LOW
        };
        let mut e = Entity::new(EntityKind::Coordinates, &coords, conf, scan_id);
        e.tag("geocoded");
        if in_au {
            e.tag("au-relevant");
            if let Some(state) = au_state_for_coords(r.latitude, r.longitude) {
                e.tag(format!("au-state:{state}"));
            }
        } else {
            e.tag("off-region");
        }
        if !anchored {
            // Off-region anchors and every non-first hit are quarantined below the
            // expansion floor as leads, not confirmed positions (matches `geocode`).
            e.tag("candidate");
        }

        e.add_evidence(build_evidence(r, query, &coords));
        out.push(e);
    }

    out
}

/// Build the enrichment evidence for one hit — every field guarded so an absent
/// value is simply omitted, never emitted as a fabricated default.
fn build_evidence(r: &GeoResult, query: &str, coords: &str) -> Evidence {
    let mut ev = Evidence::new(
        SRC,
        format!("Geocoded \"{query}\" \u{2192} {coords} ({})", r.name),
    )
    .with_attr("input_address", query)
    .with_attr("place_name", &r.name)
    .with_attr("latitude", format!("{:.6}", r.latitude))
    .with_attr("longitude", format!("{:.6}", r.longitude));
    if let Some(c) = &r.country {
        ev = ev.with_attr("country", c);
    }
    if let Some(cc) = &r.country_code {
        ev = ev.with_attr("country_code", cc.to_uppercase());
    }
    if let Some(a1) = &r.admin1 {
        ev = ev.with_attr("admin1", a1);
    }
    if let Some(a2) = &r.admin2 {
        ev = ev.with_attr("admin2", a2);
    }
    // The distinctive people-geo signal: an IANA timezone for the matched place.
    if let Some(tz) = &r.timezone {
        ev = ev.with_attr("timezone", tz);
    }
    if let Some(pop) = r.population.filter(|&p| p > 0) {
        ev = ev.with_attr("population", pop.to_string());
    }
    if let Some(fc) = &r.feature_code {
        ev = ev.with_attr("feature_code", fc);
        if let Some(class) = place_class(fc) {
            ev = ev.with_attr("place_class", class);
        }
    }
    if let Some(el) = r.elevation {
        ev = ev.with_attr("elevation_m", format!("{el:.0}"));
    }
    if !r.postcodes.is_empty() {
        ev = ev.with_attr("postcodes", r.postcodes.join(", "));
    }
    ev
}

#[async_trait]
impl Module for OpenMeteoGeo {
    fn name(&self) -> &'static str {
        "open_meteo_geo"
    }

    fn description(&self) -> &'static str {
        "Open-Meteo geocoder (free) — place-name→coordinates enriched with timezone, population, place-class & elevation"
    }

    fn priority(&self) -> u8 {
        18
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Address)
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.is_empty() {
            return Ok(ModuleResult::new());
        }

        // Open-Meteo answers 200 with `results` present on a hit and absent on a
        // miss, so a non-2xx from `fetch_json` is a genuine outage worth surfacing.
        let url = format!(
            "{BASE}?name={}&count={RESULT_LIMIT}&language=en&format=json",
            urlencode(query)
        );
        let resp: GeoResponse = fetch_json(&ctx.http, SRC, &url).await?;

        let mut result = ModuleResult::new();
        result.extend(build_entities(&resp.results, query, &ctx.scan_id));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
