//! The nearest-place label: what a `Coordinates` value can honestly be CALLED,
//! at the precision [`super::grain::assess`] grades it — never finer.
//!
//! # Why a label, and why it is computed, never stored
//!
//! A bare `-27.469800,153.025100` tells a reader nothing, so every output
//! surface prints a place name beside it. The danger is the obvious one: a
//! street name looks like a finding. `-27.4698,153.0251` is the tabulated
//! Brisbane centroid; the street that happens to contain it ("123 Adelaide
//! St") is a fact about the MAP, not about anyone, and printing it beside a
//! subject's coordinate manufactures a street-level address nobody observed.
//! So the label is bound by one rule (REQ-GEOLABEL-002, P1): its grain is
//! never finer than the fix's own grain, and the radius it shows is never
//! smaller than the fix's radius. A city centroid is labelled as the city it
//! stands for; a street is named only for a measured fix good to a street; a
//! house number only for a measured fix good to a doorway whose nearest
//! address lies within its error bar.
//!
//! The label is a pure function of the entity, the scan's own stored records
//! ([`PlaceContext`]) and compiled-in gazetteer tables — no clock, no network,
//! no RNG — so a stored scan re-exports byte-identically, a code upgrade
//! corrects old scans retroactively, and no renderer ever needs an HTTP
//! client (REQ-GEOLABEL-003). It is never persisted: it is not an entity, a
//! tag, a value or an evidence record, so it can never be merged, recalled,
//! counted as corroboration or pivoted on (REQ-GEOLABEL-004).
//!
//! # Where a label comes from, in order
//!
//! 1. **Centroid** — a value [`assess`] recognises as a tabulated centroid
//!    names what it stands for, with the grain word: "Brisbane, QLD (city
//!    centroid — not a street location)" (P3/P6). Never the street, parcel or
//!    shop containing the centroid.
//! 2. **T0 mapped feature** — a point that IS a named map feature (a Wikipedia
//!    or Wikidata place, an OSM feature) is labelled with that stored name,
//!    worded "mapped place" so it cannot read as anyone's address (P9).
//! 3. **T1 stored reverse observation** — for a MEASURED or OPERATOR fix good
//!    to a street or better, the reverse geocode THIS scan already made of that
//!    exact coordinate (`geocode` / `photon` reverse legs). Only its structured
//!    parts (house number, road, suburb, postcode, state, country), never the
//!    POI or display name, and clipped by the offset rules (P5).
//! 4. **T2 forward-geocode self-answer** — a fix produced BY a forward geocode
//!    is labelled from the structured answer stored on it, clipped to the grain
//!    the input could support (P4).
//! 5. **T3 stored statistical area** — `au_geo`'s ASGS suburb / postcode / LGA
//!    for the point, only at the grain it can support (P7), never on a
//!    centroid.
//! 6. **T4 offline gazetteer** — the nearest curated centre (Australian and
//!    Vietnamese anchors, the tabulated cities), with distance and an 8-point
//!    bearing, then the state, then the country (P13).
//!
//! No new network request is made for a label (the lead decision that dropped
//! the scan-time reverse-geocode pass): a subject's measured coordinate is
//! never sent to a third party just to name it.

use std::collections::BTreeMap;

use super::grain::{
    FixBasis, FixGrain, StandsFor, assess, is_annotator_row, quantisation_radius_m,
};
use crate::core::entity::{Entity, EntityKind, Evidence};

/// The standing caveat every label carries in its structured form: a place
/// label says where the POINT is, never who lives there.
pub const PLACE_CAVEAT: &str = "describes the point — not an address attributed to the subject";

/// The one-line legend a text renderer prints once above its place lines.
pub const PLACE_LEGEND: &str = "place = nearest place at the fix's own precision; describes the point, not an address attributed to the subject";

/// Which tier of the ladder (module docs) produced a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelBasis {
    /// A tabulated centroid named as what it stands for.
    Centroid,
    /// The point is a named map feature (T0).
    MappedFeature,
    /// This scan's own reverse geocode of this exact point (T1).
    NearestAddress,
    /// The structured answer of the forward geocode that produced the point (T2).
    ForwardGeocode,
    /// `au_geo`'s statistical-area lookup for the point (T3).
    StatisticalArea,
    /// The nearest curated centre, the state or the country, offline (T4).
    Gazetteer,
    /// A fused multi-signal fix ([`describe_fused`]), offline, locality at best.
    Fused,
    /// A best-location estimate that rests on ONE signal ([`describe_fused`]
    /// with [`FixKind::SingleSignal`]), offline, locality at best.
    SingleSignal,
}

impl LabelBasis {
    /// The snake-case name used in the JSON form and the text renderers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Centroid => "centroid",
            Self::MappedFeature => "mapped_feature",
            Self::NearestAddress => "nearest_address",
            Self::ForwardGeocode => "forward_geocode",
            Self::StatisticalArea => "statistical_area",
            Self::Gazetteer => "gazetteer",
            Self::Fused => "fused",
            Self::SingleSignal => "single_signal",
        }
    }
}

/// A coordinate's nearest-place label ([`describe`], [`describe_fused`]).
#[derive(Debug, Clone, PartialEq)]
pub struct PlaceLabel {
    /// The human-readable label, with its precision qualifier.
    pub text: String,
    /// The grain the label names — never finer than [`PlaceLabel::fix_grain`].
    pub label_grain: FixGrain,
    /// The grain the fix itself was graded at.
    pub fix_grain: FixGrain,
    /// The fix's radius (metres), as graded — rendered rounded UP. Infinite
    /// for a point that claims no disc at all (a country signal,
    /// [`FixBasis::CountrySignal`]), rendered as no radius.
    pub fix_radius_m: f64,
    /// For a nearest-address label, how far the matched address object lies
    /// from the fix (metres); `None` otherwise or when it was not recorded.
    pub offset_m: Option<f64>,
    /// Which tier produced the label.
    pub basis: LabelBasis,
}

impl PlaceLabel {
    /// The structured form every JSON surface carries as `place_label`. Every
    /// number is a rounded integer (the radius rounded UP to one significant
    /// figure, the offset to its display bucket), so float noise in the last
    /// digit can never change a byte of an export (REQ-GEOLABEL-003). A point
    /// with no radius (a country signal) carries `"fix_radius_m": null` —
    /// never `0`, which would claim a fix with no error at all.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "text": self.text,
            "label_grain": self.label_grain.as_str(),
            "fix_grain": self.fix_grain.as_str(),
            "fix_radius_m": self
                .fix_radius_m
                .is_finite()
                .then(|| radius_display_m(self.fix_radius_m)),
            "offset_m": self.offset_m.map(distance_display_m),
            "basis": self.basis.as_str(),
            "caveat": PLACE_CAVEAT,
        })
    }

    /// The bracketed precision detail the text renderers print after the
    /// label: `[label=locality, fix=locality ±8 km; centroid]`, or
    /// `[label=country, fix=country, no radius; gazetteer]` for a point that
    /// claims no disc.
    #[must_use]
    pub fn detail(&self) -> String {
        let radius = if self.fix_radius_m.is_finite() {
            format!(" ±{}", radius_text(self.fix_radius_m))
        } else {
            ", no radius".to_string()
        };
        format!(
            "[label={}, fix={}{radius}; {}]",
            self.label_grain.as_str(),
            self.fix_grain.as_str(),
            self.basis.as_str()
        )
    }
}

// ── The scan's stored reverse observations ────────────────────────────────

/// The reverse-geocode provider an observation came from. `Ord` is the
/// preference order when one point has several: Nominatim's structured
/// address first, then Photon's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReverseProvider {
    Nominatim,
    Photon,
}

/// One reverse geocode of one exact point, as the `geocode` / `photon` reverse
/// legs stored it on their `Address` entity — structured parts only. There is
/// deliberately no field for the POI or display name (`nearest_feature`,
/// `place_name`, `display_name`): a shop at the point is not part of an
/// address and never reaches a label (P9).
#[derive(Debug, Clone)]
struct ReverseObservation {
    provider: ReverseProvider,
    house_number: Option<String>,
    road: Option<String>,
    suburb: Option<String>,
    locality: Option<String>,
    state: Option<String>,
    postcode: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    /// Where the matched object lies, when the leg recorded it.
    matched: Option<(f64, f64)>,
    /// Nominatim's `place_rank` of the matched object, when recorded.
    place_rank: Option<u32>,
    /// The record's summary — the tie-break after provider and offset.
    summary: String,
}

/// The final, total tie-break between two observations of one point that
/// share a provider, an offset bucket and a summary — two answers the same
/// leg gave for the same point (a live answer and a replayed one that
/// differed), stored on two `Address` entities. Every part the label can
/// print is compared, so the pick is the same whichever order the store
/// returned those entities in (REQ-GEOLABEL-003).
type ObservationKey<'a> = ([Option<&'a str>; 8], Option<u32>, Option<(i64, i64)>);

impl ReverseObservation {
    fn content_key(&self) -> ObservationKey<'_> {
        (
            [
                self.house_number.as_deref(),
                self.road.as_deref(),
                self.suburb.as_deref(),
                self.locality.as_deref(),
                self.state.as_deref(),
                self.postcode.as_deref(),
                self.country.as_deref(),
                self.country_code.as_deref(),
            ],
            self.place_rank,
            self.matched.map(|(a, b)| micro_key(a, b)),
        )
    }
}

/// The records of ONE scan a label may read beyond the entity itself: the
/// reverse geocodes that scan made, indexed by the exact point each was made
/// of. Built once per render from the scan's entities; pure and ordered
/// (`BTreeMap`, each point's observations sorted by a total key), so the same
/// stored scan always yields the same labels.
#[derive(Debug, Clone, Default)]
pub struct PlaceContext {
    reverse: BTreeMap<(i64, i64), Vec<ReverseObservation>>,
}

/// A point keyed at the micro-degree grain both reverse legs record their
/// query at (`geocode` writes the parsed `f64`, `photon` six decimals) and
/// every `Coordinates` value is normalised to.
#[allow(clippy::cast_possible_truncation)] // |lat|,|lon| ≤ 180 → ≤ 1.8e8.
fn micro_key(lat: f64, lon: f64) -> (i64, i64) {
    ((lat * 1e6).round() as i64, (lon * 1e6).round() as i64)
}

/// An attribute value usable as ONE address component: trimmed, non-empty,
/// and not a merge splice. `hse_core`'s evidence merge joins two conflicting
/// values of one record as `"a; b"`; a spliced road names two roads, so it
/// names none.
fn component(ev: &Evidence, key: &str) -> Option<String> {
    ev.attributes
        .get(key)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty() && !v.contains("; "))
        .map(str::to_string)
}

/// A finite number attribute.
fn number(ev: &Evidence, key: &str) -> Option<f64> {
    component(ev, key)?
        .parse::<f64>()
        .ok()
        .filter(|x| x.is_finite())
}

impl PlaceContext {
    /// Index the reverse geocodes scan `scan_id` made, from its entities.
    ///
    /// A reverse observation is a `geocode` / `photon` record carrying the
    /// queried `latitude` / `longitude`, on an `Address` the leg tagged
    /// `reverse-geocoded`. Two exclusions keep every surface agreeing:
    ///
    /// * a quarantined (`candidate`) Address — an off-region answer — is not
    ///   read, so a label never depends on whether the surface happens to show
    ///   candidates;
    /// * a record another scan made (a recalled or cross-scan row, whose
    ///   `Evidence::scan_id` names that scan) is not this scan's observation of
    ///   the point; a record from before the field existed (empty `scan_id`)
    ///   is read as the scan's own, since only this scan's copy holds it.
    #[must_use]
    pub fn for_scan<'a>(entities: impl IntoIterator<Item = &'a Entity>, scan_id: &str) -> Self {
        let mut reverse: BTreeMap<(i64, i64), Vec<ReverseObservation>> = BTreeMap::new();
        for e in entities {
            if e.kind != EntityKind::Address
                || !e.has_tag("reverse-geocoded")
                || e.has_tag(crate::core::tags::CANDIDATE)
            {
                continue;
            }
            for ev in &e.evidence {
                let provider = match ev.source.as_str() {
                    "geocode" => ReverseProvider::Nominatim,
                    "photon" => ReverseProvider::Photon,
                    _ => continue,
                };
                if !(ev.scan_id.is_empty() || ev.scan_id == scan_id) {
                    continue;
                }
                let (Some(lat), Some(lon)) = (number(ev, "latitude"), number(ev, "longitude"))
                else {
                    continue;
                };
                let matched = number(ev, "matched_lat").zip(number(ev, "matched_lon"));
                reverse
                    .entry(micro_key(lat, lon))
                    .or_default()
                    .push(ReverseObservation {
                        provider,
                        house_number: component(ev, "house_number"),
                        road: component(ev, "road"),
                        suburb: component(ev, "suburb"),
                        locality: component(ev, "city"),
                        state: component(ev, "state"),
                        postcode: component(ev, "postcode"),
                        country: component(ev, "country"),
                        country_code: component(ev, "country_code").map(|c| c.to_ascii_lowercase()),
                        matched,
                        place_rank: component(ev, "place_rank").and_then(|r| r.parse().ok()),
                        summary: ev.summary.clone(),
                    });
            }
        }
        for obs in reverse.values_mut() {
            obs.sort_by(|a, b| {
                a.provider
                    .cmp(&b.provider)
                    .then_with(|| a.summary.cmp(&b.summary))
                    .then_with(|| a.content_key().cmp(&b.content_key()))
            });
        }
        Self { reverse }
    }
}

// ── Number formatting (P13): fixed tables, integers, no `-0` ──────────────

/// A radius rounded UP to one significant figure, in whole metres — up, so the
/// radius a reader sees is never smaller than the fix's (P1). A tolerance of
/// `1e-9` keeps a rung floor such as `5000.000…1` on `5 km`.
///
/// The whole-metre step rounds up too: a sub-metre radius — the operator's
/// seed typed to six decimals is good to its quantisation, ~0.06 m — shows as
/// `1 m`, never `0 m`, which would claim a fix with no error at all. Only a
/// radius that is exactly zero (or not a radius) shows as `0`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // ≥ 0, ≤ Earth.
pub(super) fn radius_display_m(m: f64) -> u64 {
    if !m.is_finite() || m <= 0.0 {
        return 0;
    }
    let scale = 10f64.powi(m.log10().floor() as i32);
    ((m / scale - 1e-9).ceil() * scale).ceil() as u64
}

/// `"60 m"`, `"8 km"` — a radius as [`radius_display_m`] rounds it.
fn radius_text(m: f64) -> String {
    let r = radius_display_m(m);
    if r < 1_000 {
        format!("{r} m")
    } else {
        format!("{} km", r / 1_000)
    }
}

/// A distance rounded to its display bucket, in whole metres: 10 m steps under
/// 100 m, 50 m steps under 1 km, 1 km steps under 10 km, 5 km steps beyond.
/// A distance is a measurement, not a bound, so it rounds to nearest.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // ≥ 0, ≤ Earth.
pub(super) fn distance_display_m(m: f64) -> u64 {
    if !m.is_finite() || m <= 0.0 {
        return 0;
    }
    let step = if m < 100.0 {
        10.0
    } else if m < 1_000.0 {
        50.0
    } else if m < 10_000.0 {
        1_000.0
    } else {
        5_000.0
    };
    ((m / step).round() * step) as u64
}

/// `"~30 m"`, `"~12 km"` — a distance as [`distance_display_m`] buckets it.
fn distance_text(m: f64) -> String {
    let d = distance_display_m(m);
    if d < 1_000 {
        format!("~{d} m")
    } else {
        format!("~{} km", d / 1_000)
    }
}

/// The 8-point compass bearing FROM `(lat1, lon1)` TO `(lat2, lon2)` — "~12 km
/// NE of Toowoomba" means the point lies north-east of Toowoomba. Local
/// equirectangular angle (exact enough within the 50 km it is ever worded
/// over), longitude difference wrapped across the antimeridian, then an
/// integer 45° sector.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // sector ∈ 0..8
pub(super) fn bearing_8(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> &'static str {
    const SECTORS: [&str; 8] = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"];
    let mut dlon = lon2 - lon1;
    if dlon > 180.0 {
        dlon -= 360.0;
    } else if dlon < -180.0 {
        dlon += 360.0;
    }
    let dx = dlon * ((lat1 + lat2) / 2.0).to_radians().cos();
    let dy = lat2 - lat1;
    let deg = dx.atan2(dy).to_degrees().rem_euclid(360.0);
    SECTORS[(((deg + 22.5) / 45.0).floor() as usize) % 8]
}

// ── Composition ───────────────────────────────────────────────────────────

/// Structured address parts, any of which may be absent.
#[derive(Debug, Default, Clone)]
struct Parts {
    house_number: Option<String>,
    road: Option<String>,
    suburb: Option<String>,
    locality: Option<String>,
    state: Option<String>,
    postcode: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
}

/// The finest grain `parts` can name, or `None` when they name nothing.
fn parts_grain(p: &Parts) -> Option<FixGrain> {
    if p.house_number.is_some() && p.road.is_some() {
        Some(FixGrain::Point)
    } else if p.road.is_some() {
        Some(FixGrain::Street)
    } else if p.suburb.is_some() || p.postcode.is_some() {
        Some(FixGrain::Suburb)
    } else if p.locality.is_some() {
        Some(FixGrain::Locality)
    } else if p.state.is_some() {
        Some(FixGrain::Region)
    } else if p.country.is_some() || p.country_code.is_some() {
        Some(FixGrain::Country)
    } else {
        None
    }
}

/// Drop every part finer than `grain`.
fn clip(mut p: Parts, grain: FixGrain) -> Parts {
    if grain > FixGrain::Point {
        p.house_number = None;
    }
    if grain > FixGrain::Street {
        p.road = None;
    }
    if grain > FixGrain::Suburb {
        p.suburb = None;
        p.postcode = None;
    }
    if grain > FixGrain::Locality {
        p.locality = None;
    }
    if grain > FixGrain::Region {
        p.state = None;
    }
    p
}

/// The display name of a country: the stored name, else the name of its ISO
/// code.
fn country_display(p: &Parts) -> Option<String> {
    p.country.clone().or_else(|| {
        p.country_code
            .as_deref()
            .and_then(|cc| crate::util::geohash::country_name_for_iso(&cc.to_ascii_uppercase()))
            .map(str::to_string)
    })
}

/// Compose already-clipped parts into one address line, in the country's own
/// convention:
///
/// * **Australia** — `"12 Smith Street, Toowong QLD 4066"`: street, then
///   suburb, state code and postcode on one line; the city is dropped under a
///   suburb, as an Australian address does.
/// * **Vietnam** — `"12 Đường Láng, Phường Láng, Hà Nội"`: street, ward, and
///   the province or centrally-run city, the two-tier form after the 2025
///   reform; no district and no postcode.
/// * **Elsewhere** — street, suburb, locality, state, country.
///
/// Region grain names the state and the country; country grain the country.
fn compose(p: &Parts) -> Option<String> {
    let street = match (&p.house_number, &p.road) {
        (Some(n), Some(r)) => Some(format!("{n} {r}")),
        (None, Some(r)) => Some(r.clone()),
        _ => None,
    };
    let cc = p.country_code.as_deref().unwrap_or("");
    let mut out: Vec<String> = Vec::new();
    out.extend(street);
    if cc.eq_ignore_ascii_case("au") {
        let st = p.state.as_deref().map(|s| {
            crate::util::address_au::state_code(s).map_or_else(|| s.to_string(), str::to_string)
        });
        let spaced =
            |items: [Option<String>; 3]| items.into_iter().flatten().collect::<Vec<_>>().join(" ");
        let area = match (&p.suburb, &p.locality, &p.postcode) {
            (Some(sub), _, pc) => Some(spaced([Some(sub.clone()), st, pc.clone()])),
            (None, Some(loc), Some(pc)) => Some(spaced([Some(loc.clone()), st, Some(pc.clone())])),
            (None, Some(loc), None) => Some(match st {
                Some(st) => format!("{loc}, {st}"),
                None => loc.clone(),
            }),
            (None, None, Some(pc)) => Some(match st {
                Some(st) => format!("Postcode {pc} area, {st}"),
                None => format!("Postcode {pc} area"),
            }),
            (None, None, None) => None,
        };
        match area {
            Some(a) => out.push(a),
            None => {
                if let Some(full) = p.state.as_deref().map(|s| {
                    crate::util::address_au::state_code(s)
                        .and_then(crate::util::address_au::state_name)
                        .unwrap_or_else(|| s.to_string())
                }) {
                    out.push(full);
                }
                out.push("Australia".to_string());
            }
        }
    } else if cc.eq_ignore_ascii_case("vn") {
        out.extend(p.suburb.clone());
        out.extend(p.locality.clone().or_else(|| p.state.clone()));
        if p.suburb.is_none() && p.locality.is_none() {
            out.extend(country_display(p));
        }
    } else {
        out.extend(p.suburb.clone());
        out.extend(p.postcode.clone().filter(|_| p.suburb.is_none()));
        out.extend(p.locality.clone());
        out.extend(p.state.clone());
        out.extend(country_display(p));
    }
    dedup_case_insensitive(&mut out);
    (!out.is_empty()).then(|| out.join(", "))
}

/// Drop a part repeating an earlier one ("Sydney, Sydney").
fn dedup_case_insensitive(parts: &mut Vec<String>) {
    let mut seen: Vec<String> = Vec::new();
    parts.retain(|p| {
        let k = p.to_lowercase();
        if seen.contains(&k) {
            false
        } else {
            seen.push(k);
            true
        }
    });
}

// ── T4: the offline gazetteer ─────────────────────────────────────────────

/// How far (km) from a curated centre a point is still worded relative to it
/// ("~12 km NE of Toowoomba"); beyond, only the region stands.
const NEAR_CENTRE_KM: f64 = 50.0;

/// How far (km) from a tabulated city ([`crate::util::city_coords`]) a point
/// outside the curated regions is still "near" it.
const NEAR_CITY_KM: f64 = 30.0;

/// "Toowong, QLD" or "~12 km NE of Toowoomba, QLD": a point worded against the
/// centre `name` (at `centre`) `km` away. An offset no larger than the fix's
/// own radius — or than 3 km, inside which a centre's own name is the honest
/// answer — is not worded: it would state a position finer than the fix.
fn near_centre(
    name: &str,
    suffix: Option<&str>,
    centre: (f64, f64),
    point: (f64, f64),
    km: f64,
    fix_radius_m: f64,
) -> String {
    let metres = km * 1_000.0;
    let place = match suffix {
        Some(s) => format!("{name}, {s}"),
        None => name.to_string(),
    };
    if km <= 3.0 || metres <= fix_radius_m {
        place
    } else {
        format!(
            "{} {} of {place}",
            distance_text(metres),
            bearing_8(centre.0, centre.1, point.0, point.1)
        )
    }
}

/// The coordinates of an AU curated anchor by name (for the bearing).
fn au_anchor_position(name: &str) -> Option<(f64, f64)> {
    crate::util::geo::au_locality_anchors()
        .find(|&(n, _, _, _)| n == name)
        .map(|(_, _, lat, lon)| (lat, lon))
}

/// The country the entity's own locating records agree on (a geocoder's
/// `country_code`), by name — `None` when none records one or they disagree.
fn stored_country(e: Option<&Entity>) -> Option<String> {
    let mut stored: Vec<String> = e
        .into_iter()
        .flat_map(|e| e.evidence.iter())
        .filter(|ev| !is_annotator_row(ev))
        .filter_map(|ev| component(ev, "country_code"))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    stored.sort_unstable();
    stored.dedup();
    match stored.as_slice() {
        [cc] => crate::util::geohash::country_name_for_iso(cc).map(str::to_string),
        _ => None,
    }
}

/// The country a point is in, from the stored records that located it (a
/// geocoder's `country_code`, when every record agrees), else the offline
/// bounding box, marked "(approx.)" because boxes overlap at borders.
fn country_phrase(e: Option<&Entity>, lat: f64, lon: f64) -> Option<String> {
    if let Some(name) = stored_country(e) {
        return Some(name);
    }
    let iso = crate::util::geohash::reverse_country_iso(lat, lon)?;
    let name = crate::util::geohash::country_name_for_iso(iso).unwrap_or(iso);
    Some(format!("{name} (approx.)"))
}

/// The offline place phrase for a point graded `grain` / `radius_m`, and the
/// grain the phrase names (never finer than `grain`).
///
/// * Country grain — the country.
/// * Region grain — the Australian state ("Queensland, Australia"), else the
///   country.
/// * Finer — the nearest curated centre within [`NEAR_CENTRE_KM`] (Australia's
///   anchors, then Vietnam's centrally-run cities), then the nearest tabulated
///   city within [`NEAR_CITY_KM`], worded by [`near_centre`] at locality grain;
///   an Australian point beyond every centre is "remote QLD — nearest centre
///   Alice Springs (~140 km)" at region grain; anything else falls back to the
///   country.
fn offline_phrase(
    e: Option<&Entity>,
    lat: f64,
    lon: f64,
    grain: FixGrain,
    radius_m: f64,
) -> Option<(String, FixGrain)> {
    let au_state = crate::util::geo::au_state_for_coords(lat, lon);
    let region = || -> Option<(String, FixGrain)> {
        if let Some(st) = au_state {
            let name = crate::util::address_au::state_name(st).unwrap_or_else(|| st.to_string());
            return Some((format!("{name}, Australia"), FixGrain::Region));
        }
        country_phrase(e, lat, lon).map(|c| (c, FixGrain::Country))
    };
    match grain {
        FixGrain::Country => {
            return country_phrase(e, lat, lon).map(|c| (c, FixGrain::Country));
        }
        FixGrain::Region => return region(),
        _ => {}
    }
    let at_locality = grain.max(FixGrain::Locality);
    if let (Some(st), Some((name, anchor_state, km))) =
        (au_state, crate::util::geo::nearest_au_locality(lat, lon))
    {
        if km <= NEAR_CENTRE_KM
            && let Some(centre) = au_anchor_position(name)
        {
            return Some((
                near_centre(name, Some(anchor_state), centre, (lat, lon), km, radius_m),
                at_locality,
            ));
        }
        return Some((
            format!(
                "remote {st} — nearest centre {name} ({})",
                distance_text(km * 1_000.0)
            ),
            FixGrain::Region.max(grain),
        ));
    }
    if let Some((name, centre, km)) = crate::util::geo::nearest_vn_locality(lat, lon) {
        return Some((
            near_centre(name, Some("Vietnam"), centre, (lat, lon), km, radius_m),
            at_locality,
        ));
    }
    if let Some((name, centre, km)) =
        crate::util::city_coords::nearest_tabulated_city(lat, lon, NEAR_CITY_KM)
    {
        // The country only when the point's own records say it: the offline
        // box is approximate at exactly the borders a city can sit on
        // (Detroit / Windsor), and the city's name already places the point.
        let country = stored_country(e);
        return Some((
            near_centre(&name, country.as_deref(), centre, (lat, lon), km, radius_m),
            at_locality,
        ));
    }
    region()
}

// ── The tiers ─────────────────────────────────────────────────────────────

/// A centroid named as what it stands for (P3/P6), when the fix is no coarser
/// than a locality — a coarser account makes the city name finer than the fix.
fn centroid_label(
    stands_for: &StandsFor,
    grain: FixGrain,
    radius_m: f64,
) -> Option<(String, FixGrain)> {
    if grain > FixGrain::Locality {
        return None;
    }
    let state = |s: &Option<String>| s.as_deref().map(|s| format!(", {s}")).unwrap_or_default();
    let text = match stands_for {
        StandsFor::Gazetteer { name, state: st } => {
            format!(
                "{name}{} (city centroid — not a street location)",
                state(st)
            )
        }
        StandsFor::Postcode { code, state: st } => format!(
            "Postcode {code} area{} (postcode centroid, ±{})",
            state(st),
            radius_text(radius_m)
        ),
        StandsFor::PostcodeRegion { prefix, state: st } => format!(
            "Postcode {prefix}xx region{} (postcode-region centroid, ±{})",
            state(st),
            radius_text(radius_m)
        ),
        StandsFor::Input(_) => return None,
    };
    Some((text, grain))
}

/// T0: the name of the map feature the point IS — a Wikipedia article's
/// `title`, a Wikidata item's `label`, an OSM feature's `name` (else its
/// category) — from the entity's own originating records, the smallest by
/// (source, name) so the pick never depends on record order.
///
/// Only while the value is still the feature's own position (its decimals good
/// to a street or better): a redacted one-decimal value is ~5 km from the
/// feature, and naming the feature there would both misplace it and undo the
/// redaction.
fn mapped_feature_name(e: &Entity) -> Option<String> {
    if quantisation_radius_m(e).is_none_or(|q| q > FixGrain::Street.ceiling_m().unwrap_or(0.0)) {
        return None;
    }
    let mut names: Vec<(String, String)> = e
        .evidence
        .iter()
        .filter(|ev| !is_annotator_row(ev))
        .filter_map(|ev| {
            let name = match ev.source.as_str() {
                "wiki_geosearch" => component(ev, "title"),
                "wikidata" => component(ev, "label"),
                "overpass" => {
                    let category = component(ev, "category");
                    match (component(ev, "name"), category) {
                        (Some(n), Some(c)) => Some(format!("{n} ({c})")),
                        (Some(n), None) => Some(n),
                        (None, Some(c)) => Some(format!("OSM {c}")),
                        (None, None) => None,
                    }
                }
                _ => None,
            }?;
            Some((ev.source.clone(), name))
        })
        .collect();
    names.sort();
    names.into_iter().next().map(|(_, n)| n)
}

/// T1: this scan's own reverse geocode of this exact point, clipped by the
/// offset rules (P5). Returns the composed line, the grain it names and the
/// offset of the matched object.
///
/// * A HOUSE NUMBER needs a fix good to a doorway, a matched object that is an
///   address point or a building (Nominatim `place_rank` ≥ 28, or a Photon
///   house number), within `max(2r, 50 m)` of the fix, and no provider
///   disagreeing about the road.
/// * A ROAD needs a fix good to a street and a matched object within
///   `max(3r, 150 m)`, with no disagreement.
/// * Otherwise the suburb and postcode — unless the matched object is over
///   2 km away (or the providers disagree on the suburb), when only the
///   locality stands.
///
/// An observation that did not record where its object lies (every one made
/// before the legs recorded `matched_lat` / `matched_lon`) has no offset, so it
/// can name no street at all.
fn nearest_address(
    observations: &[ReverseObservation],
    fix: (f64, f64),
    grain: FixGrain,
    radius_m: f64,
) -> Option<(String, FixGrain, Option<f64>)> {
    let norm = |s: &Option<String>| s.as_deref().map(str::to_lowercase);
    let distinct = |f: &dyn Fn(&ReverseObservation) -> Option<String>| {
        let mut v: Vec<String> = observations.iter().filter_map(f).collect();
        v.sort_unstable();
        v.dedup();
        v.len() > 1
    };
    let suburb_conflict = distinct(&|o| norm(&o.suburb));
    // Providers that disagree on the suburb disagree on where the point is,
    // so neither's street stands either (P5: suburb disagreement → locality).
    let road_conflict = suburb_conflict || distinct(&|o| norm(&o.road));
    let offset_of = |o: &ReverseObservation| {
        o.matched
            .map(|(a, b)| crate::util::geo::haversine_km(fix.0, fix.1, a, b) * 1_000.0)
    };
    // The pick: provider preference, then the closest recorded object (an
    // unrecorded offset last), then the summary, then the answer itself — a
    // total order, so no tie is left to the order the entities arrived in.
    let best = observations.iter().min_by(|a, b| {
        a.provider
            .cmp(&b.provider)
            .then_with(|| {
                let (oa, ob) = (offset_of(a), offset_of(b));
                match (oa, ob) {
                    (Some(x), Some(y)) => distance_display_m(x).cmp(&distance_display_m(y)),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            })
            .then_with(|| a.summary.cmp(&b.summary))
            .then_with(|| a.content_key().cmp(&b.content_key()))
    })?;
    let offset = offset_of(best);
    let house_ok = grain == FixGrain::Point
        && best.house_number.is_some()
        && match best.provider {
            ReverseProvider::Nominatim => best.place_rank.is_some_and(|r| r >= 28),
            ReverseProvider::Photon => true,
        }
        && offset.is_some_and(|o| o <= (2.0 * radius_m).max(50.0))
        && !road_conflict;
    let road_ok = grain <= FixGrain::Street
        && best.road.is_some()
        && offset.is_some_and(|o| o <= (3.0 * radius_m).max(150.0))
        && !road_conflict;
    let far = offset.is_some_and(|o| o > 2_000.0);
    let mut parts = Parts {
        house_number: best.house_number.clone().filter(|_| house_ok),
        road: best.road.clone().filter(|_| road_ok),
        suburb: best.suburb.clone().filter(|_| !far && !suburb_conflict),
        locality: best.locality.clone(),
        state: best.state.clone(),
        postcode: best.postcode.clone().filter(|_| !far && !suburb_conflict),
        country: best.country.clone(),
        country_code: best.country_code.clone(),
    };
    if parts.country_code.is_none() && crate::util::geo::is_in_australia(fix.0, fix.1) {
        parts.country_code = Some("au".to_string());
    }
    // Clip to the fix's grain FIRST, then read the grain of what is left: the
    // label names that grain, never a finer part the clip removed.
    let parts = clip(parts, grain);
    let label_grain = parts_grain(&parts)?.max(grain);
    // An observation that names nothing finer than a state adds nothing the
    // offline gazetteer cannot say better (a nearest centre, a distance).
    if label_grain > FixGrain::Locality {
        return None;
    }
    let line = compose(&parts)?;
    Some((line, label_grain, offset))
}

/// T2: the structured answer of the forward geocode that produced the point,
/// clipped to the fix's grain — the address the point was geocoded FROM, at
/// the precision the input could support (P4). Nominatim records its answer's
/// parts (`house_number`, `road`, `street`, `suburb`, `city`, `state`,
/// `postcode`, `country_code`); Photon only the hit's name, read as a road for
/// a `highway` hit or a locality for a `place` hit — never a point of
/// interest's name. The first forward record (by source, then summary) that
/// names anything at or coarser than the fix's grain answers.
fn forward_answer(e: &Entity, grain: FixGrain, au: bool) -> Option<(String, FixGrain)> {
    let mut rows: Vec<&Evidence> = e
        .evidence
        .iter()
        .filter(|ev| {
            matches!(ev.source.as_str(), "geocode" | "photon" | "open_meteo_geo")
                && ev.attributes.contains_key("input_address")
        })
        .collect();
    rows.sort_by(|a, b| {
        a.source
            .cmp(&b.source)
            .then_with(|| a.summary.cmp(&b.summary))
    });
    rows.into_iter().find_map(|ev| {
        let mut p = Parts {
            house_number: component(ev, "house_number"),
            road: component(ev, "road").or_else(|| {
                // A record written before `road` was recorded: its combined
                // `street` is a road only when it carries no house number.
                component(ev, "street").filter(|s| {
                    !s.split_whitespace()
                        .next()
                        .is_some_and(|w| w.chars().any(|c| c.is_ascii_digit()))
                })
            }),
            suburb: component(ev, "suburb"),
            locality: component(ev, "city").or_else(|| component(ev, "admin2")),
            state: component(ev, "state").or_else(|| component(ev, "admin1")),
            postcode: component(ev, "postcode"),
            country: component(ev, "country"),
            country_code: component(ev, "country_code").map(|c| c.to_ascii_lowercase()),
        };
        if ev.source == "photon" {
            match component(ev, "osm_key").as_deref() {
                Some("highway") => p.road = p.road.or_else(|| component(ev, "place_name")),
                Some("place") => p.locality = p.locality.or_else(|| component(ev, "place_name")),
                _ => {}
            }
        }
        if p.house_number.is_some() && p.road.is_none() {
            p.house_number = None;
        }
        if p.country_code.is_none() && au {
            p.country_code = Some("au".to_string());
        }
        let p = clip(p, grain);
        let label_grain = parts_grain(&p)?.max(grain);
        // A record that names only a country adds nothing the offline
        // gazetteer (which also reads the stored country) cannot say better —
        // a nearest centre, a state.
        if label_grain > FixGrain::Region {
            return None;
        }
        let line = compose(&p)?;
        Some((line, label_grain))
    })
}

/// T3: `au_geo`'s statistical-area lookup for the point (P7): the suburb only
/// for a fix good to 5 km (with its postcode only within 1.5 km), the local
/// government area for one good to 30 km. Never read on a gazetteer centroid —
/// the ASGS area CONTAINING a city centroid ("Brisbane City 4000") is the
/// map's, not the address any record reported.
fn statistical_area(e: &Entity, radius_m: f64, state: Option<&str>) -> Option<(String, FixGrain)> {
    let mut rows: Vec<&Evidence> = e
        .evidence
        .iter()
        .filter(|ev| ev.source == "au_geo")
        .collect();
    rows.sort_by(|a, b| a.summary.cmp(&b.summary));
    let first = |key: &str| rows.iter().find_map(|ev| component(ev, key));
    let st = first("au_state").or_else(|| state.map(str::to_string));
    if radius_m <= 5_000.0
        && let Some(suburb) = first("au_suburb")
    {
        let pc = first("au_postcode").filter(|_| radius_m <= 1_500.0);
        let line = [Some(suburb), st, pc]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        return Some((line, FixGrain::Suburb));
    }
    if radius_m <= 30_000.0
        && let Some(lga) = first("au_lga")
    {
        let line = match st {
            Some(st) => format!("{lga} (local government area), {st}"),
            None => format!("{lga} (local government area)"),
        };
        return Some((line, FixGrain::Locality));
    }
    None
}

/// The nearest-place label of a `Coordinates` entity, from the entity, this
/// scan's stored records (`ctx`) and the compiled-in gazetteers — `None` for
/// any other kind, an unparseable value, the radar sweep's `0,0` sentinel, or a
/// point no tier can name (open ocean with no stored country).
///
/// The tiers are tried in the order the module docs give; every one is
/// clipped so the label's grain is never finer than [`assess`]'s grade of the
/// fix (P1), and the fix's radius is always shown. A hosting, registrant or
/// OSM-infrastructure point is prefixed `infrastructure:` — it locates a
/// machine or a map feature, not a person (P11). Pure: no clock, no network.
#[must_use]
pub fn describe(e: &Entity, ctx: &PlaceContext) -> Option<PlaceLabel> {
    if e.kind != EntityKind::Coordinates
        || crate::core::scan::is_radar_sentinel(
            crate::core::scan::TargetKind::Coordinates,
            &e.value,
        )
    {
        return None;
    }
    let (lat, lon) = crate::util::geohash::parse_coords(&e.value)?;
    let fix = assess(e);
    let (grain, radius) = (fix.grain, fix.radius_m);
    let au = crate::util::geo::is_in_australia(lat, lon);
    let label = |text: String, label_grain: FixGrain, basis: LabelBasis, offset_m: Option<f64>| {
        PlaceLabel {
            text,
            label_grain: label_grain.max(grain),
            fix_grain: grain,
            fix_radius_m: radius,
            offset_m,
            basis,
        }
    };
    let mut out = None;

    if let Some(sf) = &fix.stands_for
        && let Some((text, g)) = centroid_label(sf, grain, radius)
    {
        out = Some(label(text, g, LabelBasis::Centroid, None));
    }
    if out.is_none()
        && fix.basis == FixBasis::MappedFeature
        && let Some(name) = mapped_feature_name(e)
    {
        let near = offline_phrase(Some(e), lat, lon, FixGrain::Locality, radius)
            .map(|(p, _)| format!(", {p}"))
            .unwrap_or_default();
        out = Some(label(
            format!(
                "{name} — mapped place{near} (point of interest — not an address of the subject)"
            ),
            grain,
            LabelBasis::MappedFeature,
            None,
        ));
    }
    if out.is_none()
        && matches!(fix.basis, FixBasis::Measured | FixBasis::Operator)
        && grain <= FixGrain::Street
        && let Some(obs) = ctx.reverse.get(&micro_key(lat, lon))
        && let Some((line, g, offset)) = nearest_address(obs, (lat, lon), grain, radius)
    {
        let offset_phrase = offset.map_or_else(
            || "offset unrecorded".to_string(),
            |o| format!("{} from the fix", distance_text(o)),
        );
        let lead = if g <= FixGrain::Street { "≈ " } else { "" };
        out = Some(label(
            format!(
                "{lead}{line} (nearest address, {offset_phrase}; fix ±{})",
                radius_text(radius)
            ),
            g,
            LabelBasis::NearestAddress,
            offset,
        ));
    }
    if out.is_none()
        && matches!(
            fix.basis,
            FixBasis::ForwardGeocode | FixBasis::MappedFeature
        )
        && let Some((line, g)) = forward_answer(e, grain, au)
    {
        let how = if matches!(fix.stands_for, Some(StandsFor::Input(_))) {
            "forward geocode, capped at what its input names"
        } else {
            "forward geocode"
        };
        out = Some(label(
            format!(
                "{line} ({how}; {}-level, ±{})",
                g.as_str(),
                radius_text(radius)
            ),
            g,
            LabelBasis::ForwardGeocode,
            None,
        ));
    }
    let coincident = matches!(
        fix.stands_for,
        Some(
            StandsFor::Gazetteer { .. }
                | StandsFor::Postcode { .. }
                | StandsFor::PostcodeRegion { .. }
        )
    );
    if out.is_none()
        && !coincident
        && au
        && let Some((line, g)) =
            statistical_area(e, radius, crate::util::geo::au_state_for_coords(lat, lon))
    {
        out = Some(label(
            format!(
                "{line} (statistical-area lookup; fix ±{})",
                radius_text(radius)
            ),
            g,
            LabelBasis::StatisticalArea,
            None,
        ));
    }
    if out.is_none()
        && let Some((phrase, g)) = offline_phrase(Some(e), lat, lon, grain, radius)
    {
        // A country signal names the country and no position in it: no disc
        // is drawn around its stand-in point (`grain::COUNTRY_SIGNAL_RADIUS_M`
        // — "±300 km" around Sydney for a `.au` email left Melbourne, Brisbane
        // and Perth outside the circle the label stated).
        let precision = if fix.basis == FixBasis::CountrySignal || !radius.is_finite() {
            "country-level signal — no position within the country".to_string()
        } else {
            format!("{}-level fix, ±{}", grain.as_str(), radius_text(radius))
        };
        out = Some(label(
            format!("{phrase} ({precision})"),
            g,
            LabelBasis::Gazetteer,
            None,
        ));
    }
    let mut out = out?;
    // The TAG half of the correlator's infrastructure gate (one rule, one
    // reader): hosting, registrant and `infra:` points. Not its "no anchoring
    // source" half — that would brand every city centroid a search snippet
    // named as infrastructure.
    if crate::core::correlator::is_infrastructure_geo_signals(
        false,
        e.tags.iter().map(String::as_str),
        std::iter::empty::<&str>(),
    ) {
        out.text = format!("infrastructure: {}", out.text);
    }
    Some(out)
}

/// What a best-location object's fix IS, so its label says so: several
/// signals fused into one point, or one signal standing alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixKind {
    /// The AU-059 cross-class synergy fix, or the ladder rung that recomputes
    /// it — a weighted centre of several independent signals.
    Synergy,
    /// The independent-class corroboration point — a centre of the signals
    /// that agree on one locality.
    Corroboration,
    /// A ladder rung below the synergy: ONE signal's position.
    SingleSignal,
}

impl FixKind {
    /// The kind of a best-location estimate, read from the basis the ladder
    /// wrote on it (`correlator::SYNERGY_BASIS` for the synergy rung) — the
    /// one reading every surface shares, so the JSON `source`, the dossier's
    /// basis line and the place label cannot disagree.
    #[must_use]
    pub fn of_estimate_basis(basis: &str) -> Self {
        if basis == crate::core::correlator::SYNERGY_BASIS {
            Self::Synergy
        } else {
            Self::SingleSignal
        }
    }

    /// The kind of an independent-class corroboration point that agrees
    /// `signal_count` signals: [`FixKind::Corroboration`] when two or more
    /// were fused into it, [`FixKind::SingleSignal`] when it is one signal's
    /// own position. `correlator::au_location_corroboration` returns a point
    /// for a lone signal too (count 1, one class); labelling that "(fused fix
    /// ±N)" beside its own `signal_count: 1` was the REQ-GEOLABEL-017 mislabel
    /// on the object attached to every best-location fix (REQ-GEOLABEL-023).
    #[must_use]
    pub const fn of_corroboration(signal_count: usize) -> Self {
        if signal_count >= 2 {
            Self::Corroboration
        } else {
            Self::SingleSignal
        }
    }
}

/// The label of a best-location fix — the AU-059 synergy fix, a rung of the
/// best-location ladder, the independent-class corroboration point — at
/// `(lat, lon)` good to `radius_km`. Offline only, never finer than a locality
/// (a fused point is a weighted centre of several signals, and a single
/// signal's estimate is placed at the grain the ladder can vouch for — neither
/// is a place anyone reported), no street and no point-of-interest name (P8).
/// Marked "(fused fix ±N km)" for a [`FixKind::Synergy`] or
/// [`FixKind::Corroboration`] point and "(single-signal fix ±N km)" for a
/// [`FixKind::SingleSignal`] one: a single sighting labelled "fused" beside a
/// basis line reading "single-signal fix" was the REQ-EXPORT-004 mislabel in
/// the other direction. `None` for an invalid point or one no gazetteer can
/// name.
#[must_use]
pub fn describe_fused(lat: f64, lon: f64, radius_km: f64, kind: FixKind) -> Option<PlaceLabel> {
    if !crate::util::geo::is_valid_coords(lat, lon) || !radius_km.is_finite() {
        return None;
    }
    let radius = (radius_km * 1_000.0).max(0.0);
    let grain = FixGrain::from_radius_m(radius).max(FixGrain::Locality);
    let (phrase, g) = offline_phrase(None, lat, lon, grain, radius)?;
    let (how, basis) = match kind {
        FixKind::Synergy | FixKind::Corroboration => ("fused fix", LabelBasis::Fused),
        FixKind::SingleSignal => ("single-signal fix", LabelBasis::SingleSignal),
    };
    Some(PlaceLabel {
        text: format!("{phrase} ({how} ±{})", radius_text(radius)),
        label_grain: g.max(grain),
        fix_grain: FixGrain::from_radius_m(radius),
        fix_radius_m: radius,
        offset_m: None,
        basis,
    })
}

/// The `place_label` JSON for `e`, or `None` when [`describe`] has none — the
/// one helper every JSON surface uses, so the field cannot be spelled two ways.
#[must_use]
pub fn place_label_json(e: &Entity, ctx: &PlaceContext) -> Option<serde_json::Value> {
    describe(e, ctx).map(|l| l.to_json())
}

/// The `place_label` JSON for a best-location fix of `kind`, or `Null`.
#[must_use]
pub fn fused_label_json(lat: f64, lon: f64, radius_km: f64, kind: FixKind) -> serde_json::Value {
    describe_fused(lat, lon, radius_km, kind).map_or(serde_json::Value::Null, |l| l.to_json())
}
