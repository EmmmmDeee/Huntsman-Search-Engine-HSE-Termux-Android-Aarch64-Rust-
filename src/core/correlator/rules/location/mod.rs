//! AU correlation rules — convex location-estimation family.
//!
//! The person-anchor gate plus the two rules that consume the convex estimators
//! in [`crate::util::geometry`]: **AU-052** (geographic area of operation — the
//! convex footprint and the robust, confidence-weighted location fix) and
//! **AU-053** (out-of-area location anomaly via hull membership). Split out of
//! the `geo` family so the legacy geo-cluster rules and the convex
//! location-estimation work each read as one concern. Shared helpers come from
//! `super` (rules/mod.rs) via `use super::*`.

use super::*;

/// Geo sources that locate the **person**, not an IP/host or a map feature: a
/// geocoded street address (`geocode`/`photon`), a photo's GPS (`exif_geo`), or
/// an observed Wi-Fi access point (`wigle`/`mylnikov`). A coordinate must carry
/// at least one of these to enter a subject's footprint.
///
/// This is a deliberate *allowlist*, not an infra exclude-list. A live scan
/// showed why the exclusion must be positive: an Overpass pass attaches ~20
/// nearby map POIs (surveillance cameras, cell towers) to one IP-geolocated
/// point, and IP-geo/chronolocation sources (`ip_geo`, `ipinfo`,
/// `ip_whois_geo`, `sunrise_sunset`, `overpass`) are *not* sightings of the
/// person. An exclude-list silently admits any source it forgot to name (it had
/// no `overpass` entry, so it would have built a tight footprint out of traffic
/// cameras); an allowlist admits only what genuinely anchors to the subject.
/// Geo sources that anchor a **person's** location rather than IP/host
/// infrastructure. Every entry here produces a real-world address or confirmed
/// GPS fix that is associated with the *subject*, not a CDN edge or POI.
///
/// Additions over the original five:
/// - `search_engines` — inline city-lookup geocoding from search snippets
/// - `social_location` — self-reported or professional profile address
/// - `abn_lookup` / `opencorporates` / `acnc_charities` / `gleif_lei` — AU/global
///   business registry registered address (the entity's legal place of operation)
/// - `epieos` / `contact_enrich` / `proxycurl` — email-to-person enrichment that
///   returns a home or work address for the *subject*
/// - `qld_unclaimed` — Queensland register postcode (coarse but person-linked)
/// - `github_user` / `keybase` — self-reported location on confirmed social profiles
/// - `phone_area_geo` / `phone_carrier_geo` — phone number → city/carrier inference
/// - `fullcontact` — structured location from person-enrichment data-broker API
/// - `breach_timezone` — timezone inferred from breach timestamp activity clustering
const ANCHORING_GEO_SOURCES: &[&str] = &[
    // Original five: direct GPS/geocode/wifi sightings
    "geocode",
    "photon",
    "exif_geo",
    "wigle",
    "mylnikov",
    // Search-derived inline geocoding (known-city lookup from snippets)
    "search_engines",
    // Social profile bio and professional portal addresses
    "social_location",
    // Social profile location fields (GitHub, Keybase) — self-reported but
    // person-anchored (the profile belongs to a confirmed identity node).
    "github_user",
    "keybase",
    // Phone area-code and carrier inference — narrows person to city/region.
    "phone_area_geo",
    "phone_carrier_geo",
    // Business registry addresses (legal registered location of subject/employer)
    "abn_lookup",
    "opencorporates",
    "acnc_charities",
    "gleif_lei",
    // Email-to-person enrichment returning home/work address
    "epieos",
    "contact_enrich",
    "proxycurl",
    // AU public register (coarse postcode, person-linked)
    "qld_unclaimed",
    // Multi-state AU unclaimed-money registers (NSW/VIC/WA/SA) — postcode-level,
    // surname-anchored to the subject (same class as qld_unclaimed).
    "au_unclaimed",
    // AU residential people-finder directories (White Pages AU, True People
    // Search AU) — suburb/state/postcode for a confirmed name.
    "au_people",
    // ASIC company-directors register — the director's company registered-office
    // address (a person-anchored business location).
    "asic_director",
    // Person enrichment — structured location data from data-broker APIs
    "fullcontact",
    // Timezone inference from breach timestamp clustering — coarse but
    // person-linked (the timestamps belong to the subject's account activity)
    "breach_timezone",
    // AEC and state electoral commission enrolment lookups — compulsory
    // enrolment and address-verified; highest-confidence residential signal.
    "au_electoral",
    // Property and land title register lookups — compulsory title registration,
    // government-maintained, orthogonal to directories and electoral records.
    "au_property",
];

/// Returns `true` when a source name is a person-anchoring geo source —
/// i.e. it locates the *subject*, not IP/host infrastructure. Used both by
/// the correlator's hull filters and the engine's expansion ranking bonus.
pub(crate) fn is_anchoring_geo_source(source: &str) -> bool {
    ANCHORING_GEO_SOURCES.contains(&source)
}

/// True when a `Coordinates` entity does **not** locate the subject and must be
/// kept out of their footprint: it is `hosting`-tagged (a CDN/cloud edge), it
/// carries an `infra:` map-feature tag (an Overpass POI — a camera, a cell tower
/// — scraped near a geolocated point), or it has no person-anchoring
/// corroborating source at all ([`ANCHORING_GEO_SOURCES`]) — i.e. it rests purely
/// on IP/WHOIS geo, chronolocation, or POI enrichment. See AU-052.
fn is_infrastructure_geo(e: &Entity) -> bool {
    if e.has_tag(crate::core::tags::HOSTING) {
        return true;
    }
    if e.tags.iter().any(|t| t.starts_with("infra:")) {
        return true;
    }
    let sources = e.corroborating_sources();
    !sources.iter().any(|s| ANCHORING_GEO_SOURCES.contains(s))
}

/// The coordinates admissible to a *person's* geo footprint: confirmed
/// `Coordinates` (confidence ≥ 0.50) that pass the person-anchor gate
/// ([`is_infrastructure_geo`]), parsed to `(lat, lon)`. Shared by AU-052 and
/// AU-053 so both rules operate on exactly the same admissible set.
fn person_anchored_coords(entities: &[Entity]) -> Vec<(&Entity, (f64, f64))> {
    entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .filter(|e| !is_infrastructure_geo(e))
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (c, ll)))
        .collect()
}

/// Number of distinct corroborating sources across a set of admissible
/// coordinates. The multi-source gate (≥2) ensures a single device's own GPS
/// track can't assert a footprint; AU-052 also reports the count.
fn distinct_geo_sources(parsed: &[(&Entity, (f64, f64))]) -> usize {
    let mut sources: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (e, _) in parsed {
        sources.extend(e.corroborating_sources());
    }
    sources.len()
}

/// AU-052 — Geographic area of operation (convex footprint).
///
/// Where AU-017 reports *that* coordinates cluster and AU-030 reports *how many
/// sources* produced geo, this rule reports the *shape and centre* of the
/// subject's geographic footprint: the convex hull bounding every confirmed
/// sighting, its centroid — the single best point-estimate of the subject's
/// base — and its great-circle diameter. The centroid of several independent
/// geo sources is one of the strongest location fixes an investigation can
/// derive, which is exactly the convex-hull method requested.
///
/// Precision discipline: requires ≥3 confirmed `Coordinates` from ≥2 *distinct*
/// sources (one device's own track is not multi-source convergence) that bound
/// a real area (non-collinear — see [`crate::util::geometry::geo_footprint`]). A
/// *tight* footprint (≤25 km, one metro) is a High-severity residence/base fix;
/// a dispersed one is Medium and describes a travel pattern rather than a home.
///
/// **Person-anchor gate** (learned from two live scans): a subject's coordinates
/// must geolocate the *person*, not the infrastructure in their orbit.
/// Admissible coordinates need ≥1 corroborating source from
/// [`ANCHORING_GEO_SOURCES`] (a photo's EXIF GPS, a Wi-Fi sighting, a geocoded
/// street address) and must not be `hosting`-tagged or carry an `infra:`
/// map-feature tag. The first scan showed CDN edges geolocating to four
/// continents; the second showed ~20 Overpass POIs (traffic cameras, cell
/// towers) clustered around one IP point — an *exclude*-list silently admitted
/// the latter, so the gate is a positive allowlist instead.
pub(in crate::core::correlator) fn rule_au_052_geographic_area_of_operation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let parsed = person_anchored_coords(entities);
    if parsed.len() < 3 {
        return Vec::new();
    }
    // Multi-source gate: the points must come from ≥2 distinct corroborating
    // sources, so a single GPS-logging device's track can't assert a "footprint".
    let source_count = distinct_geo_sources(&parsed);
    if source_count < 2 {
        return Vec::new();
    }
    // Bundle every convex estimator — weighted centroid, geometric median + its
    // robust radius, and the Chebyshev bounding circle — in one call. The rule
    // owns the *policy* (which coordinates qualify); `util::geometry` owns the
    // *geometry* (how to estimate the location from them).
    let weighted: Vec<((f64, f64), f64)> = parsed
        .iter()
        .map(|(e, ll)| (*ll, e.c_effective()))
        .collect();
    let Some(fix) = crate::util::geometry::location_fix(&weighted) else {
        return Vec::new(); // fewer than 3 distinct, or all collinear → no area
    };
    let fp = &fix.footprint;

    let mut uids: Vec<String> = parsed.iter().map(|(e, _)| e.uid.clone()).collect();
    uids.sort_unstable();
    uids.dedup();
    let (severity, kind) = if fp.is_tight() {
        (Severity::High, "tight fix on a residence/base")
    } else {
        (Severity::Medium, "dispersed travel footprint")
    };
    vec![Correlation::new(
        "AU-052",
        "Geographic area of operation (convex footprint)",
        severity,
        format!(
            "{} coordinates from {} sources bound a {}-vertex area ({}); confidence-weighted \
             centroid {:.4},{:.4}, diameter {:.1} km — {kind}. {}",
            parsed.len(),
            source_count,
            fp.hull.len(),
            if fp.is_tight() { "tight" } else { "dispersed" },
            fix.weighted_centroid.0,
            fix.weighted_centroid.1,
            fp.diameter_km,
            fix.location_summary(),
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-053 — Out-of-area location anomaly (convex-hull membership).
///
/// Consumes the convex machinery to answer a question AU-052 doesn't: once a
/// subject has an *established* area, does any sighting fall **outside** it? Such
/// a point is a secondary base, a travel event, or planted/bad data — each a
/// lead worth surfacing on its own.
///
/// The test is principled, not a tunable radius: cluster the admissible
/// person-anchored coordinates (same infrastructure exclusion as AU-052), take
/// the *dominant* cluster (≥3 points) as the established area, build its convex
/// hull, and flag any other coordinate that is **not** inside that hull
/// ([`crate::util::geometry::point_in_convex_hull`]) *and* lies a guarded distance
/// beyond it (`max(50 km, 2× the area's diameter)` from the area's
/// confidence-weighted centroid). The hull supplies the shape; the guard ensures
/// a flagged point is genuinely a *different place*, not a hull vertex a few km
/// out. Dominant cluster and outliers are disjoint sets, so this never degenerates
/// the way a leave-one-out hull test would.
pub(in crate::core::correlator) fn rule_au_053_out_of_area_location(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use crate::util::geohash::haversine_km;
    use crate::util::geometry::{geo_footprint, point_in_convex_hull, weighted_centroid};

    let parsed = person_anchored_coords(entities);
    // Need an established area (≥3) plus at least one candidate outlier.
    if parsed.len() < 4 {
        return Vec::new();
    }
    if distinct_geo_sources(&parsed) < 2 {
        return Vec::new();
    }

    // Cluster by 0.5° boxes (same locality grain as AU-017), tracking indices.
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    for (idx, (_, (lat, lon))) in parsed.iter().enumerate() {
        let mut placed = false;
        for cl in &mut clusters {
            let (_, (rl, ro)) = parsed[cl[0]];
            if (lat - rl).abs() < 0.5 && (lon - ro).abs() < 0.5 {
                cl.push(idx);
                placed = true;
                break;
            }
        }
        if !placed {
            clusters.push(vec![idx]);
        }
    }
    // Dominant cluster = the largest; it must hold ≥3 points to be an established
    // area that bounds a hull. Ties resolve to the lowest first-index for
    // determinism.
    let Some(dominant) = clusters
        .iter()
        .max_by(|a, b| a.len().cmp(&b.len()).then(b[0].cmp(&a[0])))
        .filter(|c| c.len() >= 3)
        .cloned()
    else {
        return Vec::new();
    };
    let in_dominant: std::collections::HashSet<usize> = dominant.iter().copied().collect();

    let dom_pts: Vec<(f64, f64)> = dominant.iter().map(|&i| parsed[i].1).collect();
    let Some(fp) = geo_footprint(&dom_pts) else {
        return Vec::new(); // dominant area collinear → no hull
    };
    let dom_weighted: Vec<((f64, f64), f64)> = dominant
        .iter()
        .map(|&i| (parsed[i].1, parsed[i].0.c_effective()))
        .collect();
    let dom_centroid = weighted_centroid(&dom_weighted).unwrap_or(fp.centroid);
    let guard_km = (2.0 * fp.diameter_km).max(50.0);

    // Outliers: admissible points not in the dominant area that are both outside
    // its hull and beyond the guard distance from its centroid.
    let mut outliers: Vec<(&Entity, (f64, f64))> = Vec::new();
    for (idx, &(e, p)) in parsed.iter().enumerate() {
        if in_dominant.contains(&idx) {
            continue;
        }
        let outside = !point_in_convex_hull(&fp.hull, p);
        let far = haversine_km(dom_centroid.0, dom_centroid.1, p.0, p.1) > guard_km;
        if outside && far {
            outliers.push((e, p));
        }
    }
    if outliers.is_empty() {
        return Vec::new();
    }

    let mut uids: Vec<String> = dominant.iter().map(|&i| parsed[i].0.uid.clone()).collect();
    uids.extend(outliers.iter().map(|(e, _)| e.uid.clone()));
    uids.sort_unstable();
    uids.dedup();
    vec![Correlation::new(
        "AU-053",
        "Out-of-area location anomaly",
        Severity::Medium,
        format!(
            "Subject's established area is {} sightings around {:.4},{:.4}; {} sighting(s) fall \
             outside it (>{:.0} km away) — secondary location, travel, or planted data",
            dominant.len(),
            dom_centroid.0,
            dom_centroid.1,
            outliers.len(),
            guard_km,
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// Orthogonal **source classes** for cross-seed geo synergy. Two coordinates
/// that agree are far stronger evidence when they come from *different* classes
/// of source (a breach record and a business registry) than from two sources of
/// the same class (two IP-geo APIs), because independent collection methods
/// don't share the same systematic error. AU-059 scores convergence by the
/// number of distinct classes that agree, not the raw source count — this is the
/// "orthogonal approaches" principle made computable.
///
/// Every person-anchoring geo source maps to exactly one class; an unrecognised
/// source falls back to [`GeoSourceClass::Other`] so the classifier total-maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GeoSourceClass {
    /// Direct GPS/photo EXIF — a physical sighting of the subject's device.
    PhotoGps,
    /// Wi-Fi access-point geolocation (wardriving databases).
    WifiSensor,
    /// Geocoded street address (forward/reverse geocoders).
    Geocode,
    /// Government/business registry registered address (ABR, ASIC, GLEIF, ACNC).
    Registry,
    /// Public people-finder / unclaimed-money / residential directory.
    Directory,
    /// Self-reported social-profile location field.
    Social,
    /// Phone number → area/carrier city inference.
    Phone,
    /// Person-enrichment data-broker API (FullContact, proxycurl, epieos).
    Enrichment,
    /// Search-snippet inline geocoding.
    Search,
    /// Australian electoral roll — compulsory residential enrolment, AEC/state ECs.
    Electoral,
    /// Australian property/land title register — government-maintained ownership record.
    Property,
    /// Unrecognised / coarse (timezone clustering, etc.).
    Other,
}

/// Map a person-anchoring source name to its orthogonal [`GeoSourceClass`].
pub(crate) fn geo_source_class(source: &str) -> GeoSourceClass {
    match source {
        "exif_geo" => GeoSourceClass::PhotoGps,
        "wigle" | "mylnikov" => GeoSourceClass::WifiSensor,
        "geocode" | "photon" => GeoSourceClass::Geocode,
        "abn_lookup" | "opencorporates" | "acnc_charities" | "gleif_lei" | "asic_director" => {
            GeoSourceClass::Registry
        }
        "qld_unclaimed" | "au_unclaimed" | "au_people" => GeoSourceClass::Directory,
        "au_electoral" => GeoSourceClass::Electoral,
        "au_property" => GeoSourceClass::Property,
        "github_user" | "keybase" | "social_location" => GeoSourceClass::Social,
        "phone_area_geo" | "phone_carrier_geo" => GeoSourceClass::Phone,
        "epieos" | "contact_enrich" | "proxycurl" | "fullcontact" => GeoSourceClass::Enrichment,
        "search_engines" => GeoSourceClass::Search,
        _ => GeoSourceClass::Other,
    }
}

/// The distinct orthogonal source classes represented across a coordinate set.
fn distinct_geo_classes(
    parsed: &[(&Entity, (f64, f64))],
) -> std::collections::HashSet<GeoSourceClass> {
    let mut classes = std::collections::HashSet::new();
    for (e, _) in parsed {
        for src in e.corroborating_sources() {
            if is_anchoring_geo_source(src) {
                classes.insert(geo_source_class(src));
            }
        }
    }
    classes
}

/// True when a coordinate falls within Australia — either it carries an
/// explicit `au-state:` / `country:AU` tag (emitted at collection time) or its
/// lat/lon lands inside the AU bounding boxes. Restricts AU-059 to the subject's
/// home jurisdiction as required, without depending on tags alone.
fn is_australian_coord(e: &Entity, (lat, lon): (f64, f64)) -> bool {
    if e.has_tag("country:AU") || e.tags.iter().any(|t| t.starts_with("au-state:")) {
        return true;
    }
    crate::util::geo::is_in_australia(lat, lon)
}

/// AU-059 — Cross-seed geographic synergy (orthogonal-class location fix).
///
/// Where AU-052 needs ≥3 person-anchored coordinates *bounding an area* and
/// AU-057 takes the weighted median of *all* confirmed coordinates regardless of
/// jurisdiction, AU-059 answers the operator's actual question: **from whatever
/// combination of seeds this scan produced, what is the single best AU location
/// estimate, and how many independent kinds of source agree on it?**
///
/// It restricts to Australian person-anchored coordinates ([`is_australian_coord`]),
/// classifies each by its orthogonal [`GeoSourceClass`], and fires as soon as
/// **≥2 distinct source classes** converge — a far lower and more useful bar than
/// AU-052's area gate, so a name→registry hit plus a photo GPS already yields a
/// fix. The estimate is the confidence-weighted centroid, with each point's
/// weight multiplied by a small per-class-diversity bonus so a 3-class agreement
/// outranks a 1-class cluster of the same size.
///
/// Severity scales with synergy: ≥3 orthogonal classes ⇒ `High` (independent
/// collection methods agreeing is the strongest geo evidence short of a warrant);
/// exactly 2 ⇒ `Medium`. The dominant AU state is reported for jurisdictional
/// context (feeds AU-056).
pub(in crate::core::correlator) fn rule_au_059_cross_seed_geo_synergy(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Australian person-anchored coordinates only.
    let parsed: Vec<(&Entity, (f64, f64))> = person_anchored_coords(entities)
        .into_iter()
        .filter(|(e, ll)| is_australian_coord(e, *ll))
        .collect();
    if parsed.len() < 2 {
        return Vec::new();
    }

    // The synergy gate: ≥2 *distinct orthogonal source classes* must agree.
    let classes = distinct_geo_classes(&parsed);
    if classes.len() < 2 {
        return Vec::new();
    }

    // Confidence-weighted centroid, each weight boosted by class diversity so a
    // point corroborated across more orthogonal classes pulls proportionally more.
    let class_bonus = 1.0 + (classes.len() as f64 - 1.0) * 0.10;
    let weighted: Vec<((f64, f64), f64)> = parsed
        .iter()
        .map(|(e, ll)| (*ll, e.c_effective() * class_bonus))
        .collect();
    let Some((lat, lon)) = crate::util::geometry::weighted_centroid(&weighted) else {
        return Vec::new();
    };

    // Dominant AU state across the contributing coordinates (for AU-056 context).
    let state = au_state_majority(&parsed).unwrap_or("AU");

    // A scan-level synergy confidence: base on the strongest contributor, lifted
    // by orthogonal-class agreement, capped below certainty.
    let peak = parsed
        .iter()
        .map(|(e, _)| e.c_effective())
        .fold(0.0_f64, f64::max);
    let synergy_conf = (peak + (classes.len() as f64 - 1.0) * 0.08).min(0.97);

    let severity = if classes.len() >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };

    let mut class_names: Vec<&str> = classes.iter().map(geo_class_name).collect();
    class_names.sort_unstable();
    let gh = crate::util::geohash::geohash(lat, lon, 6);

    let mut uids: Vec<String> = parsed.iter().map(|(e, _)| e.uid.clone()).collect();
    uids.sort_unstable();
    uids.dedup();

    vec![Correlation::new(
        "AU-059",
        "Cross-seed geographic synergy (orthogonal-class fix)",
        severity,
        format!(
            "{} AU coordinate(s) from {} orthogonal source class(es) [{}] converge on \
             {lat:.4},{lon:.4} (geohash={gh}, state={state}); synergy confidence {synergy_conf:.2} \
             — MITRE T1591.001",
            parsed.len(),
            classes.len(),
            class_names.join(", "),
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// The majority AU state across a coordinate set, by `au-state:` tag where
/// present, else inferred from lat/lon. Ties resolve alphabetically for
/// determinism. `None` when no point resolves to a state.
fn au_state_majority(parsed: &[(&Entity, (f64, f64))]) -> Option<&'static str> {
    const STATES: &[&str] = &["ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"];
    let mut counts: std::collections::BTreeMap<&'static str, u32> =
        std::collections::BTreeMap::new();
    for (e, (lat, lon)) in parsed {
        // Prefer an explicit tag (collection-time), else derive from coords.
        let tagged = e.tags.iter().find_map(|t| {
            t.strip_prefix("au-state:")
                .and_then(|s| STATES.iter().copied().find(|st| *st == s))
        });
        let state = tagged.or_else(|| crate::util::geo::au_state_for_coords(*lat, *lon));
        if let Some(s) = state {
            *counts.entry(s).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))
        .map(|(s, _)| s)
}

/// Human-readable label for a [`GeoSourceClass`] (for correlation summaries).
fn geo_class_name(c: &GeoSourceClass) -> &'static str {
    match c {
        GeoSourceClass::PhotoGps => "photo-gps",
        GeoSourceClass::WifiSensor => "wifi",
        GeoSourceClass::Geocode => "geocode",
        GeoSourceClass::Registry => "registry",
        GeoSourceClass::Directory => "directory",
        GeoSourceClass::Social => "social",
        GeoSourceClass::Phone => "phone",
        GeoSourceClass::Enrichment => "enrichment",
        GeoSourceClass::Search => "search",
        GeoSourceClass::Electoral => "electoral",
        GeoSourceClass::Property => "property",
        GeoSourceClass::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
