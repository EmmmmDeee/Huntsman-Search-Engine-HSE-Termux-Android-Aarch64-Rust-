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
/// - `phone_area_geo` / `phone_carrier_geo` — phone number → city/carrier
///   inference (both source strings are now emitted by the merged `phone_geo`
///   module's two passes; the needles are retained here)
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
    // Both needles are emitted by the merged `phone_geo` module: its area-code
    // pass stamps `phone_area_geo`, its carrier pass `phone_carrier_geo`, so the
    // per-strategy geo-source classification below is preserved.
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
    // AU unclaimed-money registers — postcode-level, surname-anchored to the
    // subject. `au_unclaimed` covers all states; its Queensland pass (folded in
    // from the former `qld_unclaimed` module) still tags its evidence with the
    // `qld_unclaimed` source, so both needles are retained.
    "qld_unclaimed",
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

/// True when a geo entity (`Coordinates` **or** `Address`) does **not** locate
/// the subject and must be kept out of their footprint: it is `hosting`-tagged
/// (a CDN/cloud edge), it carries an `infra:` map-feature tag (an Overpass POI —
/// a camera, a cell tower — scraped near a geolocated point), it is a WHOIS
/// `registrant` location (the domain owner's filing/privacy address, not the
/// subject's home), or — **for `Coordinates` only** — it has no person-anchoring
/// corroborating source at all ([`ANCHORING_GEO_SOURCES`]), i.e. a bare lat/lon
/// resting purely on IP/WHOIS geo, chronolocation, or POI enrichment. Used by
/// the `Coordinates` rules (AU-052/053/059) and the `Address` rollup rules
/// (AU-018/026/030) so neither lets a registrant/hosting/IP-geo location vote
/// the subject's physical position.
pub(in crate::core::correlator) fn is_infrastructure_geo(e: &Entity) -> bool {
    // Single tag pass: detect the HOSTING tag, a WHOIS `registrant` location, and
    // any `infra:` map-feature tag together instead of separate `.iter()` scans.
    for t in &e.tags {
        if t == crate::core::tags::HOSTING
            || t == crate::core::tags::REGISTRANT
            || t.starts_with("infra:")
        {
            return true;
        }
    }
    // The "no person-anchoring source" heuristic only holds for `Coordinates`: a
    // bare lat/lon with no anchoring source is almost always an IP/WHOIS-derived
    // point. A street `Address` legitimately comes from registry sources
    // (au_property, au_electoral, qld_unclaimed, opencorporates) that are NOT in
    // ANCHORING_GEO_SOURCES, so applying the anchoring test to an address would
    // discard a real home — addresses are gated by the infra TAGS above only.
    e.kind == EntityKind::Coordinates
        && !e
            .corroborating_sources()
            .iter()
            .any(|s| ANCHORING_GEO_SOURCES.contains(s))
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
    /// A person's **breach/stealer login IP** geolocated to a city — their own
    /// network connection at the time, not infrastructure. Coarse (ISP/cell-tower
    /// grain) but person-linked, so it corroborates a locality the finer signals
    /// already point to.
    NetworkIp,
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
/// The structured AU-059 cross-seed geo-synergy fix — the **single source** of
/// the synthesised location, so the rule's prose and the API's `best_location`
/// fields can never disagree (the API used to recover these by string-splitting
/// the finding description, which drift-broke on any reword — Rule 3).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SynergyFix {
    /// Contributing AU person-anchored coordinates.
    pub count: usize,
    /// Distinct orthogonal source-class names, sorted.
    pub class_names: Vec<&'static str>,
    pub lat: f64,
    pub lon: f64,
    /// Robust confidence radius (km): the median great-circle distance from the
    /// fix point to the contributing coordinates — half the sightings fall
    /// within it, so it degrades gracefully under outliers (0.5 breakdown point).
    pub radius_km: f64,
    pub geohash: String,
    pub state: &'static str,
    pub synergy_confidence: f64,
    pub severity: Severity,
    /// UIDs of the contributing coordinate entities (sorted, deduped).
    pub uids: Vec<String>,
}

impl SynergyFix {
    /// The canonical AU-059 finding description, formatted from the structured
    /// fix so the prose and the fields are one and the same.
    pub(crate) fn description(&self) -> String {
        format!(
            "{} AU coordinate(s) from {} orthogonal source class(es) [{}] converge on \
             {lat:.4},{lon:.4} ± {radius:.1} km (geohash={gh}, state={state}); synergy \
             confidence {conf:.2} — MITRE T1591.001",
            self.count,
            self.class_names.len(),
            self.class_names.join(", "),
            lat = self.lat,
            lon = self.lon,
            radius = self.radius_km,
            gh = self.geohash,
            state = self.state,
            conf = self.synergy_confidence,
        )
    }
}

/// Compute the AU-059 cross-seed geo-synergy fix for a scan's entities, or `None`
/// when the synergy gate isn't met (fewer than two AU person-anchored
/// coordinates, or fewer than two distinct orthogonal source classes). Pure and
/// deterministic. Shared by the rule (which formats its finding from it) and the
/// API export (which reads its fields directly).
pub(crate) fn au059_synergy_fix(entities: &[Entity]) -> Option<SynergyFix> {
    // Australian person-anchored coordinates only.
    let parsed: Vec<(&Entity, (f64, f64))> = person_anchored_coords(entities)
        .into_iter()
        .filter(|(e, ll)| is_australian_coord(e, *ll))
        .collect();
    if parsed.len() < 2 {
        return None;
    }

    // The synergy gate: ≥2 *distinct orthogonal source classes* must agree.
    let classes = distinct_geo_classes(&parsed);
    if classes.len() < 2 {
        return None;
    }

    // Confidence-weighted centroid, each weight boosted by class diversity so a
    // point corroborated across more orthogonal classes pulls proportionally more.
    let class_bonus = 1.0 + (classes.len() as f64 - 1.0) * 0.10;
    let weighted: Vec<((f64, f64), f64)> = parsed
        .iter()
        .map(|(e, ll)| (*ll, e.c_effective() * class_bonus))
        .collect();
    let (lat, lon) = crate::util::geometry::weighted_centroid(&weighted)?;

    // Dominant AU state across the contributing coordinates (for AU-056 context).
    let state = au_state_majority(&parsed).unwrap_or("AU");

    // A scan-level synergy confidence: base on the strongest contributor, lifted
    // by orthogonal-class agreement, capped below certainty.
    let peak = parsed
        .iter()
        .map(|(e, _)| e.c_effective())
        .fold(0.0_f64, f64::max);
    let synergy_confidence = (peak + (classes.len() as f64 - 1.0) * 0.08).min(0.97);

    let severity = if classes.len() >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };

    let mut class_names: Vec<&'static str> = classes.iter().map(geo_class_name).collect();
    class_names.sort_unstable();

    let mut uids: Vec<String> = parsed.iter().map(|(e, _)| e.uid.clone()).collect();
    uids.sort_unstable();
    uids.dedup();

    // Robust spread: median distance from the fix to the contributing points.
    let points: Vec<(f64, f64)> = parsed.iter().map(|(_, ll)| *ll).collect();
    let radius_km = crate::util::geometry::median_distance_km((lat, lon), &points);

    Some(SynergyFix {
        count: parsed.len(),
        class_names,
        lat,
        lon,
        radius_km,
        geohash: crate::util::geohash::geohash(lat, lon, 6),
        state,
        synergy_confidence,
        severity,
        uids,
    })
}

/// A single best-effort Australian location estimate for the subject, with the
/// precision and provenance of whatever signal produced it. The headline "where
/// is this person" answer that works for the COMMON single-signal scan, not only
/// the multi-source synergy case [`au059_synergy_fix`] covers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuLocationEstimate {
    pub lat: f64,
    pub lon: f64,
    /// Precision radius (km) — finer for a GPS fix, coarser for a postcode centroid.
    pub radius_km: f64,
    pub state: &'static str,
    /// Nearest AU population centre (offline reverse geocode), if any.
    pub locality: Option<String>,
    /// How the estimate was derived (the precedence rung that produced it).
    pub basis: &'static str,
    pub confidence: f64,
    pub geohash: String,
    /// UID(s) of the contributing entity/entities.
    pub uids: Vec<String>,
}

/// Offline anchor for an Australian fixed-line **area-code region**: the
/// population-weighted centre (the dominant capital, where the overwhelming
/// majority of the region's landlines sit) and an honest precision radius that
/// bounds the region's populated extent. Keyed by the region slug from
/// [`crate::util::address_au::au_area_code_region`]. The radius is large by
/// design — a geographic area code locates a line only to its ACMA region, so
/// this is the coarsest, lowest-priority location signal; the wide radius keeps
/// the region-grain estimate honest rather than implying a precise point. Pure.
fn au_phone_region_anchor(slug: &str) -> Option<(f64, f64, f64)> {
    match slug {
        // NSW + ACT — Sydney centre; bounds the populated east coast and the ACT.
        "central-east" => Some((-33.8688, 151.2093, 650.0)),
        // VIC + TAS — Melbourne centre; reaches across Bass Strait to Tasmania.
        "south-east" => Some((-37.8136, 144.9631, 600.0)),
        // QLD — Brisbane centre; the state spans to the far north, hence wide.
        "north-east" => Some((-27.4698, 153.0251, 1200.0)),
        // SA + WA + NT — Adelaide centre; the largest region, an honest wide radius.
        "central-west" => Some((-34.9285, 138.6007, 1700.0)),
        _ => None,
    }
}

/// The `accuracy:<n>m` tag a device-sensor coordinate carries, in kilometres.
fn coord_accuracy_km(e: &Entity) -> Option<f64> {
    e.tags.iter().find_map(|t| {
        t.strip_prefix("accuracy:")
            .and_then(|s| s.strip_suffix('m'))
            .and_then(|n| n.parse::<f64>().ok())
            .map(|m| m / 1000.0)
    })
}

/// The single best Australian location estimate for the subject, by a fixed
/// precedence from finest to coarsest signal — so EVERY scan with any AU location
/// data yields one headline fix (with its precision), not only the multi-source
/// case. Pure and deterministic; the API export and the dossier read it directly.
///
/// Precedence:
/// 1. the multi-source cross-class synergy fix ([`au059_synergy_fix`]) — strongest;
/// 2. the most-confident single AU person-anchored coordinate (a GPS/sensor fix);
/// 3. an `exact-name-match` address resolved to its postcode-region centroid;
/// 4. any breach/register postcode resolved to its centroid;
/// 5. an Australian geographic landline's area-code region centroid — coarsest, a
///    region-grain fix ([`au_phone_region_anchor`]) used only when nothing finer
///    exists, so a subject known only by a fixed-line number still yields a fix.
///
/// `None` only when the scan has no resolvable AU location signal at all.
pub(crate) fn best_au_location_estimate(entities: &[Entity]) -> Option<AuLocationEstimate> {
    let locality_of = |lat: f64, lon: f64| {
        crate::util::geo::nearest_au_locality(lat, lon).map(|(n, _, _)| n.to_string())
    };

    // 1. Multi-source synergy (delegates to the shared finder — no drift).
    if let Some(fix) = au059_synergy_fix(entities) {
        return Some(AuLocationEstimate {
            lat: fix.lat,
            lon: fix.lon,
            radius_km: fix.radius_km,
            state: fix.state,
            locality: locality_of(fix.lat, fix.lon),
            basis: "multi-source cross-class synergy",
            confidence: fix.synergy_confidence,
            geohash: fix.geohash,
            uids: fix.uids,
        });
    }

    // 2. The most-confident single AU person-anchored coordinate.
    let best_coord = person_anchored_coords(entities)
        .into_iter()
        .filter(|(e, ll)| is_australian_coord(e, *ll))
        .max_by(|a, b| {
            a.0.c_effective()
                .partial_cmp(&b.0.c_effective())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    if let Some((e, (lat, lon))) = best_coord {
        return Some(AuLocationEstimate {
            lat,
            lon,
            radius_km: coord_accuracy_km(e).unwrap_or(2.0),
            state: crate::util::geo::au_state_for_coords(lat, lon).unwrap_or("AU"),
            locality: locality_of(lat, lon),
            basis: "confirmed coordinate",
            confidence: e.c_effective(),
            geohash: crate::util::geohash::geohash(lat, lon, 6),
            uids: vec![e.uid.clone()],
        });
    }

    // 3 & 4. Postcode-grain: a name-matched address outranks a bare breach/register
    // postcode. Among equal-rank candidates the most-confident wins; deterministic.
    // `Coordinates` are EXCLUDED — their `lat,lon` value's digits would be misread
    // as a postcode (e.g. `…,151.2093` → "2093"); a coordinate's location is rung 2.
    let mut pc: Vec<(u8, f64, &Entity, f64, f64)> = entities
        .iter()
        .filter(|e| e.kind != EntityKind::Coordinates)
        .filter_map(|e| {
            let pcode = crate::core::geo_family::au_postcode(e)?;
            let (lat, lon) = crate::util::city_coords::city_coords(&pcode)?;
            let rank = if e.has_tag("exact-name-match") { 1 } else { 0 };
            Some((rank, e.c_effective(), e, lat, lon))
        })
        .collect();
    pc.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| a.2.uid.cmp(&b.2.uid))
    });
    if let Some((rank, _, e, lat, lon)) = pc.first().copied() {
        return Some(AuLocationEstimate {
            lat,
            lon,
            radius_km: 8.0, // postcode / suburb grain
            state: crate::util::geo::au_state_for_coords(lat, lon).unwrap_or("AU"),
            locality: locality_of(lat, lon),
            basis: if rank == 1 {
                "name-matched address (postcode grain)"
            } else {
                "breach/register postcode"
            },
            confidence: e.c_effective(),
            geohash: crate::util::geohash::geohash(lat, lon, 6),
            uids: vec![e.uid.clone()],
        });
    }

    // 5. Coarsest rung — an Australian geographic landline's area code locates the
    //    line to its ACMA region. Mobiles (`04…`), VoIP and service numbers carry
    //    no region (`au_phone_region` returns None) and are skipped. Only fires when
    //    every finer rung above produced nothing; the wide anchor radius keeps the
    //    region-grain estimate honest. A `platform-infra`-tagged number (scraped
    //    from a third-party page) is excluded as not subject-owned.
    let best_phone = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Phone && e.confidence >= 0.40 && !e.has_tag("platform-infra")
        })
        .filter_map(|e| {
            let (slug, _name, _states) = crate::util::address_au::au_phone_region(&e.value)?;
            let (lat, lon, radius_km) = au_phone_region_anchor(slug)?;
            Some((e, lat, lon, radius_km))
        })
        .max_by(|a, b| {
            a.0.c_effective()
                .partial_cmp(&b.0.c_effective())
                .unwrap_or(std::cmp::Ordering::Equal)
                // Equal confidence: smaller UID wins (reverse compare → "greater").
                .then_with(|| b.0.uid.cmp(&a.0.uid))
        });
    if let Some((e, lat, lon, radius_km)) = best_phone {
        return Some(AuLocationEstimate {
            lat,
            lon,
            radius_km,
            state: crate::util::geo::au_state_for_coords(lat, lon).unwrap_or("AU"),
            locality: locality_of(lat, lon),
            basis: "landline area-code region",
            // Region grain is a weak fix: down-weight hard and cap low so it can
            // never rival a true point fix in any downstream confidence read.
            confidence: (e.c_effective() * 0.5).min(0.35),
            geohash: crate::util::geohash::geohash(lat, lon, 4),
            uids: vec![e.uid.clone()],
        });
    }

    None
}

/// The most-specific orthogonal [`GeoSourceClass`] an entity's corroborating
/// sources map to — preferring a recognised class over the [`GeoSourceClass::Other`]
/// fallback, so a register postcode counts as `Directory`/`Electoral`/… (a real
/// independent method) rather than collapsing to `Other`. Deterministic: scans the
/// sorted source set and keeps the first non-`Other` class it meets.
fn best_geo_class(e: &Entity) -> GeoSourceClass {
    let mut sources: Vec<&str> = e.corroborating_sources().into_iter().collect();
    sources.sort_unstable();
    sources
        .iter()
        .map(|s| geo_source_class(s))
        .find(|c| *c != GeoSourceClass::Other)
        .unwrap_or(GeoSourceClass::Other)
}

/// A multi-source Australian **geolocation corroboration** — the locality the most
/// *independent kinds of source* agree on, and how strongly. The output of
/// [`au_location_corroboration`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LocationCorroboration {
    pub lat: f64,
    pub lon: f64,
    /// Spread (km) of the agreeing signals around the centroid.
    pub radius_km: f64,
    pub state: &'static str,
    /// Nearest AU population centre to the centroid (offline reverse geocode).
    pub locality: Option<String>,
    /// Distinct orthogonal source classes converging on this locality — the
    /// independence count that makes the fix trustworthy (`1` = single-source).
    pub independent_classes: usize,
    /// Total agreeing signals (entities) in the cluster.
    pub signal_count: usize,
    /// Names of the converging classes, sorted — the human-readable basis.
    pub class_names: Vec<&'static str>,
    /// Corroboration-weighted confidence: `1 − 0.55^independent_classes`, so each
    /// extra independent method lifts trust (1→0.45, 2→0.70, 3→0.83, 4→0.91).
    pub confidence: f64,
}

/// Distance (km) within which two AU **locality-grain** signals are treated as the
/// same area of operation — generous enough to group the suburbs/towns of one
/// region (e.g. the Sunshine Coast postcodes 4552 & 4557, ~25 km apart) yet tight
/// enough to keep distinct capitals apart.
const SAME_AREA_KM: f64 = 60.0;

/// Score how strongly **independent** Australian location signals corroborate one
/// locality — the Interpol-grade "how many different methods agree, and where"
/// geolocation question, over the BROAD signal set (not just GPS).
///
/// Where [`au059_synergy_fix`] requires ≥2 person-anchored `Coordinates` (a GPS /
/// Wi-Fi / geocode fix), this also folds in the **postcode-grain** signals that the
/// *majority* of Australian entities actually carry — a breach/register postcode, a
/// people-finder suburb, a name-matched street address — each resolved offline to a
/// centroid ([`crate::util::city_coords::city_coords`]) and classed by its
/// orthogonal [`GeoSourceClass`]. It then finds the locality (within
/// [`SAME_AREA_KM`]) that the most *distinct* source classes agree on and reports
/// that independence count, so a subject located only by postcodes — no GPS at all
/// — still gets a corroborated, trust-scored fix instead of a bare single-source
/// guess. `Coordinates` are excluded from the postcode pass (their lat/lon digits
/// would be misread as a postcode); `platform-infra` entities never contribute.
///
/// Pure, offline and deterministic. `None` only when the scan holds no resolvable
/// AU locality signal at all.
pub(crate) fn au_location_corroboration(entities: &[Entity]) -> Option<LocationCorroboration> {
    use std::collections::HashSet;

    // One locality-grain signal per entity: a precise AU coordinate, else a
    // postcode/address centroid. Each carries its orthogonal source class.
    struct Sig {
        lat: f64,
        lon: f64,
        class: GeoSourceClass,
        uid: String,
    }
    let mut sigs: Vec<Sig> = Vec::new();

    for (e, (lat, lon)) in person_anchored_coords(entities)
        .into_iter()
        .filter(|(e, ll)| is_australian_coord(e, *ll))
    {
        sigs.push(Sig {
            lat,
            lon,
            class: best_geo_class(e),
            uid: e.uid.clone(),
        });
    }
    for e in entities
        .iter()
        .filter(|e| e.kind != EntityKind::Coordinates && !e.has_tag("platform-infra"))
    {
        let Some(pc) = crate::core::geo_family::au_postcode(e) else {
            continue;
        };
        let Some((lat, lon)) = crate::util::city_coords::city_coords(&pc) else {
            continue;
        };
        sigs.push(Sig {
            lat,
            lon,
            class: best_geo_class(e),
            uid: e.uid.clone(),
        });
    }
    // The person's own breach/stealer LOGIN IP, geolocated to a city — their
    // network connection, not infrastructure. The breach modules tag a login IP
    // `geolocation-lead`; ip_geo then resolves it to an AU `Coordinates` carrying
    // an `ip` evidence attribute. A coordinate whose `ip` is one of those leads,
    // and which is not a datacenter/proxy IP, is a coarse but person-linked fix —
    // exactly the signal a breach dump's `lastip` provides for most AU victims.
    let login_ips: HashSet<&str> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::IpAddress && e.has_tag("geolocation-lead"))
        .map(|e| e.value.as_str())
        .collect();
    if !login_ips.is_empty() {
        for e in entities.iter().filter(|e| {
            e.kind == EntityKind::Coordinates
                && !e.has_tag("hosting")
                && !e.has_tag("proxy")
                && !e.has_tag("platform-infra")
        }) {
            let is_login_ip_geo = e.evidence.iter().any(|ev| {
                ev.attributes
                    .get("ip")
                    .is_some_and(|ip| login_ips.contains(ip.as_str()))
            });
            if !is_login_ip_geo {
                continue;
            }
            let Some((lat, lon)) = crate::util::geohash::parse_coords(&e.value) else {
                continue;
            };
            if !crate::util::geo::is_in_australia(lat, lon) {
                continue;
            }
            sigs.push(Sig {
                lat,
                lon,
                class: GeoSourceClass::NetworkIp,
                uid: e.uid.clone(),
            });
        }
    }
    if sigs.is_empty() {
        return None;
    }

    // For each signal, the indices of every signal within SAME_AREA_KM of it.
    let members: Vec<Vec<usize>> = sigs
        .iter()
        .map(|c| {
            sigs.iter()
                .enumerate()
                .filter(|(_, s)| {
                    crate::util::geo::haversine_km(c.lat, c.lon, s.lat, s.lon) <= SAME_AREA_KM
                })
                .map(|(i, _)| i)
                .collect()
        })
        .collect();
    let distinct_classes = |idxs: &[usize]| -> usize {
        idxs.iter()
            .map(|&i| sigs[i].class)
            .collect::<HashSet<_>>()
            .len()
    };

    // The locality the most distinct classes agree on (then the most signals);
    // deterministic UID tie-break.
    let best = (0..sigs.len()).max_by(|&a, &b| {
        distinct_classes(&members[a])
            .cmp(&distinct_classes(&members[b]))
            .then(members[a].len().cmp(&members[b].len()))
            .then_with(|| sigs[b].uid.cmp(&sigs[a].uid))
    })?;
    let cluster = &members[best];

    // Centroid (mean) of the agreeing signals; spread = farthest member from it.
    let n = cluster.len() as f64;
    let lat = cluster.iter().map(|&i| sigs[i].lat).sum::<f64>() / n;
    let lon = cluster.iter().map(|&i| sigs[i].lon).sum::<f64>() / n;
    let radius_km = cluster
        .iter()
        .map(|&i| crate::util::geo::haversine_km(lat, lon, sigs[i].lat, sigs[i].lon))
        .fold(0.0_f64, f64::max)
        .max(8.0); // never claim sub-postcode precision from a single signal

    let mut classes: Vec<GeoSourceClass> = cluster
        .iter()
        .map(|&i| sigs[i].class)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let independent_classes = classes.len();
    classes.sort_unstable_by_key(geo_class_name);
    let class_names: Vec<&'static str> = classes.iter().map(geo_class_name).collect();

    Some(LocationCorroboration {
        lat,
        lon,
        radius_km,
        state: crate::util::geo::au_state_for_coords(lat, lon).unwrap_or("AU"),
        locality: crate::util::geo::nearest_au_locality(lat, lon).map(|(n, _, _)| n.to_string()),
        independent_classes,
        signal_count: cluster.len(),
        class_names,
        confidence: 1.0 - 0.55_f64.powi(independent_classes as i32),
    })
}

pub(in crate::core::correlator) fn rule_au_059_cross_seed_geo_synergy(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let Some(fix) = au059_synergy_fix(entities) else {
        return Vec::new();
    };
    vec![Correlation::new(
        "AU-059",
        "Cross-seed geographic synergy (orthogonal-class fix)",
        fix.severity,
        fix.description(),
        fix.uids.clone(),
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
        GeoSourceClass::NetworkIp => "network-ip",
        GeoSourceClass::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
