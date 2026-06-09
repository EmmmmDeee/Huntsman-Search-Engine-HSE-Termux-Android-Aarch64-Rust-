//! AU correlation rules — geo family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

pub(in crate::core::correlator) fn rule_au_013_local_network_discovery(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const LAN_TAGS: &[&str] = &["local-arp", "local-interface", "wifi-ap"];
    let hits: Vec<&Entity> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::IpAddress | EntityKind::MacAddress))
        .filter(|e| LAN_TAGS.iter().any(|t| e.has_tag(t)))
        .collect();
    if hits.len() < 2 {
        return Vec::new();
    }
    vec![Correlation {
        rule_id: "AU-013".into(),
        rule_name: "Local-network discovery".into(),
        severity: Severity::Low,
        description: format!(
            "{} entities observed on the local network (ARP / interfaces / Wi-Fi APs)",
            hits.len()
        ),
        entity_uids: hits.iter().map(|e| e.uid.clone()).collect(),
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(in crate::core::correlator) fn rule_au_014_geo_cluster(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const GEO_TAGS: &[&str] = &["geoint", "wifi-observed"];
    entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter_map(|e| {
            let hits: Vec<&str> = GEO_TAGS.iter().copied().filter(|t| e.has_tag(t)).collect();
            // Corroborating sources only: the deterministic `geo_normalize`
            // enrichment pass is not an independent geo observation, so a lone
            // postcode-centroid it touched must not look like a "cluster".
            let sources = e.corroborating_sources();
            if hits.len() >= 2 || sources.len() >= 2 {
                Some(Correlation {
                    rule_id: "AU-014".into(),
                    rule_name: "Geolocation cluster".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Coordinates '{}' confirmed by {} geo source(s)",
                        e.value,
                        sources.len().max(hits.len())
                    ),
                    entity_uids: vec![e.uid.clone()],
                    scan_id: scan_id.into(),
                    ts,
                    rank: 0.0,
                })
            } else {
                None
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_016_breach_ip_geo_chain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let breach_ips: Vec<&Entity> = entities_of_kind(entities, EntityKind::IpAddress)
        .into_iter()
        .filter(|e| e.has_tag("breach"))
        .collect();
    let coords: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
        .collect();
    if breach_ips.is_empty() || coords.is_empty() {
        return Vec::new();
    }
    let linked: Vec<&Entity> = coords
        .iter()
        .filter(|c| {
            c.evidence.iter().any(|ev| {
                breach_ips
                    .iter()
                    .any(|ip| text_mentions_ip(&ev.summary, &ip.value))
            })
        })
        .copied()
        .collect();
    if linked.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = breach_ips.iter().map(|e| e.uid.clone()).collect();
    uids.extend(linked.iter().map(|e| e.uid.clone()));
    vec![Correlation {
        rule_id: "AU-016".into(),
        rule_name: "Breach IP → geolocation chain".into(),
        severity: Severity::High,
        description: format!(
            "{} breach IP(s) resolved to {} coordinate(s) via geolocation pipeline",
            breach_ips.len(),
            linked.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(in crate::core::correlator) fn rule_au_017_multi_geo_convergence(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let coords: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .collect();
    if coords.len() < 2 {
        return Vec::new();
    }
    // Parse once through the canonical, range-validating helper so out-of-range
    // junk ("200,300") is dropped here rather than silently clustered. Each
    // surviving entity carries its (lat, lon) so the inner loop never re-parses.
    let parsed: Vec<(&Entity, (f64, f64))> = coords
        .iter()
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (*c, ll)))
        .collect();
    let mut clusters: Vec<Vec<(&Entity, (f64, f64))>> = Vec::new();
    for &(c, (lat, lon)) in &parsed {
        let mut found = false;
        for cluster in &mut clusters {
            let (_, (rl, ro)) = cluster[0];
            if (lat - rl).abs() < 0.5 && (lon - ro).abs() < 0.5 {
                cluster.push((c, (lat, lon)));
                found = true;
                break;
            }
        }
        if !found {
            clusters.push(vec![(c, (lat, lon))]);
        }
    }
    clusters
        .into_iter()
        .filter(|cl| cl.len() >= 2)
        .map(|cl| {
            let uids: Vec<String> = cl.iter().map(|(e, _)| e.uid.clone()).collect();
            let sources: HashSet<&str> = cl
                .iter()
                .flat_map(|(e, _)| e.evidence.iter().map(|ev| ev.source.as_str()))
                .collect();
            Correlation {
                rule_id: "AU-017".into(),
                rule_name: "Multi-source geographic convergence".into(),
                severity: Severity::High,
                description: format!(
                    "{} coordinate entities converge within 0.5° (~55km), from {} source(s)",
                    cl.len(),
                    sources.len()
                ),
                entity_uids: uids,
                scan_id: scan_id.into(),
                ts,
                rank: 0.0,
            }
        })
        .collect()
}

pub(in crate::core::correlator) fn rule_au_018_email_address_colocation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let emails: Vec<&Entity> = entities_of_kind(entities, EntityKind::Email)
        .into_iter()
        .filter(|e| e.confidence >= 0.60)
        .collect();
    let addresses: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Address | EntityKind::Coordinates) && e.confidence >= 0.50
        })
        .collect();
    if emails.is_empty() || addresses.is_empty() {
        return Vec::new();
    }
    let mut uids: Vec<String> = emails.iter().take(10).map(|e| e.uid.clone()).collect();
    uids.extend(addresses.iter().take(5).map(|e| e.uid.clone()));
    vec![Correlation {
        rule_id: "AU-018".into(),
        rule_name: "Email + physical location co-located".into(),
        severity: Severity::High,
        description: format!(
            "{} email(s) co-located with {} address/coordinate(s) — identity-location linkage",
            emails.len(),
            addresses.len()
        ),
        entity_uids: uids,
        scan_id: scan_id.into(),
        ts,
        rank: 0.0,
    }]
}

pub(in crate::core::correlator) fn rule_au_026_validated_address(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const GEO_SOURCES: &[&str] = &[
        "geocode",
        "photon",
        "geo_intel",
        "wigle",
        "overpass",
        "ip_geo",
        "ip2location",
        "ipapi",
        "ipinfo",
        "opencorporates",
        "epieos",
        "proxycurl",
        "contact_enrich",
        // Authoritative registries that emit a registered address (parity with
        // opencorporates): ACNC charities register + GLEIF LEI index.
        "acnc_charities",
        "gleif_lei",
    ];
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Address)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
    {
        let sources = tagged_matching_sources(e, GEO_SOURCES);
        if sources.len() >= 2 {
            let mut names: Vec<&str> = sources.into_iter().collect();
            names.sort_unstable();
            out.push(Correlation::new(
                "AU-026",
                "Multi-source validated address",
                Severity::High,
                format!(
                    "Address '{}' confirmed by {} independent source(s): {}",
                    e.value,
                    names.len(),
                    names.join(", ")
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

/// AU-027 — Address ↔ coordinates geolocation chain.
///
/// Co-presence signal: fires when the scan holds both geo-tagged `Address` and
/// `Coordinates` entities (confidence ≥ 0.55). It asserts that multiple geo
/// artefacts were derived for the subject, NOT that a given address geocodes to
/// a given coordinate — the correlator runs in `core` and cannot call the
/// `util::geohash` distance helpers (the `core_does_not_import_util` layering
/// invariant), so cross-kind proximity is intentionally not verified here.
/// Spatial proximity between coordinate sets is AU-017's job.
pub(in crate::core::correlator) fn rule_au_027_address_coordinates_chain(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let addresses: Vec<&Entity> = entities_of_kind(entities, EntityKind::Address)
        .into_iter()
        .filter(|e| e.confidence >= 0.55)
        .collect();
    let coords: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.55)
        .collect();
    if addresses.is_empty() || coords.is_empty() {
        return Vec::new();
    }
    let addr_has_geo_tag = addresses
        .iter()
        .any(|a| a.has_tag("geoint") || a.has_tag("reverse-geocoded") || a.has_tag("validated"));
    let coords_has_geo_tag = coords
        .iter()
        .any(|c| c.has_tag("geoint") || c.has_tag("geocoded"));
    if !addr_has_geo_tag && !coords_has_geo_tag {
        return Vec::new();
    }
    let mut uids: Vec<String> = addresses.iter().take(3).map(|a| a.uid.clone()).collect();
    uids.extend(coords.iter().take(3).map(|c| c.uid.clone()));
    vec![Correlation::new(
        "AU-027",
        "Address-coordinates geolocation chain",
        Severity::High,
        format!(
            "{} address(es) and {} coordinate set(s) form a validated geolocation chain",
            addresses.len(),
            coords.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-030 — Multi-source geolocation convergence (source breadth).
///
/// Measures how many INDEPENDENT sources produced geo entities for the subject
/// (`corroborating_sources`, so the unconditional `geo_normalize` enrichment
/// pass can't inflate the count), escalating Medium→High→Critical at 3/4/5+. It
/// is source *convergence* — many sources agreeing to provide geolocation — not
/// a check that those sources agree on the same place; cross-kind proximity is
/// not verified here (see AU-027 on why the correlator can't). AU-017 covers
/// spatial clustering of `Coordinates`.
pub(in crate::core::correlator) fn rule_au_030_geo_convergence_score(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let geo_entities: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::Address | EntityKind::Coordinates) && e.confidence >= 0.40
        })
        .collect();

    if geo_entities.len() < 2 {
        return Vec::new();
    }

    // Corroborating sources only — exclude the `geo_normalize` enrichment pass,
    // which touches every geo entity and would otherwise manufacture the third
    // "independent source" this convergence score requires out of nothing.
    let mut all_sources: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in &geo_entities {
        for src in e.corroborating_sources() {
            all_sources.insert(src);
        }
    }

    if all_sources.len() < 3 {
        return Vec::new();
    }

    let mut sources: Vec<&str> = all_sources.into_iter().collect();
    sources.sort_unstable();
    let uids: Vec<String> = geo_entities.iter().map(|e| e.uid.clone()).collect();

    let severity = if sources.len() >= 5 {
        Severity::Critical
    } else if sources.len() >= 4 {
        Severity::High
    } else {
        Severity::Medium
    };

    vec![Correlation::new(
        "AU-030",
        "Multi-source geolocation convergence",
        severity,
        format!(
            "{} independent sources produced {} geo entities: {}",
            sources.len(),
            geo_entities.len(),
            sources.join(", ")
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// Geolocation sources that resolve an *IP/host*, not a person: a coordinate
/// backed only by these is a datacenter/ISP/anycast location, never a residence.
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
const ANCHORING_GEO_SOURCES: &[&str] = &["geocode", "photon", "exif_geo", "wigle", "mylnikov"];

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
    let parsed: Vec<(&Entity, (f64, f64))> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .filter(|e| !is_infrastructure_geo(e))
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (c, ll)))
        .collect();
    if parsed.len() < 3 {
        return Vec::new();
    }
    // Multi-source gate: the points must come from ≥2 distinct corroborating
    // sources, so a single GPS-logging device's track can't assert a "footprint".
    let mut sources: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (e, _) in &parsed {
        for src in e.corroborating_sources() {
            sources.insert(src);
        }
    }
    if sources.len() < 2 {
        return Vec::new();
    }
    let points: Vec<(f64, f64)> = parsed.iter().map(|(_, ll)| *ll).collect();
    let Some(fp) = crate::util::geometry::geo_footprint(&points) else {
        return Vec::new(); // fewer than 3 distinct, or all collinear → no area
    };
    // Confidence-weighted centroid: the convex combination of the sightings by
    // each one's `c_effective`, so a GPS-exact photo pulls the centre harder than
    // a shaky IP-geo point. Being a convex combination it always lies inside the
    // hull. Falls back to the unweighted hull centroid only if the helper can't
    // form one (it can, given ≥1 point).
    let weighted: Vec<((f64, f64), f64)> = parsed
        .iter()
        .map(|(e, ll)| (*ll, e.c_effective()))
        .collect();
    let centroid = crate::util::geometry::weighted_centroid(&weighted).unwrap_or(fp.centroid);
    // The geometric median (Weber point) is the headline location fix: it
    // minimises the SUM of distances to the sightings and has a 0.5 breakdown
    // point, so a lone travel/VPN/planted outlier can't drag it off the
    // subject's real base — the property the centroid and Chebyshev centre lack.
    let gmed = crate::util::geometry::geometric_median(&points).unwrap_or(centroid);
    // Robust uncertainty for that fix: the MEDIAN distance from it to the
    // sightings. Same 0.5 breakdown point as the median itself, so a lone
    // outlier can't inflate it — the honest "± km" around the real base, paired
    // with an outlier-robust location instead of the worst-case Chebyshev radius.
    let gmed_spread = crate::util::geometry::median_distance_km(gmed, &points);
    // The Chebyshev centre (minimum-enclosing-circle centre) is retained as the
    // bounding circle: its radius is the honest worst-case uncertainty around the
    // footprint. `min_enclosing_circle` returns `Some` for any non-empty set.
    let mec = crate::util::geometry::min_enclosing_circle(&points);
    let (center, radius_km) = mec
        .map(|c| (c.center, c.radius_km))
        .unwrap_or((fp.centroid, fp.diameter_km / 2.0));

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
             centroid {:.4},{:.4}, diameter {:.1} km — {kind}. Best location fix (geometric \
             median, outlier-robust): {:.4},{:.4} ± {:.1} km (robust); bounding circle \
             (Chebyshev centre): {:.4},{:.4} ± {:.1} km",
            parsed.len(),
            sources.len(),
            fp.hull.len(),
            if fp.is_tight() { "tight" } else { "dispersed" },
            centroid.0,
            centroid.1,
            fp.diameter_km,
            gmed.0,
            gmed.1,
            gmed_spread,
            center.0,
            center.1,
            radius_km,
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

    let parsed: Vec<(&Entity, (f64, f64))> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.confidence >= 0.50)
        .filter(|e| !is_infrastructure_geo(e))
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (c, ll)))
        .collect();
    // Need an established area (≥3) plus at least one candidate outlier.
    if parsed.len() < 4 {
        return Vec::new();
    }
    // Multi-source gate, identical to AU-052.
    let mut sources: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (e, _) in &parsed {
        for src in e.corroborating_sources() {
            sources.insert(src);
        }
    }
    if sources.len() < 2 {
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

/// AU-032 — Geographic co-location cluster (graph-aware). Walks the
/// `CoLocatedWith` edge graph and reports each connected component of
/// `COLOCATION_CLUSTER_MIN`+ Coordinates entities — i.e. three or more
/// independent coordinate sources that transitively converge within
/// `CO_LOCATION_KM`. This is the graph-structural (transitive-closure) signal
/// the pairwise geo rules (AU-017/AU-030) don't surface. Deterministic:
/// component membership is edge-defined and the output is uid-sorted.
pub(in crate::core::correlator) fn rule_au_032_colocation_cluster(
    entities: &[Entity],
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{HashMap, HashSet};

    // Undirected adjacency from CoLocatedWith edges only.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations {
        if r.kind == RelationKind::CoLocatedWith {
            adj.entry(r.from_uid.as_str()).or_default().push(&r.to_uid);
            adj.entry(r.to_uid.as_str()).or_default().push(&r.from_uid);
        }
    }
    if adj.is_empty() {
        return Vec::new();
    }

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // Connected components via DFS (stack). Iterate seed nodes in sorted order
    // so the emitted clusters are deterministic regardless of edge ordering.
    let mut nodes: Vec<&str> = adj.keys().copied().collect();
    nodes.sort_unstable();
    let mut visited: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for &start in &nodes {
        if !visited.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut stack = vec![start];
        while let Some(n) = stack.pop() {
            if let Some(neighbours) = adj.get(n) {
                for &m in neighbours {
                    if visited.insert(m) {
                        comp.push(m);
                        stack.push(m);
                    }
                }
            }
        }
        if comp.len() >= COLOCATION_CLUSTER_MIN {
            comp.sort_unstable();
            let sample = by_uid.get(comp[0]).map_or(comp[0], |e| e.value.as_str());
            let uids: Vec<String> = comp.iter().map(|u| (*u).to_string()).collect();
            out.push(Correlation::new(
                "AU-032",
                "Geographic co-location cluster",
                Severity::Medium,
                format!(
                    "{} coordinates converge within {:.0} km (e.g. {})",
                    comp.len(),
                    crate::core::relation::CO_LOCATION_KM,
                    sample
                ),
                uids,
                scan_id,
                ts,
            ));
        }
    }
    out
}
