use super::*;

use crate::util::geohash::geohash;

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
    vec![Correlation::new(
        "AU-016",
        "Breach IP → geolocation chain",
        Severity::High,
        format!(
            "{} breach IP(s) resolved to {} coordinate(s) via geolocation pipeline",
            breach_ips.len(),
            linked.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

pub(in crate::core::correlator) fn rule_au_017_multi_geo_convergence(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Cheap precondition: fewer than two confirmed coordinate entities can never
    // form a cluster, so bail before parsing anything.
    if entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Coordinates && e.confidence >= 0.50 && !is_infrastructure_geo(e)
        })
        .take(2)
        .count()
        < 2
    {
        return Vec::new();
    }
    // Parse once through the canonical, range-validating helper so out-of-range
    // junk ("200,300") is dropped here rather than silently clustered. Each
    // surviving entity carries its (lat, lon) so the inner loop never re-parses.
    // Filter and parse fuse into one pass — no intermediate `coords` Vec.
    // Infrastructure coordinates (a domain's hosting datacentre, a WHOIS
    // registrant location) are NOT the subject's whereabouts, so they must not
    // fuse into a "subject physically located here" convergence — parity with
    // AU-030/AU-099 and the sibling geo rules.
    let mut parsed: Vec<(&Entity, (f64, f64))> = entities
        .iter()
        .filter(|e| {
            e.kind == EntityKind::Coordinates && e.confidence >= 0.50 && !is_infrastructure_geo(e)
        })
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (c, ll)))
        .collect();
    // Deterministic clustering: the greedy single-link assignment below
    // compares each point against the FIRST member of each cluster, so both
    // which point founds a cluster and which cluster a borderline point joins
    // depend on iteration order. The live pass feeds entities in HashMap
    // (randomised) order, so a chain geometry (A–B close, B–C close, A–C far)
    // clustered as {A,B} on one run and {A,B,C} on another — different uid
    // sets that the live and finalise passes then both persist as distinct
    // AU-017 rows. Sort by uid so identical entity sets always cluster
    // identically, whatever order the caller iterated.
    parsed.sort_by(|a, b| a.0.uid.cmp(&b.0.uid));
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
            Correlation::new(
                "AU-017",
                "Multi-source geographic convergence",
                Severity::High,
                format!(
                    "{} coordinate entities converge within 0.5° (~55km), from {} source(s)",
                    cl.len(),
                    sources.len()
                ),
                uids,
                scan_id,
                ts,
            )
        })
        .collect()
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
        // NB: IP-geo sources (`ip_geo` / `ip2location` / `ip_whois_geo` /
        // `ipinfo`) are deliberately excluded — they locate the IP's
        // datacentre/ISP, not the subject's street address, so counting two of
        // them as "independent validation" geolocated the subject to a hosting
        // region (H5). Street-address validation needs geocoders / registries.
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
/// Fires when the scan holds both geo-tagged `Address` and `Coordinates`
/// entities (confidence ≥ 0.55) that resolve to ONE coherent place. A "validated
/// geolocation chain" is a single location, so the coordinates are clustered by
/// great-circle distance ([`crate::util::geohash::haversine_km`], permitted in
/// `core` — AU-017 already uses `geohash`) and the chain is anchored on the
/// DOMINANT cluster. Without this, deep recursion that surfaced a second city's
/// coordinates (a Brisbane subject also picking up a Cairns result ~1700 km
/// away) chained both into one continent-spanning "chain". Per-cluster spatial
/// convergence is AU-017's job; this asserts the *primary* address↔coordinate
/// location.
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

    // Geographic coherence. Parse the coordinates and greedy single-link cluster
    // them within COHERENCE_KM (one metro + surrounding region). Sort by uid so
    // the clustering is independent of the caller's (HashMap-random) iteration
    // order — the same determinism guard AU-017 uses.
    const COHERENCE_KM: f64 = 150.0;
    let mut parsed: Vec<(&Entity, (f64, f64))> = coords
        .iter()
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (*c, ll)))
        .collect();
    if parsed.is_empty() {
        return Vec::new();
    }
    parsed.sort_by(|a, b| a.0.uid.cmp(&b.0.uid));
    let mut clusters: Vec<Vec<(&Entity, (f64, f64))>> = Vec::new();
    for &(c, (lat, lon)) in &parsed {
        let joined = clusters.iter_mut().find(|cl| {
            let (_, (rl, ro)) = cl[0];
            crate::util::geohash::haversine_km(lat, lon, rl, ro) <= COHERENCE_KM
        });
        match joined {
            Some(cl) => cl.push((c, (lat, lon))),
            None => clusters.push(vec![(c, (lat, lon))]),
        }
    }
    // Anchor on the dominant (largest) cluster; tie-break on the smallest
    // founding uid so the choice is deterministic across runs.
    let dominant = clusters
        .iter()
        .max_by(|a, b| {
            a.len()
                .cmp(&b.len())
                .then_with(|| b[0].0.uid.cmp(&a[0].0.uid))
        })
        .expect("parsed is non-empty, so at least one cluster exists");
    let (anchor_lat, anchor_lon) = dominant[0].1;

    // Full member set (no `take` cap): the live/finalise passes must yield the same
    // uid SET so containment-dedup folds them — a `take(3)` of the HashMap-ordered
    // address list gave disjoint samples that persisted as duplicate AU-027 rows
    // (the AU-018 defect/fix). The described counts are already the full counts.
    let mut uids: Vec<String> = addresses.iter().map(|a| a.uid.clone()).collect();
    uids.extend(dominant.iter().map(|(c, _)| c.uid.clone()));
    vec![Correlation::new(
        "AU-027",
        "Address-coordinates geolocation chain",
        Severity::High,
        format!(
            "{} address(es) and {} coordinate set(s) form a validated geolocation chain near ({anchor_lat:.3}, {anchor_lon:.3})",
            addresses.len(),
            dominant.len(),
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
            matches!(e.kind, EntityKind::Address | EntityKind::Coordinates)
                && e.confidence >= 0.40
                // Exclude infrastructure geo (registrant/hosting/IP-only fixes):
                // otherwise a domain's registrant address + its hosting country
                // manufacture two of the three "independent sources" this
                // convergence score escalates to Critical on, geolocating the
                // subject to their domain's datacentre.
                && !is_infrastructure_geo(e)
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

/// AU-057 — Synthesised location fix (weighted geometric median).
///
/// Collects confirmed (`confidence ≥ 0.60`) **person-anchored** `Coordinates`
/// entities ([`is_infrastructure_geo`] — the same admissibility gate AU-052/053/059
/// already use, so a hosting IP, a map POI, or a bare IP/WHOIS-derived fix can
/// never enter the subject's "primary location" here either), weights each by
/// its confidence AND its source's real-world spatial precision
/// ([`precision_weight_multiplier`] — a GPS/geocode fix pulls harder than a
/// phone-carrier or search-snippet fix at equal confidence), and computes the
/// [`crate::util::geometry::weighted_geometric_median`] — the point that
/// minimises the weighted sum of great-circle distances to all inputs. This
/// converts the qualitative "sources agree" assertion from AU-017/AU-030 into a
/// single computable best-estimate lat/lon.
///
/// Before this gate existed, a live phone scan reproduced the exact failure it
/// prevents: a residential `ip_geo` fix (its own doc comment records "free
/// IP-geo providers routinely miss residential geolocation by 30-80 km") sat at
/// exactly the 0.60 floor and fused into this median at full, unweighted
/// footing — a "primary location" synthesised partly from infrastructure noise,
/// not a subject sighting.
///
/// Requires ≥ 2 valid inputs; `High` at ≥ 3 inputs, `Medium` at 2.
pub(in crate::core::correlator) fn rule_au_057_synthesised_location_fix(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let candidates: Vec<(&Entity, (f64, f64))> =
        entities_of_kind(entities, EntityKind::Coordinates)
            .into_iter()
            // Exclude infrastructure coordinates: a synthesised "location fix" must
            // come from the subject's own points, not a hosting/registrant datacentre.
            .filter(|e| e.confidence >= 0.60 && !is_infrastructure_geo(e))
            .filter_map(|e| crate::util::geohash::parse_coords(&e.value).map(|ll| (e, ll)))
            .collect();

    if candidates.len() < 2 {
        return Vec::new();
    }

    let weighted: Vec<((f64, f64), f64)> = candidates
        .iter()
        .map(|(e, ll)| {
            let precision_bonus =
                best_precision_radius_m(e).map_or(1.0, precision_weight_multiplier);
            (*ll, e.confidence * precision_bonus)
        })
        .collect();

    let Some((lat, lon)) = crate::util::geometry::weighted_geometric_median(&weighted) else {
        return Vec::new();
    };

    let gh = geohash(lat, lon, 5);
    let severity = if candidates.len() >= 3 {
        Severity::High
    } else {
        Severity::Medium
    };
    let uids: Vec<String> = candidates.iter().map(|(e, _)| e.uid.clone()).collect();

    // Name the synthesised primary location: reverse-geocode the median to its
    // nearest AU population centre (offline). The raw coordinate is the precise
    // estimate; the locality is the human "where does this person live" answer.
    let place = crate::util::geo::nearest_au_locality(lat, lon)
        .map(|(name, state, km)| {
            format!(" — estimated primary location near {name}, {state} (≈{km:.0} km)")
        })
        .unwrap_or_default();

    vec![Correlation::new(
        "AU-057",
        "Synthesised location fix (weighted median)",
        severity,
        format!(
            "Weighted geometric median of {} confirmed coordinate(s): ({lat:.4}, {lon:.4}) \
             geohash={gh}{place} — MITRE T1591.001",
            candidates.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}
