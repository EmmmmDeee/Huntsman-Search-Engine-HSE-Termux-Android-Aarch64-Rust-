//! GEOINT correlation rules — cross-kind chain and address-locality
//! consolidation family.
//!
//! Links geo entities to other signal classes — local-network discovery
//! (AU-013), breach-IP → coordinate chains (AU-016), email ↔ location
//! co-location (AU-018) — and consolidates multi-source address evidence
//! (AU-026), address ↔ coordinate chains (AU-027), and source-breadth
//! convergence (AU-030). See `super::super` (rules/mod.rs) for the shared
//! helpers; all reach them via `use super::*` → `geo/mod.rs` → `use super::*` →
//! `rules/mod.rs`.

use super::*;

pub(in crate::core::correlator) fn rule_au_013_local_network_discovery(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const LAN_TAGS: &[&str] = &["local-arp", "local-interface", "wifi-ap"];
    // Single filter pass: kind gate and tag probe folded together so each entity
    // is visited once (the kind check short-circuits the tag scan).
    let hits: Vec<&Entity> = entities
        .iter()
        .filter(|e| {
            matches!(e.kind, EntityKind::IpAddress | EntityKind::MacAddress)
                && LAN_TAGS.iter().any(|t| e.has_tag(t))
        })
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

pub(in crate::core::correlator) fn rule_au_018_email_address_colocation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    // Single pass partitions the two member classes instead of filtering the
    // entity list twice (once for emails, once for addresses/coordinates).
    let mut emails: Vec<&Entity> = Vec::new();
    let mut addresses: Vec<&Entity> = Vec::new();
    for e in entities {
        if e.kind == EntityKind::Email && e.confidence >= 0.60 {
            emails.push(e);
        } else if matches!(e.kind, EntityKind::Address | EntityKind::Coordinates)
            && e.confidence >= 0.50
        {
            addresses.push(e);
        }
    }
    if emails.is_empty() || addresses.is_empty() {
        return Vec::new();
    }
    // Include the FULL member set (no `take` cap). Entities only grow during a
    // scan, so the live-pass set is a strict subset of the finalize set — which
    // lets `upsert_correlation`'s containment dedup supersede the live partial
    // with the finalize row. A capped sample (`take(5)`) of a growing collection
    // produced DISJOINT live/finalize sets (different 5 addresses), which the
    // superset-supersede couldn't fold together, so AU-018 persisted twice
    // ("co-located with 6" and "with 9") for one scan.
    let mut uids: Vec<String> = emails.iter().map(|e| e.uid.clone()).collect();
    uids.extend(addresses.iter().map(|e| e.uid.clone()));
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

    let mut uids: Vec<String> = addresses.iter().take(3).map(|a| a.uid.clone()).collect();
    uids.extend(dominant.iter().take(3).map(|(c, _)| c.uid.clone()));
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
