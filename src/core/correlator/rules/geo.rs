//! AU correlation rules — geo family. See `super` (rules/mod.rs) for the
//! shared helpers; every rule reaches them through `use super::*`.

use super::*;

use crate::util::geohash::geohash;

/// The AU state/territory a confirmed `Coordinates` entity asserts. Prefers the
/// `au-state:XX` tag the geo builders attach, but falls back to deriving the
/// state straight from the lat/long via [`crate::util::geo::au_state_for_coords`]
/// when the tag is absent — a coordinate enters the graph from many modules
/// (`geo_normalize`, `search_engines`, `exif_geo`, …), only three of which tag
/// it, so a tag-only read silently dropped most real fixes (seen on a live
/// scan: a Brisbane coordinate from `geo_normalize` carried no tag and the
/// jurisdiction cross-check never fired). Only confirmed fixes (≥0.50) count, so
/// an off-region candidate can't assert a jurisdiction.
fn coord_state(e: &Entity) -> Option<&'static str> {
    if e.kind != EntityKind::Coordinates || e.confidence < 0.50 {
        return None;
    }
    const AU_STATES: [&str; 8] = ["ACT", "NSW", "NT", "QLD", "SA", "TAS", "VIC", "WA"];
    if let Some(state) = e
        .tags
        .iter()
        .find_map(|t| t.strip_prefix("au-state:"))
        .and_then(|code| AU_STATES.into_iter().find(|s| *s == code))
    {
        return Some(state);
    }
    crate::util::geohash::parse_coords(&e.value)
        .and_then(|(lat, lon)| crate::util::geo::au_state_for_coords(lat, lon))
}

/// AU-056 — Jurisdiction cross-check (coordinate state vs address state).
///
/// The synergy lever for the new offline state attribution: a subject's
/// location is asserted independently by two signal classes — a `Coordinates`
/// fix (tagged `au-state:` from its lat/long) and an `Address`/postcode (whose
/// state is parsed by [`crate::util::address_au::state_code`]). This rule
/// reconciles them:
///
/// * **Agreement** — both classes name the *same* state → a corroboration that
///   raises confidence in the location at jurisdiction grain (High when each
///   side speaks with one voice, Medium when one side is mixed).
/// * **Conflict** — the two classes name *disjoint* states (coordinates say
///   QLD, every address says VIC) → a Medium anomaly worth surfacing: travel, a
///   secondary base, or planted/stale data.
///
/// Requires at least one state from *each* class; a scan with only coordinates,
/// or only addresses, yields nothing (there is nothing to cross-check). Pure
/// over the confirmed entity set.
pub(in crate::core::correlator) fn rule_au_056_jurisdiction_cross_check(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    // state -> contributing uids, for each signal class.
    let mut coord_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut addr_states: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for e in entities {
        if let Some(state) = coord_state(e) {
            coord_states.entry(state).or_default().push(e.uid.clone());
        } else if e.kind == EntityKind::Address
            && e.confidence >= 0.50
            && let Some(state) = crate::util::address_au::state_code(&e.value)
        {
            addr_states.entry(state).or_default().push(e.uid.clone());
        }
    }

    if coord_states.is_empty() || addr_states.is_empty() {
        return Vec::new();
    }

    let coord_set: BTreeSet<&'static str> = coord_states.keys().copied().collect();
    let addr_set: BTreeSet<&'static str> = addr_states.keys().copied().collect();
    let shared: Vec<&'static str> = coord_set.intersection(&addr_set).copied().collect();

    let mut uids: Vec<String> = coord_states
        .values()
        .chain(addr_states.values())
        .flatten()
        .cloned()
        .collect();
    uids.sort_unstable();
    uids.dedup();

    let correlation = if let Some(&state) = shared.first() {
        // Agreement. High only when neither class is internally split AND the
        // shared state is the *only* state either class names.
        let unanimous = coord_set.len() == 1 && addr_set.len() == 1;
        let severity = if unanimous {
            Severity::High
        } else {
            Severity::Medium
        };
        Correlation::new(
            "AU-056",
            "Jurisdiction corroborated (coordinate + address)",
            severity,
            format!(
                "Coordinate fix(es) and address/postcode(s) independently place the subject in \
                 {state} — location corroborated at state grain{}",
                if unanimous {
                    String::new()
                } else {
                    format!(
                        " (coordinates: {}; addresses: {})",
                        coord_set.iter().copied().collect::<Vec<_>>().join("/"),
                        addr_set.iter().copied().collect::<Vec<_>>().join("/"),
                    )
                }
            ),
            uids,
            scan_id,
            ts,
        )
    } else {
        Correlation::new(
            "AU-056",
            "Jurisdiction conflict (coordinate vs address)",
            Severity::Medium,
            format!(
                "Coordinate fix(es) place the subject in {} but address/postcode(s) say {} — \
                 travel, a secondary base, or planted/stale data",
                coord_set.iter().copied().collect::<Vec<_>>().join("/"),
                addr_set.iter().copied().collect::<Vec<_>>().join("/"),
            ),
            uids,
            scan_id,
            ts,
        )
    };

    vec![correlation]
}

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
    let mut parsed: Vec<(&Entity, (f64, f64))> = coords
        .iter()
        .filter_map(|c| crate::util::geohash::parse_coords(&c.value).map(|ll| (*c, ll)))
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

/// AU-057 — Synthesised location fix (weighted geometric median).
///
/// Collects all confirmed (`confidence ≥ 0.60`) `Coordinates` entities, weights
/// each by its confidence, and computes the
/// [`crate::util::geometry::weighted_geometric_median`] — the point that
/// minimises the confidence-weighted sum of great-circle distances to all
/// inputs. This converts the qualitative "sources agree" assertion from
/// AU-017/AU-030 into a single computable best-estimate lat/lon.
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
            .filter(|e| e.confidence >= 0.60)
            .filter_map(|e| crate::util::geohash::parse_coords(&e.value).map(|ll| (e, ll)))
            .collect();

    if candidates.len() < 2 {
        return Vec::new();
    }

    let weighted: Vec<((f64, f64), f64)> = candidates
        .iter()
        .map(|(e, ll)| (*ll, e.confidence))
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

    vec![Correlation::new(
        "AU-057",
        "Synthesised location fix (weighted median)",
        severity,
        format!(
            "Weighted geometric median of {} confirmed coordinate(s): ({lat:.4}, {lon:.4}) \
             geohash={gh} — MITRE T1591.001",
            candidates.len()
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-058 — Professional profile geographic signal (T1591.002).
///
/// AU real estate agent profile URLs embed a suburb-level workplace location in
/// the URL slug — no live HTTP fetch required. ratemyagent.com.au slugs follow
/// `/real-estate-agent/<name>-<suburb>-<id>/`; the suburb token is extracted and
/// surfaced as a geographic signal aligned with MITRE T1591.002 (Business
/// Relationships — physical location inferred from professional context).
pub(in crate::core::correlator) fn rule_au_058_professional_profile_geo(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const PROF_HOSTS: &[&str] = &["ratemyagent.com.au", "homely.com.au", "soho.com.au"];

    let mut out = Vec::new();

    for e in entities_of_kind(entities, EntityKind::Url) {
        if e.confidence < 0.45 {
            continue;
        }
        let url_lower = e.value.to_lowercase();
        let Some(host) = PROF_HOSTS.iter().find(|h| url_lower.contains(*h)) else {
            continue;
        };

        let suburb = if host.contains("ratemyagent") {
            extract_ratemyagent_suburb(&e.value)
        } else {
            None
        };

        let Some(suburb) = suburb else {
            continue;
        };

        out.push(Correlation::new(
            "AU-058",
            "Professional profile geographic signal",
            Severity::Medium,
            format!(
                "Real estate agent profile at {host} indicates subject operates in \
                 '{suburb}' — MITRE T1591.002 (Business Relationships)"
            ),
            vec![e.uid.clone()],
            scan_id,
            ts,
        ));
    }

    out
}

/// Extract the suburb token from a ratemyagent.com.au agent URL slug.
///
/// Pattern: `/real-estate-agent/<name>-<suburb>-<id>/`
/// The trailing ID is stripped; the preceding token is the suburb.
fn extract_ratemyagent_suburb(url: &str) -> Option<String> {
    let path_start = url.find("/real-estate-agent/")?;
    let slug_area = &url[path_start + "/real-estate-agent/".len()..];
    let slug = slug_area
        .trim_end_matches('/')
        .split('?')
        .next()
        .unwrap_or(slug_area);
    let parts: Vec<&str> = slug.split('-').collect();
    if parts.len() < 4 {
        return None;
    }
    let id = *parts.last()?;
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) || id.len() < 2 {
        return None;
    }
    let suburb = parts[parts.len() - 2];
    if suburb.len() >= 4 && suburb.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(suburb.to_string())
    } else {
        None
    }
}
