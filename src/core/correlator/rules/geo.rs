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
                        coord_set.iter().copied().enumerate().fold(
                            String::new(),
                            |mut acc, (i, s)| {
                                if i > 0 {
                                    acc.push('/');
                                }
                                acc.push_str(s);
                                acc
                            },
                        ),
                        addr_set.iter().copied().enumerate().fold(
                            String::new(),
                            |mut acc, (i, s)| {
                                if i > 0 {
                                    acc.push('/');
                                }
                                acc.push_str(s);
                                acc
                            },
                        ),
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
                coord_set
                    .iter()
                    .copied()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, s)| {
                        if i > 0 {
                            acc.push('/');
                        }
                        acc.push_str(s);
                        acc
                    },),
                addr_set
                    .iter()
                    .copied()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, s)| {
                        if i > 0 {
                            acc.push('/');
                        }
                        acc.push_str(s);
                        acc
                    },),
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
    // Cheap precondition: fewer than two confirmed coordinate entities can never
    // form a cluster, so bail before parsing anything.
    if entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates && e.confidence >= 0.50)
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
    let mut parsed: Vec<(&Entity, (f64, f64))> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Coordinates && e.confidence >= 0.50)
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

/// AU-060 — Cell-tower cross-validated (live sensor × crowdsourced database).
///
/// Fires when a `DeviceId` entity for a cell tower carries evidence from a
/// live on-device cellular sensor (`cell_intel`) *and* from at least one
/// crowdsourced database source (`opencellid` or `cell_local`).
///
/// The cross-validation matters because the two sources are fully independent:
/// `cell_intel` is a passive RF measurement — the device physically received
/// the tower's broadcast — while `opencellid`/`cell_local` is a pre-existing
/// crowdsourced catalogue that independently places the same tower at a known
/// lat/lon.  Agreement across those two channels is the strongest available
/// non-GPS, non-warrant cell-based location fix: the device was within radio
/// range of a tower whose position the database independently confirms.
pub(in crate::core::correlator) fn rule_au_060_cell_tower_cross_validation(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    const LIVE_SENSOR: &[&str] = &["cell_intel"];
    const DB_SOURCE: &[&str] = &["opencellid", "cell_local"];

    entities
        .iter()
        .filter(|e| e.kind == EntityKind::DeviceId && e.has_tag("cell-tower"))
        .filter(|e| {
            let srcs = e.evidence_sources();
            LIVE_SENSOR.iter().any(|s| srcs.contains(s))
                && DB_SOURCE.iter().any(|s| srcs.contains(s))
        })
        .map(|e| {
            Correlation::new(
                "AU-060",
                "Cell tower cross-validated (sensor × database)",
                Severity::Medium,
                format!(
                    "Cell tower {} confirmed by live RF sensor (cell_intel) and crowdsourced \
                     database (opencellid/cell_local) — location fix cross-validated at tower grain",
                    e.value
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            )
        })
        .collect()
}

/// AU-061 — Address locality corroborated by 3+ independent sources.
///
/// When the same AU suburb+state is asserted by three or more *distinct*
/// evidence sources — across any street addresses in that area — the
/// physical location is strongly corroborated.  Uses
/// [`crate::util::address_au::extract_first`] to parse the suburb and state
/// from each address entity, then groups by `"suburb state"` (lowercase).
///
/// The three-source threshold means at least three different collectors
/// (e.g. `au_people`, `search_engines`, `au_address`) independently placed
/// the subject in the same suburb — not merely one module emitting the
/// same address twice.
///
/// Severity High: independent corroboration of physical location is
/// actionable intelligence across skip-trace, asset recovery, and
/// welfare-check use cases.
pub(in crate::core::correlator) fn rule_au_061_address_locality_corroboration(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    use std::collections::{BTreeMap, BTreeSet};

    let addresses = entities_of_kind(entities, EntityKind::Address);

    // "suburb state" (lowercase) → (distinct_sources, contributing_uids, display_label)
    let mut locality_map: BTreeMap<String, (BTreeSet<String>, Vec<String>, String)> =
        BTreeMap::new();
    for e in &addresses {
        if e.confidence < 0.40 {
            continue;
        }
        let Some(parsed) = crate::util::address_au::extract_first(&e.value) else {
            continue;
        };
        let key = format!("{} {}", parsed.suburb.to_lowercase(), parsed.state);
        let entry = locality_map.entry(key).or_insert_with(|| {
            let display = format!("{}, {}", parsed.suburb, parsed.state);
            (BTreeSet::new(), Vec::new(), display)
        });
        for ev in &e.evidence {
            entry.0.insert(ev.source.clone());
        }
        if !entry.1.contains(&e.uid) {
            entry.1.push(e.uid.clone());
        }
    }

    let mut out = Vec::new();
    for (_, (sources, uids, display)) in &locality_map {
        if sources.len() < 3 {
            continue;
        }
        let mut src_list: Vec<&str> = sources.iter().map(String::as_str).collect();
        src_list.sort_unstable();
        out.push(Correlation::new(
            "AU-061",
            "Address locality corroborated by 3+ independent sources",
            Severity::High,
            format!(
                "Locality '{}' confirmed by {} independent source(s): {}",
                display,
                sources.len(),
                src_list.join(", ")
            ),
            uids.iter().take(5).cloned().collect(),
            scan_id,
            ts,
        ));
    }
    out
}

/// AU-062 — Address postcode↔state mismatch (anomaly signal).
///
/// Fires when an `Address` entity's four-digit postcode falls outside the
/// known range for the state it names.  The check uses
/// [`crate::util::address_au::state_for_postcode`] — the same function the
/// AU address parser uses — so the boundary conditions are consistent.
///
/// * **Planted/stale data**: a historical or synthetic address may carry a
///   correct suburb/state but a wrong postcode, or vice versa.
/// * **AU-062 × AU-056 synergy**: AU-056 cross-checks coordinates vs address
///   state; AU-062 cross-checks the address's own internal consistency.
///   Both firing together elevates confidence that something is off.
///
/// Only fires when the postcode positively maps to a *different* state; an
/// unrecognised postcode (e.g. an international format) is silently skipped.
pub(in crate::core::correlator) fn rule_au_062_postcode_state_mismatch(
    entities: &[Entity],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let mut out = Vec::new();
    for e in entities_of_kind(entities, EntityKind::Address) {
        if e.confidence < 0.40 {
            continue;
        }
        // Extract the stated state code from the address text.
        let Some(stated_state) = crate::util::address_au::state_code(&e.value) else {
            continue;
        };
        // Find a trailing 4-digit token that plausibly is the postcode.
        let Some(postcode) = e
            .value
            .split_whitespace()
            .rev()
            .find(|t| t.len() == 4 && t.chars().all(|c| c.is_ascii_digit()))
        else {
            continue;
        };
        // Check whether the postcode maps to a different state.
        if let Some(expected) = crate::util::address_au::state_for_postcode(postcode)
            && expected != stated_state
        {
            out.push(Correlation::new(
                "AU-062",
                "Address postcode–state mismatch",
                Severity::Medium,
                format!(
                    "Address '{}' states {} but postcode {} maps to {} — \
                     possible stale, planted, or OCR-corrupted data",
                    e.value, stated_state, postcode, expected
                ),
                vec![e.uid.clone()],
                scan_id,
                ts,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── coord_state ───────────────────────────────────────────────────────────

    #[test]
    fn coord_state_prefers_the_au_state_tag() {
        let mut e = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.6, "s");
        e.tag("au-state:QLD");
        assert_eq!(coord_state(&e), Some("QLD"));
    }

    #[test]
    fn coord_state_falls_back_to_lat_lon_when_untagged() {
        // Brisbane, no tag → derived from the coordinate.
        let e = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
        assert_eq!(coord_state(&e), Some("QLD"));
    }

    #[test]
    fn coord_state_none_below_threshold_or_wrong_kind() {
        let weak = Entity::new(EntityKind::Coordinates, "-27.47,153.02", 0.49, "s");
        assert_eq!(coord_state(&weak), None);
        let email = Entity::new(EntityKind::Email, "a@b.com", 0.9, "s");
        assert_eq!(coord_state(&email), None);
    }

    // ── extract_ratemyagent_suburb ────────────────────────────────────────────

    #[test]
    fn extract_ratemyagent_suburb_reads_slug_and_strips_query() {
        assert_eq!(
            extract_ratemyagent_suburb(
                "https://www.ratemyagent.com.au/real-estate-agent/john-smith-brisbane-abc12/"
            ),
            Some("brisbane".to_string())
        );
        // A trailing query string is stripped before parsing.
        assert_eq!(
            extract_ratemyagent_suburb(
                "https://www.ratemyagent.com.au/real-estate-agent/jane-doe-geelong-x9z?ref=1"
            ),
            Some("geelong".to_string())
        );
    }

    #[test]
    fn extract_ratemyagent_suburb_rejects_malformed_slugs() {
        // No agent path at all.
        assert_eq!(
            extract_ratemyagent_suburb("https://example.com/agent/x"),
            None
        );
        // Fewer than 4 hyphen parts.
        assert_eq!(
            extract_ratemyagent_suburb("https://x/real-estate-agent/a-b-c/"),
            None
        );
        // Suburb token carries a digit → rejected.
        assert_eq!(
            extract_ratemyagent_suburb("https://x/real-estate-agent/john-smith-bris2-abc12/"),
            None
        );
    }
}
