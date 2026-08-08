use super::*;

pub(in crate::core::correlator) fn rule_au_013_local_network_discovery(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    const LAN_TAGS: &[&str] = &[
        crate::core::tags::LOCAL_ARP,
        crate::core::tags::LOCAL_INTERFACE,
        crate::core::tags::WIFI_AP,
    ];
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
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        // Mirror AU-017: a coordinate must clear a confidence floor AND not be
        // infrastructure geo — a datacentre/hosting/CDN point, or any bare
        // IP/WHOIS coordinate with no anchoring source. Without this a hosting
        // centroid that merely carries two enrichment sources surfaced as a
        // confirmed personal geo lead.
        .filter(|e| e.confidence >= 0.50 && !is_infrastructure_geo(e))
        .filter_map(|e| {
            // Corroborating sources only: the deterministic `geo_normalize`
            // enrichment pass is not an independent geo observation, so a lone
            // postcode-centroid it touched must not look like a "cluster".
            //
            // A `geoint`/`wifi-observed` TAG count was formerly accepted as an
            // independent alternative gate here, and the reported count took
            // whichever of the two was larger. That double-counted: a single
            // WiGLE observation tags its Coordinates entity BOTH `wifi-observed`
            // and `geoint` from one `wigle` evidence record
            // (`modules::wigle::named_ap_entities`), so a lone WiGLE source
            // alone cleared the tag gate and the finding claimed "confirmed by
            // 2 geo source(s)" for a coordinate one source produced. A tag is
            // not a source; only `corroborating_sources` counts independent
            // corroboration.
            let sources = e.corroborating_sources();
            if sources.len() >= 2 {
                Some(Correlation {
                    rule_id: "AU-014".into(),
                    rule_name: "Geolocation cluster".into(),
                    severity: Severity::Medium,
                    description: format!(
                        "Coordinates '{}' confirmed by {} geo source(s)",
                        e.value,
                        sources.len()
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

/// AU-032 — Geographic co-location cluster (graph-aware). Walks the
/// `CoLocatedWith` edge graph and reports each connected component of
/// `COLOCATION_CLUSTER_MIN`+ Coordinates entities — i.e. three or more
/// independent coordinate sources that transitively converge within
/// `CO_LOCATION_KM`. This is the graph-structural (transitive-closure) signal
/// the pairwise geo rules (AU-017/AU-030) don't surface. Deterministic:
/// component membership is edge-defined and the output is uid-sorted.
pub(in crate::core::correlator) fn rule_au_032_colocation_cluster(
    context: &RuleContext,
    relations: &[Relation],
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    use std::collections::{HashMap, HashSet};

    let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    // Undirected adjacency from CoLocatedWith edges — but ONLY between two
    // non-infrastructure coordinates. A datacentre/hosting/CDN point (or any bare
    // IP-geo coordinate with no anchoring source) must not be a node in a
    // co-location cluster: a shared host would otherwise bridge unrelated people
    // into a false "geographic convergence", and a cluster of co-located
    // datacentres would report as one. Gating the EDGES (not just the final
    // component) stops an infra node from transitively linking two real
    // person-clusters before it could be pruned.
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in relations {
        if r.kind == RelationKind::CoLocatedWith
            && by_uid
                .get(r.from_uid.as_str())
                .is_some_and(|e| !is_infrastructure_geo(e))
            && by_uid
                .get(r.to_uid.as_str())
                .is_some_and(|e| !is_infrastructure_geo(e))
        {
            adj.entry(r.from_uid.as_str()).or_default().push(&r.to_uid);
            adj.entry(r.to_uid.as_str()).or_default().push(&r.from_uid);
        }
    }
    if adj.is_empty() {
        return Vec::new();
    }

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

/// AU-084 — Dual-source cell tower corroboration (live sensor × crowdsourced database).
///
/// Fires when one or more `DeviceId` entities tagged `cell-tower` are independently
/// confirmed by both `cell_intel` (live Termux telephony sensor — hardware observation
/// via `termux-telephony-cellinfo`) and `opencellid` (crowdsourced tower database —
/// OpenCelliD API). Two orthogonal sources agreeing on the same `mcc-mnc-lac-cid`
/// key upgrades the tower from a single-source report to a cross-validated sighting:
/// the radio signal was physically detected AND the database independently records it.
///
/// Severity scales with corroborated tower count: Low for 1–2 towers (data-quality
/// upgrade), Medium for ≥3 (a multi-tower radio environment narrows the subject's
/// position to within a cell footprint). The Coordinates entities spawned by these
/// towers are the primary geoint leads; this rule surfaces the corroboration quality.
pub(in crate::core::correlator) fn rule_au_084_cell_tower_dual_source(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    let corroborated: Vec<&Entity> = entities_of_kind(entities, EntityKind::DeviceId)
        .into_iter()
        .filter(|e| {
            if !e.has_tag(crate::core::tags::CELL_TOWER) {
                return false;
            }
            let sources = e.evidence_sources();
            sources.contains("cell_intel") && sources.contains("opencellid")
        })
        .collect();

    if corroborated.is_empty() {
        return Vec::new();
    }

    let severity = if corroborated.len() >= 3 {
        Severity::Medium
    } else {
        Severity::Low
    };
    let mut uids: Vec<String> = corroborated.iter().map(|e| e.uid.clone()).collect();
    uids.sort_unstable();
    uids.dedup();

    vec![Correlation::new(
        "AU-084",
        "Dual-source cell tower corroboration",
        severity,
        format!(
            "{} cell tower(s) independently confirmed by live telephony sensor (cell_intel) \
             and crowdsourced database (opencellid) — MITRE T1592 (Gather Victim Host Information)",
            corroborated.len(),
        ),
        uids,
        scan_id,
        ts,
    )]
}

/// AU-115 — Personal Wi-Fi network geolocated.
///
/// A personalised SSID (a home/office network name, frequently surfaced from a
/// stealer log) that WiGLE resolves to a physical location places the network's
/// OWNER. `wigle::emit_ssid_entities` mints `ssid-located` Coordinates whose
/// evidence carries the originating `ssid` attribute; this rule joins each
/// `Ssid` entity to the WiGLE Coordinates that name it and reports the
/// geolocation — a high-value GEOINT lead (a subject-owned network is a far
/// stronger location anchor than a coarse IP-geo fix), previously surfaced by no
/// correlation.
///
/// Precision: matches on the exact case-folded SSID name, requires WiGLE's
/// `ssid-located` provenance tag (so only a network WiGLE's own uniqueness gate
/// admitted participates — a generic `linksys`/`xfinitywifi` name never reaches
/// emission), and runs on the confirmed (candidate-filtered) view.
pub(in crate::core::correlator) fn rule_au_115_personal_wifi_geolocated(
    context: &RuleContext,
    scan_id: &str,
    ts: u64,
) -> Vec<Correlation> {
    let entities = context.entities();
    let ssids = entities_of_kind(entities, EntityKind::Ssid);
    if ssids.is_empty() {
        return Vec::new();
    }
    let located: Vec<&Entity> = entities_of_kind(entities, EntityKind::Coordinates)
        .into_iter()
        .filter(|e| e.has_tag("ssid-located"))
        .collect();
    if located.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for ssid in ssids {
        let name_lc = ssid.value.trim().to_lowercase();
        let matches: Vec<&Entity> = located
            .iter()
            .copied()
            .filter(|c| {
                c.evidence.iter().any(|ev| {
                    ev.attributes
                        .get("ssid")
                        .is_some_and(|s| s.trim().to_lowercase() == name_lc)
                })
            })
            .collect();
        if matches.is_empty() {
            continue;
        }
        let mut uids: Vec<String> = matches.iter().map(|c| c.uid.clone()).collect();
        uids.push(ssid.uid.clone());
        uids.sort_unstable();
        uids.dedup();
        out.push(Correlation::new(
            "AU-115",
            "Personal Wi-Fi network geolocated",
            Severity::High,
            format!(
                "Personal Wi-Fi network '{}' geolocated by WiGLE to {} observed position(s) — a \
                 subject-owned network placing its owner (MITRE T1590 Gather Victim Network Information)",
                ssid.value,
                matches.len(),
            ),
            uids,
            scan_id,
            ts,
        ));
    }
    out
}
