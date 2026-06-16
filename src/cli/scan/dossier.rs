//! Dossier renderer for `hse scan --output dossier`.
//!
//! Separated from the scan command loop so the render logic is independently
//! readable and testable.

use crate::core::{correlator::Correlation, entity::Entity, relation::Relation, scan::Scan};

pub(super) fn print_dossier(
    scan: &Scan,
    entities: &[Entity],
    correlations: &[Correlation],
    relations: &[Relation],
    kind: &str,
    value: &str,
    sid: &str,
) {
    use std::collections::BTreeMap;

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  HUNTSMAN SEARCH ENGINE — INTELLIGENCE DOSSIER              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Target:    {kind} = {value}");
    println!("  Scan ID:   {}", &sid[..16]);
    println!("  Status:    {}", scan.status.as_str());
    println!("  Entities:  {}", scan.entity_count);
    println!(
        "  Modules:   {} run, {} errored, {} deduped",
        scan.modules_run, scan.modules_errored, scan.modules_deduped
    );
    println!();

    let mut by_kind: BTreeMap<String, Vec<&Entity>> = BTreeMap::new();
    for e in entities {
        by_kind.entry(e.kind.to_string()).or_default().push(e);
    }

    let kind_order = [
        "person",
        "email",
        "phone",
        "username",
        "credential",
        "api_key",
        "password",
        "address",
        "coordinates",
        "organisation",
        "abn_acn",
        "asn",
        "domain",
        "ip_address",
        "url",
        "mac_address",
        "device_id",
    ];

    for kind_name in &kind_order {
        let Some(group) = by_kind.get(*kind_name) else {
            continue;
        };
        let header = match *kind_name {
            "person" => "PERSONS",
            "email" => "EMAIL ADDRESSES",
            "phone" => "PHONE NUMBERS",
            "username" => "USERNAMES / HANDLES",
            "credential" => "CREDENTIALS (from breach/stealer data)",
            "api_key" => "API KEYS (from breach/stealer data)",
            "password" => "PASSWORDS (from breach/stealer data)",
            "address" => "PHYSICAL ADDRESSES / LOCATIONS",
            "coordinates" => "GPS COORDINATES",
            "organisation" => "ORGANISATIONS",
            "abn_acn" => "ABN / ACN (Australian Business Numbers)",
            "domain" => "DOMAINS",
            "ip_address" => "IP ADDRESSES",
            "url" => "URLS / PROFILES",
            "mac_address" => "MAC ADDRESSES (network devices)",
            "device_id" => "DEVICE IDENTIFIERS",
            other => other,
        };

        println!("━━━ {} ({}) ━━━", header, group.len());
        println!();

        let mut sorted = group.clone();
        sorted.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for e in &sorted {
            let c_eff = e.c_effective();
            let class = e.classify();
            println!(
                "  {} [{}]  conf={:.2}  c_eff={:.2}  corr={}",
                e.value, class, e.confidence, c_eff, e.corroboration
            );

            if !e.tags.is_empty() {
                println!("    tags: {}", e.tags.join(", "));
            }

            for ev in &e.evidence {
                println!(
                    "    ├─ {src} — {summary}",
                    src = ev.source,
                    summary = ev.summary
                );
                for (k, v) in &ev.attributes {
                    if !v.is_empty() {
                        println!("    │  {k}: {v}");
                    }
                }
            }
            println!();
        }
    }

    if !correlations.is_empty() {
        println!("━━━ CORRELATIONS ({}) ━━━", correlations.len());
        println!();
        for c in correlations {
            let sev = match c.severity.to_string().as_str() {
                "CRITICAL" => "🔴 CRITICAL",
                "HIGH" => "🟠 HIGH",
                "MEDIUM" => "🟡 MEDIUM",
                _ => "🔵 LOW",
            };
            println!("  {} [{}] {}", c.rule_id, sev, c.rule_name);
            println!("    {}", c.description);
            println!();
        }
    }

    if !relations.is_empty() {
        use std::collections::HashMap;
        let by_uid: HashMap<&str, &Entity> = entities.iter().map(|e| (e.uid.as_str(), e)).collect();
        let label = |uid: &str| -> String {
            by_uid.get(uid).map_or_else(
                || format!("{}…", &uid[..uid.len().min(8)]),
                |e| super::super::truncate(&e.value, 40),
            )
        };
        println!("━━━ RELATIONS ({}) ━━━", relations.len());
        println!();
        for r in relations {
            println!(
                "  {}  ──{}──▶  {}   (conf={:.2})",
                label(&r.from_uid),
                r.kind,
                label(&r.to_uid),
                r.confidence
            );
        }
        println!();
    }

    print_diagnostics(scan, entities, kind, value, sid);
}

fn print_diagnostics(scan: &Scan, entities: &[Entity], kind: &str, value: &str, sid: &str) {
    let wall_ms = scan
        .finished_at
        .and_then(|f| f.checked_sub(scan.started_at))
        .unwrap_or(0)
        .saturating_mul(1000);
    let diag = crate::util::diagnostics::analyse(sid, kind, value, wall_ms, entities);

    println!("━━━ DIAGNOSTICS ━━━");
    println!();
    println!("  Scan wall-time:  {} ms", diag.wall_time_ms);

    use crate::core::module::ModuleCost;
    let cost_by_module: std::collections::HashMap<String, ModuleCost> = crate::modules::registry()
        .iter()
        .map(|m| (m.name().to_string(), m.cost()))
        .collect();
    let cost_label = |name: &str| match cost_by_module.get(name) {
        Some(ModuleCost::Free) => "free",
        Some(ModuleCost::KeyGated) => "key",
        Some(ModuleCost::Paid) => "paid",
        None => "·",
    };

    println!("  Modules ranked by yield (cost tier shown for ROI tuning):");
    for m in diag.modules_by_yield.iter().take(15) {
        let kinds = m.unique_kinds.join(",");
        println!(
            "    {:4}  {:<5} {:<22} conf={:.2}  novelty={:5.1}%  kinds={}",
            m.entities_emitted,
            cost_label(&m.name),
            m.name,
            m.mean_confidence,
            m.novelty_ratio * 100.0,
            kinds
        );
    }
    let wasted: Vec<&str> = diag
        .modules_by_yield
        .iter()
        .filter(|m| {
            m.entities_emitted == 0
                && matches!(
                    cost_by_module.get(&m.name),
                    Some(ModuleCost::KeyGated | ModuleCost::Paid)
                )
        })
        .map(|m| m.name.as_str())
        .collect();
    if !wasted.is_empty() {
        println!(
            "  ROI: {} keyed/paid module(s) yielded nothing — consider --exclude {}",
            wasted.len(),
            wasted.join(",")
        );
    }
    println!();

    println!("  Source confidence (n / mean / p50 / p90):");
    let mut srcs: Vec<_> = diag.source_confidence.iter().collect();
    srcs.sort_by_key(|(_, s)| std::cmp::Reverse(s.n));
    for (src, s) in srcs.iter().take(15) {
        println!(
            "    {:<22} n={:<4} mean={:.2}  p50={:.2}  p90={:.2}",
            src, s.n, s.mean, s.p50, s.p90
        );
    }
    println!();

    let g = &diag.geo_precision;
    println!("━━━ GEO INTELLIGENCE ━━━");
    println!();
    println!(
        "  Coordinates: {} total ({} with geohash, {} with timezone)",
        g.coordinates_count, g.coords_with_geohash, g.coords_with_timezone
    );
    println!(
        "  Addresses:   {} total ({} state, {} country, {} ISO, {} postal)",
        g.address_count,
        g.addresses_with_state,
        g.addresses_with_country,
        g.addresses_with_iso,
        g.addresses_with_postal
    );
    if !g.iso_countries.is_empty() {
        println!("  ISO countries: {}", g.iso_countries.join(", "));
    }
    if !g.timezones.is_empty() {
        println!("  Timezones:     {}", g.timezones.join(", "));
    }
    println!(
        "  Multi-source convergence: {}",
        if g.multi_source_convergence {
            "YES (≥2 coords within 5km)"
        } else {
            "no"
        }
    );
    println!();

    if !diag.proximity_graph.is_empty() {
        println!("  Proximity graph (top 15 closest coord pairs):");
        for edge in diag.proximity_graph.iter().take(15) {
            let label = if edge.same_country {
                format!(
                    " [same country: {}]",
                    edge.from_country.as_deref().unwrap_or("?")
                )
            } else if edge.from_country.is_some() || edge.to_country.is_some() {
                format!(
                    " [{} ↔ {}]",
                    edge.from_country.as_deref().unwrap_or("?"),
                    edge.to_country.as_deref().unwrap_or("?")
                )
            } else {
                String::new()
            };
            println!(
                "    {:>10.3} km   {} ↔ {}{}",
                edge.distance_km, edge.from_value, edge.to_value, label
            );
        }
        println!();
    }

    let timeline = crate::core::timeline::reconstruct(entities);
    println!("━━━ TIMELINE ({} events) ━━━", timeline.len());
    println!();
    if timeline.is_empty() {
        println!("  No dated events reconstructed from the current entity set.");
    } else {
        for ev in timeline.iter().take(40) {
            println!(
                "  {:<19}  {:<16}  {} [{}]",
                ev.iso,
                ev.kind.as_str(),
                ev.entity_value,
                ev.source
            );
        }
        if timeline.len() > 40 {
            println!("  … {} more", timeline.len() - 40);
        }
    }
    println!();

    println!("━━━ ENRICHMENT LINEAGE ━━━");
    println!();
    let mut lineage_sorted = diag.enrichment_lineage.clone();
    lineage_sorted.sort_by_key(|n| std::cmp::Reverse(n.source_chain.len()));
    for node in lineage_sorted.iter().take(20) {
        println!(
            "  [{}] {} (conf={:.2}, corr={})",
            node.kind, node.value_preview, node.confidence, node.corroboration
        );
        println!("    sources: {}", node.source_chain.join(" → "));
    }
    println!();

    println!("━━━ OPTIMIZATION HINTS ━━━");
    println!();
    for hint in &diag.optimization_hints {
        println!("  • {hint}");
    }
    println!();

    println!("━━━ END OF DOSSIER ━━━");
}
