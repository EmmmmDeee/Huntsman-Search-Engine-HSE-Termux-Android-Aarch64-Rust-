//! `investigate` — offline analytical pass over an HSE scan-report JSON.
//!
//! Re-hydrates a previously exported scan (`{ scan, entities, correlations }`)
//! into the platform's own `Entity` / `Correlation` types and runs the live
//! analytical code over it — entity classification, the `core::temporal`
//! behavioural engine, and a signal-vs-noise triage — without touching the
//! network. This is the lens used for the synthetic seed "Jordan Leigh Meyer".
//!
//! Usage:
//!   cargo run --example investigate -- <scan-report.json> ["Seed Name"]

use std::collections::BTreeMap;

use huntsman_search_engine::core::{
    correlator::Correlation,
    entity::{Classification, Entity, EntityKind},
    temporal,
};

#[derive(serde::Deserialize)]
struct Report {
    #[serde(default)]
    entities: Vec<Entity>,
    #[serde(default)]
    correlations: Vec<Correlation>,
    #[serde(default)]
    scan: serde_json::Value,
}

fn ceff(e: &Entity) -> f64 {
    e.c_effective()
}

fn rule(title: &str) {
    println!(
        "\n\x1b[1m{title}\x1b[0m\n{}",
        "─".repeat(title.len().max(40))
    );
}

fn top_of_kind<'a>(ents: &'a [Entity], kind: &EntityKind, n: usize) -> Vec<&'a Entity> {
    let mut v: Vec<&Entity> = ents.iter().filter(|e| &e.kind == kind).collect();
    v.sort_by(|a, b| {
        ceff(b)
            .partial_cmp(&ceff(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    v.truncate(n);
    v
}

/// Crude but useful geospatial label for a lat/lon pair within AU/US bands.
fn geo_label(value: &str) -> &'static str {
    let Some((lat, lon)) = value.split_once(',') else {
        return "";
    };
    let (lat, lon): (f64, f64) = match (lat.trim().parse(), lon.trim().parse()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return "",
    };
    match (lat, lon) {
        (la, lo) if (-28.0..-26.0).contains(&la) && (152.0..154.0).contains(&lo) => {
            "Brisbane, QLD (AU)"
        }
        (la, lo) if (-34.5..-33.0).contains(&la) && (150.5..151.8).contains(&lo) => {
            "Sydney, NSW (AU)"
        }
        (la, lo) if (-35.5..-34.5).contains(&la) && (138.0..139.0).contains(&lo) => {
            "Adelaide, SA (AU)"
        }
        (la, _) if (-44.0..-10.0).contains(&la) => "elsewhere in Australia",
        _ => "OUTSIDE Australia (likely decoy/recycled)",
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: investigate <scan-report.json> [\"Seed Name\"]");
        std::process::exit(2);
    });
    let seed = args.next().unwrap_or_else(|| "(unspecified)".into());

    let body = std::fs::read_to_string(&path).expect("read report");
    let rep: Report = serde_json::from_str(&body).expect("parse report");
    let ents = &rep.entities;

    println!("\x1b[1;36m═══ HSE INVESTIGATION · seed: {seed} ═══\x1b[0m");
    println!(
        "source: {path}  |  scan: {}  |  status: {}",
        rep.scan.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
        rep.scan
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("?"),
    );
    if let (Some(s), Some(f)) = (
        rep.scan.get("started_at").and_then(|v| v.as_u64()),
        rep.scan.get("finished_at").and_then(|v| v.as_u64()),
    ) {
        println!(
            "wall-clock: {}s  |  entities: {}  |  correlations: {}",
            f - s,
            ents.len(),
            rep.correlations.len()
        );
    }

    // ── Entity census ────────────────────────────────────────────────────
    rule("ENTITY CENSUS");
    let mut census: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for e in ents {
        let slot = census.entry(e.kind.to_string()).or_default();
        slot.0 += 1;
        if e.classify() == Classification::Verified {
            slot.1 += 1;
        }
    }
    for (kind, (n, verified)) in &census {
        println!("  {kind:<14} {n:>4}   ({verified} verified)");
    }

    // ── Identity core ────────────────────────────────────────────────────
    rule("IDENTITY CORE (persons · usernames · emails)");
    for (label, kind) in [
        ("PERSON", EntityKind::Person),
        ("USERNAME", EntityKind::Username),
        ("EMAIL", EntityKind::Email),
    ] {
        println!("  ▸ {label}");
        for e in top_of_kind(ents, &kind, 6) {
            println!(
                "      {:<26} Ceff={:.2} [{}] corr×{}",
                truncate(&e.value, 26),
                ceff(e),
                e.classify().as_str(),
                e.corroboration,
            );
        }
    }

    // ── Geospatial ───────────────────────────────────────────────────────
    rule("GEOSPATIAL ASSESSMENT");
    for e in top_of_kind(ents, &EntityKind::Coordinates, 8) {
        println!(
            "  COORD {:<22} Ceff={:.2}  → {}",
            e.value,
            ceff(e),
            geo_label(&e.value)
        );
    }
    for e in top_of_kind(ents, &EntityKind::Address, 8) {
        let au = e.value.to_lowercase().contains("australia")
            || [
                "qld",
                "nsw",
                "vic",
                "wa",
                "tas",
                "sa",
                "brisbane",
                "sydney",
                "melbourne",
                "adelaide",
                "perth",
            ]
            .iter()
            .any(|k| e.value.to_lowercase().contains(k));
        println!(
            "  ADDR  {:<28} Ceff={:.2}  {}",
            truncate(&e.value, 28),
            ceff(e),
            if au { "✓AU" } else { "·non-AU" }
        );
    }

    // ── Infrastructure ───────────────────────────────────────────────────
    rule("INFRASTRUCTURE (top IPs / domains by Ceff)");
    for e in top_of_kind(ents, &EntityKind::IpAddress, 6) {
        println!(
            "  IP   {:<34} Ceff={:.2} tags={:?}",
            e.value,
            ceff(e),
            e.tags
        );
    }
    println!(
        "  domains: {}  urls: {}",
        census.get("domain").map_or(0, |c| c.0),
        census.get("url").map_or(0, |c| c.0)
    );

    // ── Correlations ─────────────────────────────────────────────────────
    rule("CORRELATION SUMMARY");
    let mut by_rule: BTreeMap<String, (String, usize, String)> = BTreeMap::new();
    for c in &rep.correlations {
        let e = by_rule.entry(c.rule_id.clone()).or_insert((
            c.rule_name.clone(),
            0,
            c.severity.to_string(),
        ));
        e.1 += 1;
    }
    for (rid, (name, count, sev)) in &by_rule {
        println!("  {rid:<8} {sev:<8} ×{count:<4} {name}");
    }
    println!("\n  HIGH/CRITICAL findings:");
    for c in &rep.correlations {
        if c.severity >= huntsman_search_engine::core::Severity::High {
            println!("    [{}] {}", c.severity, truncate(&c.description, 96));
        }
    }

    // ── Temporal / behavioural engine (the new capability) ───────────────
    rule("TEMPORAL / BEHAVIOURAL PROFILE  (core::temporal)");
    match temporal::analyze(ents) {
        Some(p) => {
            println!("  samples={}  span={}..{}", p.samples, p.earliest, p.latest);
            if let Some(label) = p.offset_label() {
                println!(
                    "  inferred timezone: {label}  (confidence {:.2}, peak {:02}:00 UTC)",
                    p.offset_confidence,
                    p.peak_hour_utc()
                );
            }
            println!("  activity bursts: {}", p.bursts.len());
        }
        None => println!(
            "  insufficient behavioural timestamps in this corpus (need ≥{}).\n  \
             → re-scan with timestamp-emitting modules (github_user, hackernews, crtsh)\n  \
             to populate the diurnal histogram and enable AU-033 timezone inference.",
            temporal::MIN_SAMPLES
        ),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
