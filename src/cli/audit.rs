//! `hse audit` — score and explain a scan's output quality.
//!
//! Ingests a scan from any of three sources and emits the
//! [`crate::audit`] scorecard (noise, infrastructure pollution, fragment values,
//! missed-PII, source health) with actionable recommendations:
//!   • `--csv <file>`   a CSV export (`hse export --format csv`), any version;
//!   • `--scan-id <id>` a scan already in the local store (`latest` allowed);
//!   • `--log <file>`   a debug log / scan-event stream (JSONL or tracing text),
//!                      which adds source-health signals to whichever entity
//!                      source is used (or audits the log on its own).
//!
//! `--csv`/`--scan-id` supply entities; `--log` supplies source-health signals.
//! They compose: `hse audit --scan-id latest --log debug.log` audits the stored
//! scan AND folds in what the log reveals about engine/module health.

use crate::audit::{AuditEntity, AuditReport, LogSignals, audit};
use crate::core::error::{Error, Result};

pub(super) async fn cmd_audit(
    csv: Option<String>,
    scan_id: Option<String>,
    log: Option<String>,
    json: bool,
) -> Result<()> {
    if csv.is_none() && scan_id.is_none() && log.is_none() {
        return Err(Error::Other(
            "nothing to audit — pass --csv <file>, --scan-id <id>, and/or --log <file>".into(),
        ));
    }

    // Entities: at most one of --csv / --scan-id (CSV wins if both given, with a
    // note) — they describe the same kind of artifact.
    let mut entities: Vec<AuditEntity> = Vec::new();
    let mut source_label = String::new();
    if let Some(path) = &csv {
        let text =
            std::fs::read_to_string(path).map_err(|e| Error::Other(format!("read {path}: {e}")))?;
        entities = parse_csv(&text)?;
        source_label = format!("CSV {path} ({} entities)", entities.len());
    } else if let Some(id) = &scan_id {
        entities = load_from_store(id)?;
        source_label = format!("scan {id} ({} entities)", entities.len());
    }

    // Source-health signals from a log, if provided.
    let signals = if let Some(path) = &log {
        let text =
            std::fs::read_to_string(path).map_err(|e| Error::Other(format!("read {path}: {e}")))?;
        let s = parse_log(&text);
        if !source_label.is_empty() {
            source_label.push_str(&format!(" + log {path} ({} lines)", s.lines_parsed));
        } else {
            source_label = format!("log {path} ({} lines)", s.lines_parsed);
        }
        s
    } else {
        LogSignals::default()
    };

    let report = audit(&entities, signals);

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json()).unwrap_or_else(|_| "{}".into())
        );
    } else {
        print_report(&report, &source_label);
    }
    Ok(())
}

// ── CSV export parser (header-driven, tolerant of every export version) ───────

/// Parse an `hse` CSV export. Keys off the header row by NAME, so it works across
/// the old (`…,sources,tags`) and new (`…,sources,evidence_urls,evidence,tags`)
/// layouts alike. Unknown/missing columns degrade gracefully.
fn parse_csv(text: &str) -> Result<Vec<AuditEntity>> {
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| Error::Other("empty CSV".into()))?;
    let cols: Vec<String> = split_csv(header).iter().map(|s| s.to_lowercase()).collect();
    let idx = |name: &str| cols.iter().position(|c| c == name);
    let (ci_kind, ci_val) = (
        idx("kind").ok_or_else(|| Error::Other("CSV missing 'kind' column".into()))?,
        idx("value").ok_or_else(|| Error::Other("CSV missing 'value' column".into()))?,
    );
    let (ci_conf, ci_ceff, ci_corr, ci_src, ci_tags) = (
        idx("confidence"),
        idx("c_effective"),
        idx("corroboration"),
        idx("sources"),
        idx("tags"),
    );

    let mut out = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let f = split_csv(line);
        let get = |i: Option<usize>| i.and_then(|i| f.get(i)).map(String::as_str).unwrap_or("");
        let kind = f.get(ci_kind).cloned().unwrap_or_default();
        let value = f.get(ci_val).cloned().unwrap_or_default();
        if kind.is_empty() {
            continue;
        }
        let conf = get(ci_conf).parse().unwrap_or(0.0);
        let ceff = ci_ceff
            .and_then(|i| f.get(i))
            .and_then(|s| s.parse().ok())
            .unwrap_or(conf);
        out.push(AuditEntity {
            kind,
            value,
            confidence: conf,
            c_effective: ceff,
            corroboration: get(ci_corr).parse().unwrap_or(0),
            sources: split_pipe(get(ci_src)),
            tags: split_pipe(get(ci_tags)),
        });
    }
    Ok(out)
}

/// Minimal RFC-4180-ish field splitter: handles `"`-quoted fields containing
/// commas and doubled `""` escapes. Sufficient for our own exports.
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut in_q = false;
    while let Some(c) = chars.next() {
        match c {
            '"' if in_q && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => in_q = !in_q,
            ',' if !in_q => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// `sources` / `tags` columns are `|`-joined in our exports.
fn split_pipe(s: &str) -> Vec<String> {
    s.split('|')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect()
}

// ── Store loader ──────────────────────────────────────────────────────────────

fn load_from_store(scan_id: &str) -> Result<Vec<AuditEntity>> {
    use crate::storage::Store;
    let store = Store::open(&crate::default_db_path())?;
    // `latest` → most-recent Complete scan; explicit id existence-checked.
    // Shared with `export`/`diff` via `super::resolve_scan_id`.
    let sid = super::resolve_scan_id(&store, scan_id)?;
    Ok(store
        .entities_for_scan(&sid)?
        .iter()
        .map(AuditEntity::from_entity)
        .collect())
}

// ── Log parser (JSONL or tracing-text) ────────────────────────────────────────

/// Parse a debug-log / event stream into source-health signals. Each line is
/// tried as JSON first (a scan-event / structured record); on failure it is
/// parsed as a `tracing` fmt line (`… target: msg key="value" key=N`). Robust to
/// mixed content — anything unrecognised is skipped, the rest is mined for the
/// signals the auditor scores.
fn parse_log(text: &str) -> LogSignals {
    let mut s = LogSignals::default();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        s.lines_parsed += 1;

        // Try structured JSON first (scan events or JSON-formatted tracing).
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            ingest_json(&mut s, &v);
            continue;
        }
        ingest_text(&mut s, line);
    }
    // De-dup engine lists (a log may probe repeatedly).
    for v in [
        &mut s.engines_blocked,
        &mut s.engines_down,
        &mut s.engine_parser_defects,
        &mut s.expansion_stops,
    ] {
        v.sort();
        v.dedup();
    }
    s
}

/// Pull a `key="value"` or `key=value` field out of a tracing line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!("{key}="))? + key.len() + 1;
    let rest = &line[at..];
    if let Some(stripped) = rest.strip_prefix('"') {
        stripped.find('"').map(|end| &stripped[..end])
    } else {
        let end = rest.find([' ', ',']).unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn ingest_text(s: &mut LogSignals, line: &str) {
    let low = line.to_ascii_lowercase();

    // Engine-health probe lines (target huntsman::engine_health).
    if line.contains("engine_health") || line.contains("liveness probe") {
        if let Some(name) = field(line, "engine") {
            let status = field(line, "status").unwrap_or("");
            let detail = field(line, "detail").unwrap_or("");
            match status {
                "down" => s.engines_down.push(name.to_string()),
                "blocked" => {
                    if detail.contains("PARSER") {
                        s.engine_parser_defects.push(name.to_string());
                    } else {
                        s.engines_blocked.push(name.to_string());
                    }
                }
                _ => {}
            }
        }
        return;
    }

    // Module errors / timeouts (engine.rs warn lines).
    if low.contains("module error") || (low.contains("module") && low.contains("error=")) {
        if let Some(m) = field(line, "module") {
            *s.module_errors.entry(m.to_string()).or_default() += 1;
        }
        return;
    }
    if low.contains("timeout") && line.contains("module=") {
        if let Some(m) = field(line, "module") {
            *s.module_timeouts.entry(m.to_string()).or_default() += 1;
        }
        return;
    }
    // Generic HTTP/fetch failures.
    if low.contains("error sending request") || low.contains("failed to fetch") {
        s.http_failures += 1;
    }
    if low.contains("expansion")
        && low.contains("stop")
        && let Some(r) = field(line, "reason")
    {
        s.expansion_stops.push(r.to_string());
    }
}

fn ingest_json(s: &mut LogSignals, v: &serde_json::Value) {
    // Scan-event records: {"type":"module_error","module":"…","error":"…"}.
    let typ = v
        .get("type")
        .or_else(|| v.get("kind"))
        .and_then(|t| t.as_str())
        .unwrap_or("");
    let module = |key: &str| v.get(key).and_then(|m| m.as_str());
    match typ {
        "module_error" => {
            if let Some(m) = module("module") {
                *s.module_errors.entry(m.to_string()).or_default() += 1;
            }
        }
        "module_skipped" => {
            if v.get("reason").and_then(|r| r.as_str()) == Some("timeout")
                && let Some(m) = module("module")
            {
                *s.module_timeouts.entry(m.to_string()).or_default() += 1;
            }
        }
        "expansion_stop" => {
            if let Some(r) = v.get("reason").and_then(|r| r.as_str()) {
                s.expansion_stops.push(r.to_string());
            }
        }
        "entity_excluded" => {
            if let Some(r) = v.get("reason").and_then(|r| r.as_str()) {
                *s.excluded_reasons.entry(r.to_string()).or_default() += 1;
            }
        }
        _ => {
            // Engine-health JSON: {"engine":"brave","status":"blocked","detail":"…PARSER…"}.
            if let Some(name) = module("engine") {
                match v.get("status").and_then(|x| x.as_str()) {
                    Some("down") => s.engines_down.push(name.to_string()),
                    Some("blocked") => {
                        let detail = v.get("detail").and_then(|d| d.as_str()).unwrap_or("");
                        if detail.contains("PARSER") {
                            s.engine_parser_defects.push(name.to_string());
                        } else {
                            s.engines_blocked.push(name.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn print_report(r: &AuditReport, source: &str) {
    println!("\n══════════════════════════════════════════════════════════════");
    println!("  Huntsman scan audit");
    println!("══════════════════════════════════════════════════════════════");
    println!("source     : {source}");
    println!("score      : {}/100   ({})", r.score, r.grade());
    println!(
        "entities   : {}  —  {} verified · {} probable · {} candidate",
        r.entity_total, r.tiers.0, r.tiers.1, r.tiers.2
    );
    println!("noise ratio: {:.0}% candidate-tier", r.noise_ratio * 100.0);
    if r.geo.coord_count > 0 {
        println!(
            "geolocation: {} fix(es) from {} source(s) · spread {:.0} km · {}{}",
            r.geo.coord_count,
            r.geo.source_count,
            r.geo.max_spread_km,
            if r.geo.has_consensus {
                "consensus"
            } else {
                "no consensus"
            },
            if r.geo.outliers > 0 {
                format!(" · {} outlier(s)", r.geo.outliers)
            } else {
                String::new()
            },
        );
    }
    if !r.by_kind.is_empty() {
        let top: Vec<String> = r
            .by_kind
            .iter()
            .take(8)
            .map(|(k, n)| format!("{k}:{n}"))
            .collect();
        println!("by kind    : {}", top.join("  "));
    }

    if r.findings.is_empty() {
        println!("\n✓ no weaknesses detected — results are individualised and verifiable.");
    } else {
        println!("\nFindings ({}):", r.findings.len());
        for f in &r.findings {
            println!(
                "\n  [{}] {} — {}",
                f.severity.as_str(),
                f.category,
                f.message
            );
            for ex in &f.examples {
                println!("        • {ex}");
            }
            println!("        → {}", f.recommendation);
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parses_old_format_header_driven() {
        let csv = "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,tags\n\
            ip_address,172.66.147.185,172.66.147.185,0.950,1.000,258,VERIFIED,1780814281,dns_intel|shodan,cloudflare|hosting\n\
            email,matthewdiegmann@gmail.com,matthewdiegmann@gmail.com,0.850,1.000,4,VERIFIED,1780814282,oathnet_pro|smtp_vrfy,verified\n";
        let ents = parse_csv(csv).unwrap();
        assert_eq!(ents.len(), 2);
        assert_eq!(ents[0].kind, "ip_address");
        assert_eq!(ents[0].corroboration, 258);
        assert_eq!(ents[0].sources, vec!["dns_intel", "shodan"]);
        assert!(ents[0].tags.contains(&"cloudflare".to_string()));
        assert_eq!(ents[1].value, "matthewdiegmann@gmail.com");
    }

    #[test]
    fn csv_parses_new_format_with_evidence_columns() {
        // Header order differs and adds columns — must still map by name.
        let csv = "kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,evidence_urls,evidence,tags\n\
            domain,cloudflare.com,cloudflare.com,1.0,1.0,5,VERIFIED,1,whois,https://x,e,infra\n";
        let ents = parse_csv(csv).unwrap();
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].kind, "domain");
        assert_eq!(ents[0].tags, vec!["infra"]);
    }

    #[test]
    fn csv_handles_quoted_commas() {
        let csv = "kind,value\nperson,\"Doe, Jane\"\n";
        let ents = parse_csv(csv).unwrap();
        assert_eq!(ents[0].value, "Doe, Jane");
    }

    #[test]
    fn log_text_extracts_engine_and_module_health() {
        let log = "\
2026-06-07T08:36:03Z INFO huntsman::engine_health: search engine liveness probe engine=\"google\" status=\"blocked\" detail=\"anti-bot\" results=0\n\
2026-06-07T08:36:04Z INFO huntsman::engine_health: search engine liveness probe engine=\"brave\" status=\"blocked\" detail=\"page carried ~13 links but the parser extracted 0 results — likely a PARSER defect\" results=0\n\
2026-06-07T08:36:05Z INFO huntsman::engine_health: liveness probe engine=\"mojeek\" status=\"down\" results=0\n\
2026-06-07T08:36:06Z WARN huntsman::core::engine: module error module=\"crtsh\" error=timeout\n";
        let s = parse_log(log);
        assert_eq!(s.lines_parsed, 4);
        assert_eq!(s.engines_blocked, vec!["google"]);
        assert_eq!(s.engine_parser_defects, vec!["brave"]);
        assert_eq!(s.engines_down, vec!["mojeek"]);
        assert_eq!(s.module_errors.get("crtsh"), Some(&1));
    }

    #[test]
    fn log_jsonl_events_are_ingested() {
        let log = "\
{\"type\":\"module_error\",\"module\":\"hibp\",\"error\":\"429\"}\n\
{\"type\":\"expansion_stop\",\"reason\":\"max_entities=200 reached\"}\n\
{\"type\":\"entity_excluded\",\"kind\":\"username\",\"value\":\"arizonambb\",\"reason\":\"identity_mismatch\"}\n\
{\"type\":\"entity_excluded\",\"kind\":\"username\",\"value\":\"centenario\",\"reason\":\"identity_mismatch\"}\n\
{\"type\":\"entity_excluded\",\"kind\":\"credential\",\"value\":\"x\",\"reason\":\"non_pivotable_kind\"}\n\
{\"engine\":\"qwant\",\"status\":\"blocked\",\"detail\":\"anti-bot\"}\n";
        let s = parse_log(log);
        assert_eq!(s.module_errors.get("hibp"), Some(&1));
        assert_eq!(s.expansion_stops, vec!["max_entities=200 reached"]);
        assert_eq!(s.engines_blocked, vec!["qwant"]);
        assert_eq!(s.excluded_reasons.get("identity_mismatch"), Some(&2));
        assert_eq!(s.excluded_reasons.get("non_pivotable_kind"), Some(&1));
    }

    #[test]
    fn field_extracts_quoted_and_bare_values() {
        assert_eq!(field("a status=\"blocked\" b", "status"), Some("blocked"));
        assert_eq!(field("a results=0 b", "results"), Some("0"));
        assert_eq!(field("no key here", "status"), None);
    }
}
