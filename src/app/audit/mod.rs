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

use crate::audit::{AuditEntity, AuditReport, LogSignals, Severity, audit};
use crate::core::error::{Error, Result};

pub async fn cmd_audit(
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
        if scan_id.is_some() {
            eprintln!("{}", csv_scan_id_conflict_note(path));
        }
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

    if report
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High))
    {
        return Err(Error::Other(
            "audit: HIGH/CRITICAL findings detected — address the weaknesses above \
             before treating these results as reliable"
                .into(),
        ));
    }
    Ok(())
}

/// The stderr note printed when both `--csv` and `--scan-id` are given —
/// `--csv` wins (this module's doc comment has always promised "with a note",
/// but no such note was ever actually printed until now).
fn csv_scan_id_conflict_note(csv_path: &str) -> String {
    format!("note: both --csv and --scan-id given — using --csv \"{csv_path}\", ignoring --scan-id")
}

// ── CSV export parser (header-driven, tolerant of every export version) ───────

/// Parse an `hse` CSV export. Keys off the header row by NAME, so it works across
/// the old (`…,sources,tags`) and new (`…,sources,evidence_urls,evidence,tags`)
/// layouts alike. Unknown/missing columns degrade gracefully.
fn parse_csv(text: &str) -> Result<Vec<AuditEntity>> {
    let mut rows = crate::util::csv_row::parse_rows(text).into_iter();
    let header = rows
        .next()
        .ok_or_else(|| Error::Other("empty CSV".into()))?;
    let cols: Vec<String> = header.iter().map(|s| s.to_lowercase()).collect();
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
    for f in rows {
        if f.iter().all(|s| s.trim().is_empty()) {
            continue;
        }
        let get = |i: Option<usize>| i.and_then(|i| f.get(i)).map_or("", String::as_str);
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
            c_effective: ceff,
            corroboration: get(ci_corr).parse().unwrap_or(0),
            sources: split_pipe(get(ci_src)),
            tags: split_pipe(get(ci_tags)),
        });
    }
    Ok(out)
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
    // Shared with the other store-backed app use cases through app::runtime.
    let sid = crate::app::runtime::resolve_scan_id(&store, scan_id)?;
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
    if r.quarantined > 0 {
        println!(
            "quarantined: {} breach co-occurrence row(s) (non-subject; excluded from view & grade)",
            r.quarantined
        );
    }
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
    include!("tests.rs");
}
