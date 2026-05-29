//! `hse exposure` — the defensive inversion of `hse scan`.
//!
//! Loads a previously-stored scan's entities and runs the pure
//! [`crate::core::exposure`] analyser to answer "how exposed am I, and
//! what do I do about it?". This is the self-footprint use case: scan
//! your own identifiers, then turn the findings into a remediation plan.
//!
//! Output is local-only. Pass `--redact` to mask identifier values so the
//! report can be shared without re-exposing the data it is about.

use crate::core::error::{Error, Result};
use crate::core::exposure::{self, Severity};
use crate::default_db_path;
use crate::storage::Store;

use super::{color_severity, use_color};

pub(super) struct ExposureCmd {
    pub scan_id: String,
    pub output: String,
    pub redact: bool,
}

fn resolve_scan_id(store: &Store, raw: &str) -> Result<String> {
    if raw != "latest" {
        return Ok(raw.to_string());
    }
    store
        .latest_completed_scan()?
        .map(|s| s.id)
        .ok_or_else(|| Error::Other("no completed scans in store — run `hse scan` first".into()))
}

pub(super) async fn cmd_exposure(cmd: ExposureCmd) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let sid = resolve_scan_id(&store, &cmd.scan_id)?;
    let mut entities = store.entities_for_scan(&sid)?;

    // Redact in place so neither rendering path can leak raw identifiers.
    if cmd.redact {
        for e in &mut entities {
            let masked = exposure::redact_value(&e.kind, &e.value);
            e.value = masked.clone();
            e.raw_value = masked;
        }
    }

    let report = exposure::assess(&entities);

    match cmd.output.to_lowercase().as_str() {
        "json" => {
            let body = serde_json::to_string_pretty(&report)
                .map_err(|e| Error::Other(format!("json serialise: {e}")))?;
            println!("{body}");
        }
        "table" => print_table(&report, &sid),
        other => {
            return Err(Error::Other(format!(
                "unknown --output '{other}'. Valid: table, json"
            )));
        }
    }
    Ok(())
}

fn print_table(report: &exposure::ExposureReport, sid: &str) {
    let color = use_color();
    println!("Self-exposure assessment — scan {sid}");
    println!(
        "Exposure score: {}/100  (grade {})  — higher is more exposed",
        report.exposure_score, report.grade
    );
    println!(
        "Findings: {} critical/high, {} total",
        report.count_at_least(Severity::High),
        report.findings.len()
    );

    if report.findings.is_empty() {
        println!("\nNo exposure findings. Nothing of concern surfaced in this scan.");
        return;
    }

    for f in &report.findings {
        println!();
        println!(
            "[{}] {} — {}",
            color_severity(f.severity.as_str(), color),
            f.id,
            f.title
        );
        println!("  {}", f.detail);
        if !f.related.is_empty() {
            // Cap the echoed values so a noisy scan doesn't flood the terminal.
            let shown: Vec<&String> = f.related.iter().take(8).collect();
            let suffix = if f.related.len() > shown.len() {
                format!(" (+{} more)", f.related.len() - shown.len())
            } else {
                String::new()
            };
            let joined = shown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            println!("  affected: {joined}{suffix}");
        }
        println!("  remediation:");
        for step in &f.remediation {
            println!("    - {step}");
        }
    }
    println!("\nReport is local-only. Re-run after remediating to watch the score fall.");
}
