//! Prompt construction, response parsing, and orchestration for scan analysis.
//!
//! [`build_prompt`] and [`parse_response`] are pure functions, unit-tested
//! without a network call — the same split this codebase's OSINT modules use
//! between a pure `entities_from` projection and the I/O that feeds it.
//! [`analyze_scan`] is the one place that ties an [`OllamaClient`] to a
//! [`StoragePort`]; both CLI entry points (`hse analyze`, `hse-ai-daemon`) call
//! only this function, so the two never drift on what "analyze a scan" means.

use crate::core::entity::Entity;
use crate::core::error::{Error, Result};
use crate::core::port::StoragePort;
use crate::core::scan_analysis::{AnalysisFinding, ScanAnalysis};
use serde::Deserialize;
use std::time::Duration;

use super::ollama::OllamaClient;

/// Cap on how many entities go into the prompt context. An unbounded scan
/// (thousands of entities) would blow both the model's context window and
/// [`OllamaClient`]'s response cap; the most decision-relevant entities are the
/// highest-confidence ones anyway, so ranking + truncating (rather than e.g.
/// sampling) is the right cut.
pub const MAX_ENTITIES_IN_PROMPT: usize = 200;

/// At most this many findings are kept from the model's response — a long tail
/// of low-value findings is not a "more thorough" analysis, it's noise.
pub const MAX_FINDINGS: usize = 5;

/// Build the prompt sent to Ollama for `scan_id`'s discovered entities.
///
/// Deterministic given a deterministic `entities` slice (sorted by
/// [`Entity::c_effective`] descending, ties broken by `uid` for a total
/// order) — but the *model's response* to it is explicitly NOT claimed
/// deterministic; that is exactly why this whole surface stays outside
/// `core/` and its determinism guarantees (see `src/lib.rs`).
#[must_use]
pub fn build_prompt(scan_id: &str, entities: &[Entity]) -> String {
    let mut ranked: Vec<&Entity> = entities.iter().collect();
    ranked.sort_by(|a, b| {
        b.c_effective()
            .partial_cmp(&a.c_effective())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.uid.cmp(&b.uid))
    });
    ranked.truncate(MAX_ENTITIES_IN_PROMPT);

    let mut lines = String::new();
    for e in &ranked {
        lines.push_str(&format!(
            "- {} = {} (confidence {:.2})\n",
            e.kind,
            e.value,
            e.c_effective()
        ));
    }

    format!(
        "You are assisting a defensive OSINT analyst reviewing exposure data for \
         their OWN identity or an explicitly authorised subject. Do not suggest, \
         plan, or describe any exploitation, intrusion, contact, or offensive \
         action against anyone. Only summarise and rank what is already listed \
         below.\n\n\
         Given the entities discovered by scan {scan_id}, respond with ONLY a \
         single JSON object, no other text, matching exactly this shape:\n\
         {{\"summary\": \"<one short paragraph>\", \"findings\": \
         [{{\"description\": \"<finding>\", \"severity\": <integer 0-100>}}]}}\n\
         Include at most {MAX_FINDINGS} findings, ranked most severe first, where \
         severity reflects privacy/security exposure impact if this data were \
         used against the subject.\n\n\
         Entities:\n{lines}"
    )
}

#[derive(Deserialize)]
struct RawAnalysis {
    summary: String,
    #[serde(default)]
    findings: Vec<RawFinding>,
}

#[derive(Deserialize)]
struct RawFinding {
    description: String,
    severity: i64,
}

/// Parse the model's raw text response into a [`ScanAnalysis`]. Fails closed
/// (a surfaced `Err`) on anything that is not the exact expected JSON shape —
/// a model that ignores the requested format must never be silently treated
/// as "no findings", which would misreport a parsing failure as a clean scan.
pub fn parse_response(
    scan_id: &str,
    model: &str,
    created_at: u64,
    raw: &str,
) -> Result<ScanAnalysis> {
    let parsed: RawAnalysis = serde_json::from_str(raw.trim()).map_err(|e| {
        Error::module(
            "ai_daemon",
            format!("model response was not the requested JSON shape: {e}"),
        )
    })?;
    let findings = parsed
        .findings
        .into_iter()
        .take(MAX_FINDINGS)
        .map(|f| AnalysisFinding {
            description: f.description,
            severity: f.severity.clamp(0, 100) as u8,
        })
        .collect();
    Ok(ScanAnalysis {
        scan_id: scan_id.to_string(),
        model: model.to_string(),
        created_at,
        summary: parsed.summary,
        findings,
    })
}

/// Analyze one scan end to end: read its entities, prompt Ollama (bounded by
/// `timeout` — generation time is NOT bounded by the client itself, since it
/// varies hugely by model/hardware), parse the response, persist it, and
/// return it. Callers (`hse analyze`, `hse-ai-daemon`) share this single
/// implementation so the two entry points can't drift on what "analyzing a
/// scan" does.
pub async fn analyze_scan(
    store: &dyn StoragePort,
    client: &OllamaClient,
    scan_id: &str,
    timeout: Duration,
) -> Result<ScanAnalysis> {
    let entities = store.entities_for_scan(scan_id)?;
    let prompt = build_prompt(scan_id, &entities);
    let raw = tokio::time::timeout(timeout, client.generate(&prompt))
        .await
        .map_err(|_| {
            Error::module(
                "ai_daemon",
                format!("Ollama request timed out after {timeout:?}"),
            )
        })??;
    let created_at = crate::core::entity::unix_now();
    let analysis = parse_response(scan_id, client.model(), created_at, &raw)?;
    store.upsert_scan_analysis(&analysis)?;
    Ok(analysis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    fn entity(kind: EntityKind, value: &str, confidence: f64, uid: &str) -> Entity {
        let mut e = Entity::new(kind, value.to_string(), confidence, "test".to_string());
        e.uid = uid.to_string();
        e
    }

    #[test]
    fn build_prompt_ranks_by_effective_confidence_descending() {
        let entities = vec![
            entity(EntityKind::Email, "low@example.com", 0.2, "b"),
            entity(EntityKind::Email, "high@example.com", 0.9, "a"),
        ];
        let prompt = build_prompt("scan1", &entities);
        let high_pos = prompt.find("high@example.com").expect("present");
        let low_pos = prompt.find("low@example.com").expect("present");
        assert!(
            high_pos < low_pos,
            "higher-confidence entity must come first"
        );
    }

    #[test]
    fn build_prompt_truncates_to_the_entity_cap() {
        let entities: Vec<Entity> = (0..(MAX_ENTITIES_IN_PROMPT + 50))
            .map(|i| {
                entity(
                    EntityKind::Username,
                    &format!("user{i}"),
                    0.5,
                    &format!("u{i}"),
                )
            })
            .collect();
        let prompt = build_prompt("scan1", &entities);
        let listed = prompt.matches("- ").count();
        assert_eq!(listed, MAX_ENTITIES_IN_PROMPT);
    }

    #[test]
    fn build_prompt_never_suggests_offensive_action() {
        // A cheap but real regression guard: the prompt text itself must
        // explicitly forbid exploitation/intrusion framing, since this is the
        // one place in the crate that hands free-text instructions to an LLM.
        let prompt = build_prompt("scan1", &[]);
        assert!(prompt.contains("Do not suggest, plan, or describe any exploitation"));
    }

    #[test]
    fn parse_response_reads_summary_and_findings() {
        let raw = r#"{"summary":"Two accounts found.","findings":[{"description":"Reused handle","severity":70}]}"#;
        let analysis = parse_response("scan1", "qwen2.5:7b", 1_700_000_000, raw).expect("parse");
        assert_eq!(analysis.summary, "Two accounts found.");
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].severity, 70);
    }

    #[test]
    fn parse_response_clamps_out_of_range_severity() {
        let raw = r#"{"summary":"x","findings":[{"description":"a","severity":9001},{"description":"b","severity":-5}]}"#;
        let analysis = parse_response("scan1", "m", 0, raw).expect("parse");
        assert_eq!(analysis.findings[0].severity, 100);
        assert_eq!(analysis.findings[1].severity, 0);
    }

    #[test]
    fn parse_response_caps_finding_count() {
        let findings: Vec<String> = (0..20)
            .map(|i| format!(r#"{{"description":"f{i}","severity":10}}"#))
            .collect();
        let raw = format!(r#"{{"summary":"x","findings":[{}]}}"#, findings.join(","));
        let analysis = parse_response("scan1", "m", 0, &raw).expect("parse");
        assert_eq!(analysis.findings.len(), MAX_FINDINGS);
    }

    #[test]
    fn parse_response_fails_closed_on_non_json_text() {
        let err = parse_response("scan1", "m", 0, "I cannot help with that.")
            .expect_err("prose response must be a surfaced error, not empty findings");
        assert!(err.to_string().contains("JSON"));
    }

    #[test]
    fn parse_response_fails_closed_on_wrong_shape() {
        // Valid JSON, but missing the required `summary` field.
        let err = parse_response("scan1", "m", 0, r#"{"findings":[]}"#)
            .expect_err("a schema mismatch must be Err, not a default-initialised analysis");
        assert!(!err.to_string().is_empty());
    }
}
