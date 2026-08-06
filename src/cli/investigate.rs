//! `hse investigate [TEXT]` — extract OSINT entities mentioned in a free-text
//! investigative prompt.
//!
//! Bridges a natural-language question (the kind of prompt an operator would
//! type to an AI research assistant — "find what's linked to
//! alice@example.com", "who owns example.com and where are they based") to
//! HSE's own deterministic, offline entity extractor
//! (`util::entity_extractor`) — the SAME extractor `hse ingest` runs on
//! document text. No text is ever sent to an external LLM: extraction is pure
//! pattern/classifier matching, so results are exactly reproducible and never
//! fabricated.
//!
//! Mirrors `hse ingest --auto-scan`'s restraint exactly: extraction only
//! prints by default; `--auto-scan` additionally persists the batch as a
//! completed, correlated scan (offline — no module dispatch, no network) via
//! the shared [`crate::app::persist`] use case. Feeding every extracted
//! entity straight into the live scan engine as seeds is deliberately NOT
//! what this does — a natural-language prompt can easily NAME many entities,
//! and auto-launching reconnaissance against every one of them would be both
//! non-deterministic and a footgun (the identical reasoning `cli::ingest`
//! documents for its own `--auto-scan`).

use crate::core::error::{Error, Result};
use crate::util::entity_extractor::{EntityExtractor, ExtractedEntity};
use std::io::Read;

use super::truncate;

/// Evidence-source / scan-label strings are truncated to this many characters
/// so a long prompt doesn't dump a full paragraph into every entity's
/// evidence chain or the printed summary line.
const LABEL_MAX_CHARS: usize = 80;

pub(super) async fn cmd_investigate(
    text: Option<String>,
    auto_scan: bool,
    min_confidence: f64,
    json: bool,
) -> Result<()> {
    let text = match text {
        Some(t) => t,
        None => {
            // No positional TEXT → read from stdin, so a longer prompt (or a
            // script piping one in) doesn't need shell quoting.
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::InvalidTarget(
            "investigate text is empty — pass a prompt, e.g. \
             `hse investigate \"find what's linked to alice@example.com\"`, \
             or pipe one in on stdin"
                .to_string(),
        ));
    }

    let extractor =
        EntityExtractor::new(min_confidence).map_err(|e| Error::Other(e.to_string()))?;
    let entities = extractor.extract_from_text(text);

    // Best-effort, exactly like `hse ingest --auto-scan`: a persistence hiccup
    // must warn, never fail the command — the extracted entities are still
    // printed below regardless. Never persists an empty batch.
    let scan = if auto_scan && !entities.is_empty() {
        match run_auto_scan(&entities, text).await {
            Ok(summary) => Some(summary),
            Err(e) => {
                tracing::warn!("auto-scan: could not persist extracted entities: {e}");
                None
            }
        }
    } else {
        None
    };

    if json {
        print_json(text, &entities, scan.as_ref());
    } else {
        print_table(text, &entities, scan.as_ref());
    }
    Ok(())
}

/// Result of persisting an `--auto-scan` batch — the summary printed to the
/// operator.
struct AutoScanSummary {
    sid: String,
    entities: usize,
    relations: usize,
    correlations: usize,
}

/// Persist the extracted `entities` as a completed, correlated scan — the
/// `--auto-scan` action. Same shape as `cli::ingest::run_auto_scan`, sourced
/// from the prompt text instead of a document, and sharing the identical
/// conversion ([`crate::app::convert`]) and persistence
/// ([`crate::app::persist`]) use cases so the two commands can never drift on
/// how a batch becomes a scan.
async fn run_auto_scan(entities: &[ExtractedEntity], text: &str) -> Result<AutoScanSummary> {
    let label = truncate(text, LABEL_MAX_CHARS);
    // Collision-free per call — same rationale as ingest's identical fix: two
    // `hse investigate --auto-scan` runs within the same second must not
    // collide and overwrite each other's scan row + entities.
    let sid = format!(
        "investigate-{}",
        crate::util::uid::scan_id("investigate", text)
    );
    let evidence_source = format!("investigate:{label}");
    let converted: Vec<crate::core::entity::Entity> = entities
        .iter()
        .map(|e| {
            crate::app::convert::extracted_to_hse_entity(
                e,
                &sid,
                &evidence_source,
                "investigate-query",
            )
        })
        .collect();
    let scan_label =
        crate::app::persist::strongest_identity_label(&converted, format!("investigate: {label}"));
    let (relations, correlations) = crate::app::persist::persist_entities_as_scan(
        &sid,
        scan_label,
        crate::core::scan::TargetKind::FullName,
        &converted,
    )
    .await?;
    Ok(AutoScanSummary {
        sid,
        entities: converted.len(),
        relations,
        correlations,
    })
}

fn print_table(text: &str, entities: &[ExtractedEntity], scan: Option<&AutoScanSummary>) {
    if entities.is_empty() {
        println!(
            "No OSINT entities recognised in that prompt — try lowering \
             --min-confidence or naming something concrete (an email, domain, \
             phone number, username, ...)."
        );
        return;
    }
    println!(
        "Investigate: {:?} — {} entit{} found",
        truncate(text, LABEL_MAX_CHARS),
        entities.len(),
        if entities.len() == 1 { "y" } else { "ies" }
    );
    println!();
    for e in entities {
        println!(
            "  {:<12} {:<40} confidence {:.2}  ({})",
            e.kind.to_str(),
            e.value,
            e.confidence,
            e.source_pattern
        );
    }
    if let Some(s) = scan {
        println!(
            "\nauto-scan: stored scan {} ({} entities, {} relations, {} correlations) — \
             view with `hse list`",
            s.sid, s.entities, s.relations, s.correlations
        );
    }
}

fn print_json(text: &str, entities: &[ExtractedEntity], scan: Option<&AutoScanSummary>) {
    let entities_json: Vec<_> = entities
        .iter()
        .map(|e| {
            serde_json::json!({
                "kind": e.kind.to_str(),
                "value": e.value,
                "confidence": e.confidence,
                "source_pattern": e.source_pattern,
                "boost_reason": e.boost_reason,
            })
        })
        .collect();
    let mut body = serde_json::json!({
        "query": text,
        "entities": entities_json,
    });
    if let Some(s) = scan {
        body["auto_scan"] = serde_json::json!({
            "scan_id": s.sid,
            "entities": s.entities,
            "relations": s.relations,
            "correlations": s.correlations,
        });
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".into())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_text() -> &'static str {
        "Find everything linked to alice@example.com and the domain example.com"
    }

    #[test]
    fn extracts_email_and_domain_from_a_natural_language_prompt() {
        // The core bridge this command exists for: a free-text investigative
        // question, not a clean single value, still yields the entities it
        // names — the same deterministic extractor `hse ingest` already runs
        // on document text, so no external LLM call and nothing fabricated.
        let extractor = EntityExtractor::new(0.30).expect("valid floor");
        let entities = extractor.extract_from_text(sample_text());
        assert!(
            entities.iter().any(|e| e.value == "alice@example.com"),
            "must extract the email mentioned in the prompt: {entities:?}"
        );
        assert!(
            entities.iter().any(|e| e.value == "example.com"),
            "must extract the domain mentioned in the prompt: {entities:?}"
        );
    }

    #[tokio::test]
    async fn auto_scan_persists_entities_extracted_from_the_prompt() {
        // Under cfg(test) the store is rooted in a temp dir, so this touches
        // no real ~/.huntsman.
        let extractor = EntityExtractor::new(0.30).expect("valid floor");
        let entities = extractor.extract_from_text(sample_text());
        assert!(
            !entities.is_empty(),
            "the sample prompt must extract something"
        );

        let summary = run_auto_scan(&entities, sample_text())
            .await
            .expect("auto-scan should persist the extracted entities");
        assert!(
            summary.sid.starts_with("investigate-"),
            "the scan id must mark it as an investigate-originated scan: {}",
            summary.sid
        );
        assert_eq!(summary.entities, entities.len());
    }

    #[tokio::test]
    async fn auto_scan_ids_are_unique_across_calls_in_the_same_second() {
        // Same collision hazard ingest's auto-scan had (and was fixed for):
        // a fixed-per-second id would let two investigations of the same
        // prompt in the same second overwrite each other's data.
        let extractor = EntityExtractor::new(0.30).expect("valid floor");
        let entities = extractor.extract_from_text(sample_text());
        let a = run_auto_scan(&entities, sample_text())
            .await
            .expect("first auto-scan persists");
        let b = run_auto_scan(&entities, sample_text())
            .await
            .expect("second auto-scan persists");
        assert_ne!(
            a.sid, b.sid,
            "two investigations must not collide on one scan id (would overwrite data)"
        );
    }

    #[test]
    fn entities_extracted_from_a_prompt_carry_investigate_provenance() {
        // Regression guard for the shared app::convert function: an
        // investigate-sourced entity must NOT be mislabelled as
        // document-ingested, and its evidence must name the prompt, not a
        // filename — the two commands share the converter but must never
        // share (or default) provenance.
        let entity = crate::app::convert::extracted_to_hse_entity(
            &ExtractedEntity {
                kind: crate::util::entity_extractor::EntityKind::Email,
                value: "alice@example.com".to_string(),
                confidence: 0.85,
                context: None,
                source_pattern: "email_rfc5322".to_string(),
                boost_reason: None,
            },
            "scan-1",
            "investigate:find what's linked to alice@example.com",
            "investigate-query",
        );
        assert!(entity.tags.contains(&"investigate-query".to_string()));
        assert!(!entity.tags.contains(&"document-ingestion".to_string()));
        assert!(
            entity
                .evidence
                .iter()
                .any(|e| e.source.starts_with("investigate:")),
            "evidence must name the investigate origin, not ingest"
        );
    }

    #[tokio::test]
    async fn empty_prompt_is_rejected() {
        let err = cmd_investigate(Some("   ".to_string()), false, 0.30, false)
            .await
            .expect_err("blank text must be rejected, not silently scan nothing");
        assert!(matches!(err, Error::InvalidTarget(_)));
    }
}
