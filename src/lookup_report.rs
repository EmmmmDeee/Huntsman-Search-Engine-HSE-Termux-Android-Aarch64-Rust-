//! The text report of an identifier lookup: the entities found, the outcome of each source, and the
//! lineage of the observations behind them. The email, username and people front-ends print this
//! report, so their formats cannot drift apart.
//!
//! The rows are tab-separated records, and the values in them come from third parties: a profile
//! name, a register entry, a dataset name. Every value is written through
//! [`escape_controls`](crate::textnorm::escape_controls) here, so a value can neither drive the
//! terminal with an escape sequence nor start a row or a column of its own. [`entity_row`] and
//! [`evidence_row`] are the only places a row of this shape is formatted, and
//! `tests/architecture_boundaries.rs` fails if a second one appears.

use std::fmt::Write as _;

use crate::entity::{Entity, Evidence};
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{lineage_tsv_line, observations_from, resolve_with_lineage};
use crate::source_outcome::SourceExecutionOutcome;
use crate::textnorm::escape_controls;

/// One entity row: kind, `value`, confidence, tags. The caller picks the value it shows: a lookup
/// shows what the source said (`raw_value`), `recon` the normalised value.
#[must_use]
pub fn entity_row(entity: &Entity, value: &str) -> String {
    format!(
        "{}\t{}\t{:.2}\t{}",
        entity.kind,
        escape_controls(value),
        entity.confidence,
        escape_controls(&entity.tags.join(","))
    )
}

/// The row that names the evidence behind an entity: its source and its summary.
#[must_use]
pub fn evidence_row(evidence: &Evidence) -> String {
    format!(
        "evidence\t{}\t{}",
        escape_controls(&evidence.provenance.source),
        escape_controls(&evidence.summary)
    )
}

/// Longest outcome detail shown, in characters.
const MAX_DETAIL_CHARS: usize = 200;

/// Why a source reached its outcome, as one escaped line of at most 200 characters, when the
/// source said. Detail can quote a provider, so every control character is escaped.
#[must_use]
pub fn outcome_detail(outcome: &SourceExecutionOutcome) -> Option<String> {
    let detail = outcome.detail.as_deref()?.trim();
    if detail.is_empty() {
        return None;
    }
    let shown = match detail.char_indices().nth(MAX_DETAIL_CHARS) {
        Some((cut, _)) => format!("{}...", &detail[..cut]),
        None => detail.to_owned(),
    };
    Some(escape_controls(&shown))
}

/// The report of one lookup. The first line is `entities=N`. Each entity follows as a
/// tab-separated line (kind, value, confidence, tags), then each source outcome (module, kind,
/// found count, and `detail=` when the source gave a reason), and the lineage block closes the
/// report.
///
/// # Errors
/// The first formatting or lineage-resolution error, as text.
pub fn render(entities: &[Entity], outcomes: &[SourceExecutionOutcome]) -> Result<String, String> {
    let mut out = format!("entities={}\n", entities.len());
    for entity in entities {
        writeln!(out, "{}", entity_row(entity, &entity.raw_value))
            .map_err(|err| err.to_string())?;
    }
    for outcome in outcomes {
        let found = outcome
            .found
            .map_or_else(|| "none".to_owned(), |count| count.to_string());
        let kind = serde_json::to_value(outcome.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".into());
        write!(
            out,
            "{}\t{kind}\tfound={found}",
            escape_controls(&outcome.module)
        )
        .map_err(|err| err.to_string())?;
        if let Some(detail) = outcome_detail(outcome) {
            write!(out, "\tdetail={detail}").map_err(|err| err.to_string())?;
        }
        out.push('\n');
    }
    append_lineage(entities, &mut out)?;
    Ok(out)
}

fn append_lineage(entities: &[Entity], out: &mut String) -> Result<(), String> {
    let observations = observations_from(entities);
    if observations.is_empty() {
        return Ok(());
    }
    let resolution = resolve_with_lineage(observations, Vec::new(), AutoMergePolicy::default())
        .map_err(|err| err.to_string())?;
    writeln!(out, "lineage={}", resolution.observations.len()).map_err(|err| err.to_string())?;
    for item in &resolution.observations {
        writeln!(out, "{}", lineage_tsv_line(item)).map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    use crate::test_support::unexpected_controls;

    /// Text a third party controls: a terminal escape, a forged row, a forged column, a carriage
    /// return, DEL and NUL.
    const HOSTILE: &str = "Ada\u{1b}[2J\nforged\tcolumn\r\u{7f}\u{0} Lovelace";

    fn entity_from(kind: EntityKind, value: &str, datasets: &[&str]) -> Entity {
        let mut entity = Entity::new(kind, value, 0.9, "scan");
        entity.tag("tag\u{1b}[31m\nforged");
        let mut evidence = Evidence::new(EvidenceProvenance::new("probe"), "record");
        for dataset in datasets {
            evidence = evidence.with_attr("dataset", *dataset);
        }
        entity.add_evidence(evidence);
        entity
    }

    #[test]
    fn a_failed_outcome_shows_its_reason_escaped_and_capped() {
        let mut failed = SourceExecutionOutcome::success("asic_director", 1, 0);
        failed.kind = crate::source_outcome::SourceOutcomeKind::Inconclusive;
        failed.found = None;
        failed.detail = Some(HOSTILE.to_owned());
        let mut long = SourceExecutionOutcome::success("asic_persons", 1, 0);
        long.detail = Some("x".repeat(500));
        let silent = SourceExecutionOutcome::success("gravatar", 1, 3);

        let report = render(&[], &[failed, long, silent]).unwrap();
        let lines: Vec<&str> = report.lines().collect();

        assert_eq!(lines.len(), 4, "{report}");
        assert!(lines[1].starts_with("asic_director\tinconclusive\tfound=none\tdetail=Ada"));
        assert_eq!(lines[1].split('\t').count(), 4, "{}", lines[1]);
        assert!(
            unexpected_controls(lines[1], &['\t']).is_empty(),
            "{}",
            lines[1]
        );
        assert_eq!(
            lines[2],
            format!(
                "asic_persons\tinconclusive\tfound=0\tdetail={}...",
                "x".repeat(200)
            )
        );
        assert_eq!(lines[3], "gravatar\tsuccess\tfound=3");
    }

    #[test]
    fn third_party_text_cannot_break_a_row_or_drive_the_terminal() {
        let entities = vec![
            entity_from(EntityKind::Person, HOSTILE, &["set\u{1b}[0m"]),
            // Two different datasets make the lineage ambiguous, which prints every candidate.
            entity_from(
                EntityKind::Organisation,
                "Acme\u{1b}]0;title\u{7} Pty Ltd",
                &["one\nforged", "two\tcolumn"],
            ),
        ];
        let outcomes = vec![SourceExecutionOutcome::success("module\u{1b}[1m", 1, 2)];
        let text = render(&entities, &outcomes).expect("the report renders");

        assert!(
            unexpected_controls(&text, &['\n', '\t']).is_empty(),
            "a control character other than the report's own separators: {text:?}"
        );
        for row in text.lines().skip(1).take(entities.len()) {
            assert_eq!(
                row.matches('\t').count(),
                3,
                "an entity row is four columns: {row:?}"
            );
        }
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("forged") || line.starts_with("column")),
            "text inside a value became a row of its own: {text:?}"
        );
        assert!(
            text.contains("Ada\\u{1b}[2J\\nforged\\tcolumn\\r\\u{7f}\\u{0} Lovelace"),
            "the value is shown escaped, not dropped: {text:?}"
        );
    }

    #[test]
    fn the_row_functions_escape_the_value_the_caller_chooses_to_show() {
        let entity = entity_from(EntityKind::Person, "Ada Lovelace", &[]);
        assert_eq!(
            entity_row(&entity, "normalised\nvalue"),
            "person\tnormalised\\nvalue\t0.90\ttag\\u{1b}[31m\\nforged"
        );
        let evidence = Evidence::new(
            EvidenceProvenance::new("probe\u{1b}[1m"),
            "summary\nforged\tcolumn\u{1b}[2J",
        );
        assert_eq!(
            evidence_row(&evidence),
            "evidence\tprobe\\u{1b}[1m\tsummary\\nforged\\tcolumn\\u{1b}[2J"
        );
    }

    /// Every kind. The match has no wildcard, so adding a variant stops this from compiling and the
    /// tests below cannot quietly skip it.
    fn every_kind() -> Vec<EntityKind> {
        let all = vec![
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Username,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::IpAddress,
            EntityKind::Coordinates,
            EntityKind::Address,
            EntityKind::Credential,
            EntityKind::Document,
            EntityKind::CryptoAddress,
            EntityKind::DeviceId,
            EntityKind::Ssid,
            EntityKind::TrackingId,
            EntityKind::AbnAcn,
            EntityKind::ApiKey,
            EntityKind::MacAddress,
            EntityKind::Asn,
            EntityKind::Other,
        ];
        for kind in &all {
            match kind {
                EntityKind::Person
                | EntityKind::Organisation
                | EntityKind::Email
                | EntityKind::Phone
                | EntityKind::Username
                | EntityKind::Domain
                | EntityKind::Url
                | EntityKind::IpAddress
                | EntityKind::Coordinates
                | EntityKind::Address
                | EntityKind::Credential
                | EntityKind::Document
                | EntityKind::CryptoAddress
                | EntityKind::DeviceId
                | EntityKind::Ssid
                | EntityKind::TrackingId
                | EntityKind::AbnAcn
                | EntityKind::ApiKey
                | EntityKind::MacAddress
                | EntityKind::Asn
                | EntityKind::Other => {}
            }
        }
        all
    }

    #[test]
    fn a_row_names_its_kind_as_the_json_wire_format_does() {
        // `recon` used to take the kind name from serde and every other printer from `Display`.
        for kind in every_kind() {
            let wire = serde_json::to_value(&kind).expect("a kind serialises");
            assert_eq!(wire.as_str(), Some(kind.as_str()), "{kind:?}");
            let entity = Entity::new(kind.clone(), "v", 0.5, "scan");
            assert!(
                entity_row(&entity, "v").starts_with(&format!("{}\t", kind.as_str())),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn ordinary_rows_keep_the_exact_bytes_the_old_formatters_wrote() {
        // The five formatters this module replaced all wrote this for text with no control characters.
        let value = "Émile O'Brien-Smith";
        for kind in every_kind() {
            let mut entity = Entity::new(kind.clone(), value, 0.123, "scan");
            entity.tag("github");
            entity.tag("public-profile");
            let old = format!(
                "{}\t{}\t{:.2}\t{}",
                kind.as_str(),
                value,
                0.123,
                "github,public-profile"
            );
            assert_eq!(entity_row(&entity, value), old, "{kind:?}");
        }
    }

    #[test]
    fn ordinary_text_is_printed_unchanged() {
        let entities = vec![entity_from(
            EntityKind::Person,
            "Émile Zola",
            &["Dataset A"],
        )];
        let text = render(&entities, &[]).expect("the report renders");
        assert!(text.contains("person\tÉmile Zola\t0.90\t"), "{text:?}");
    }
}
