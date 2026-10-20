//! The text report of an identifier lookup: the entities found, the outcome of each source, the
//! relations between the entities, and the lineage of the observations behind them. The email,
//! username, people, domain, network and exposure front-ends print this report, so their formats
//! cannot drift apart.
//!
//! The rows are tab-separated records, and the values in them come from third parties: a profile
//! name, a register entry, a dataset name. Every value is written through
//! [`escape_controls`](crate::textnorm::escape_controls) here, so a value can neither drive the
//! terminal with an escape sequence nor start a row or a column of its own. [`entity_row`],
//! [`evidence_row`] and [`attribute_row`] are the only places a row of this shape is formatted, and
//! `tests/architecture_boundaries.rs` fails if a second one appears. A report leaves nothing out:
//! each entity is followed by every evidence record behind it, and each evidence record by every
//! attribute it carries.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::entity::{Entity, Evidence};
use crate::identity_resolution::AutoMergePolicy;
use crate::lineage::{lineage_tsv_line, observations_from, resolve_with_lineage};
use crate::relation::{self, Relation};
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

/// The row that names one attribute of an evidence record: its key and its value, both escaped.
#[must_use]
pub fn attribute_row(key: &str, value: &str) -> String {
    format!(
        "attribute\t{}\t{}",
        escape_controls(key),
        escape_controls(value)
    )
}

/// The rows that name one evidence record: its own row, then one row per attribute it carries, in
/// key order.
#[must_use]
pub fn evidence_rows(evidence: &Evidence) -> Vec<String> {
    let mut rows = vec![evidence_row(evidence)];
    rows.extend(
        evidence
            .attributes
            .iter()
            .map(|(key, value)| attribute_row(key, value)),
    );
    rows
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

/// The row that names one source outcome: module, kind, found count (`none` when the source
/// gave no count), and `detail=` when the source gave a reason.
#[must_use]
pub fn outcome_row(outcome: &SourceExecutionOutcome) -> String {
    let found = outcome
        .found
        .map_or_else(|| "none".to_owned(), |count| count.to_string());
    let kind = serde_json::to_value(outcome.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into());
    let mut row = format!(
        "{}\t{kind}\tfound={found}",
        escape_controls(&outcome.module)
    );
    if let Some(detail) = outcome_detail(outcome) {
        row.push_str("\tdetail=");
        row.push_str(&detail);
    }
    row
}

/// The row that names one relation between two entities of a report: `relation`, its kind, each
/// end as kind and the value the entity row shows, and its confidence.
#[must_use]
pub fn relation_row(relation: &Relation, from: &Entity, to: &Entity) -> String {
    format!(
        "relation\t{}\t{}\t{}\t{}\t{}\t{:.2}",
        relation.kind,
        from.kind,
        escape_controls(&from.raw_value),
        to.kind,
        escape_controls(&to.raw_value),
        relation.confidence
    )
}

/// The report of one lookup. The first line is `entities=N`. Each entity follows as a
/// tab-separated line (kind, value, confidence, tags), then each evidence record behind it and each
/// attribute of that evidence (see [`evidence_rows`]). Then each source outcome (module, kind,
/// found count, and `detail=` when the source gave a reason), then `relations=N` and a
/// [`relation_row`] for each relation the analysis derives between the entities
/// ([`relation::derive_all`], as the pipeline and `correlate` do), and the lineage block closes
/// the report. A report with no relation has no relations block.
///
/// # Errors
/// The first formatting or lineage-resolution error, as text.
pub fn render(entities: &[Entity], outcomes: &[SourceExecutionOutcome]) -> Result<String, String> {
    let mut out = format!("entities={}\n", entities.len());
    for entity in entities {
        writeln!(out, "{}", entity_row(entity, &entity.raw_value))
            .map_err(|err| err.to_string())?;
        for evidence in &entity.evidence {
            for row in evidence_rows(evidence) {
                writeln!(out, "{row}").map_err(|err| err.to_string())?;
            }
        }
    }
    for outcome in outcomes {
        writeln!(out, "{}", outcome_row(outcome)).map_err(|err| err.to_string())?;
    }
    append_relations(entities, &mut out)?;
    append_lineage(entities, &mut out)?;
    Ok(out)
}

/// The relations between the report's entities, one row each, sorted so the same entities
/// always print the same block.
fn append_relations(entities: &[Entity], out: &mut String) -> Result<(), String> {
    let Some(scan_id) = entities.first().map(|entity| entity.scan_id.as_str()) else {
        return Ok(());
    };
    let by_uid = entities
        .iter()
        .map(|entity| (entity.uid.as_str(), entity))
        .collect::<HashMap<_, _>>();
    let mut rows = relation::derive_all(entities, scan_id)
        .iter()
        .filter_map(|relation| {
            let from = by_uid.get(relation.from_uid.as_str())?;
            let to = by_uid.get(relation.to_uid.as_str())?;
            Some(relation_row(relation, from, to))
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Ok(());
    }
    rows.sort();
    rows.dedup();
    writeln!(out, "relations={}", rows.len()).map_err(|err| err.to_string())?;
    for row in rows {
        writeln!(out, "{row}").map_err(|err| err.to_string())?;
    }
    Ok(())
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

    #[test]
    fn a_report_lists_the_relations_between_its_entities_with_their_values_escaped() {
        let employer = format!("Example {HOSTILE} Pty Ltd");
        let mut person = Entity::new(EntityKind::Person, HOSTILE, 0.7, "scan");
        person.add_evidence(
            Evidence::new(EvidenceProvenance::new("profile"), "a public profile")
                .with_attr("employer", &employer),
        );
        let org = Entity::new(EntityKind::Organisation, &employer, 0.55, "scan");
        let text = render(&[person, org], &[]).unwrap();
        let relations = text
            .lines()
            .skip_while(|line| !line.starts_with("relations="))
            .take_while(|line| !line.starts_with("lineage="))
            .collect::<Vec<_>>();
        let shown = escape_controls(HOSTILE);
        assert_eq!(
            relations,
            [
                "relations=1".to_owned(),
                format!(
                    "relation\temployed_by\tperson\t{shown}\torganisation\tExample {shown} Pty Ltd\t0.55"
                ),
            ],
            "{text}"
        );
        assert!(
            unexpected_controls(&text, &['\n', '\t']).is_empty(),
            "{text:?}"
        );
    }

    #[test]
    fn a_report_with_no_relation_has_no_relations_block() {
        let text = render(
            &[Entity::new(EntityKind::Email, "a@example.com", 0.9, "scan")],
            &[],
        )
        .unwrap();
        assert!(!text.contains("relations="), "{text}");
    }

    /// The front-ends print the report as it renders, so an email lookup shows the relations
    /// between what it found: here only what it derives from the address itself, with every
    /// public source answering that it has nothing.
    #[test]
    fn an_email_lookup_prints_the_relations_between_its_entities() {
        use crate::email_cli::{self, EmailRun};
        use crate::http::Response;
        use crate::test_support::ScriptedTransport;
        let reply = |status, body: &str| {
            Ok(Response {
                status,
                headers: vec![("content-type".into(), "application/json".into())],
                body: body.as_bytes().to_vec(),
                truncated: false,
            })
        };
        let transport = ScriptedTransport::new(vec![
            reply(404, ""),
            reply(200, r#"{"users":[]}"#),
            reply(404, "No key found"),
        ]);
        let EmailRun::Printed { text, .. } = email_cli::run(&transport, "jane.doe@acme.example", 1)
        else {
            panic!("email lookup did not print");
        };
        assert!(
            text.contains(
                "\nrelation\tbelongs_to_domain\temail\tjane.doe@acme.example\tdomain\tacme.example\t0.80\n"
            ),
            "{text}"
        );
        let block = text.find("\nrelations=").expect("a relations block");
        assert!(
            block > text.find("\nopenpgp_keys\t").expect("the outcome rows")
                && block < text.find("\nlineage=").expect("the lineage block"),
            "relations follow the outcomes and precede the lineage: {text}"
        );
    }

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
        for entity in &entities {
            let row = entity_row(entity, &entity.raw_value);
            assert!(text.lines().any(|line| line == row), "{row:?} in {text:?}");
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
        assert_eq!(
            attribute_row("key\nforged", "value\tcolumn\u{1b}[2J"),
            "attribute\tkey\\nforged\tvalue\\tcolumn\\u{1b}[2J"
        );
    }

    #[test]
    fn every_evidence_record_and_attribute_is_printed_under_its_entity() {
        let mut entity = entity_from(EntityKind::Person, "Ada Lovelace", &[]);
        let mut first = Evidence::new(EvidenceProvenance::new("register"), "first record")
            .with_attr("registrant", "Ada Lovelace")
            .with_attr("note", "line one\nline two");
        first
            .attributes
            .insert("address".into(), "1 Analytical Way".into());
        entity.add_evidence(first);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::new("forum"),
            "second record",
        ));

        let text = render(std::slice::from_ref(&entity), &[]).expect("the report renders");
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|line| *line == entity_row(&entity, &entity.raw_value))
            .expect("the entity row is printed");
        assert_eq!(
            &lines[at + 1..at + 7],
            [
                "evidence\tprobe\trecord",
                "evidence\tregister\tfirst record",
                "attribute\taddress\t1 Analytical Way",
                "attribute\tnote\tline one\\nline two",
                "attribute\tregistrant\tAda Lovelace",
                "evidence\tforum\tsecond record",
            ],
            "{text}"
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
            EntityKind::Netblock,
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
                | EntityKind::Netblock
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
