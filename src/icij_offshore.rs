//! ICIJ Offshore Leaks: the keyless reconciliation API over the Panama, Paradise, Pandora and
//! Offshore Leaks databases.
//!
//! The API answers any name with fuzzy matches ("Ruja Ignatova" returns `RUJA FM`, `IGNATOVA
//! TRUST` and a different Ignatova), so a node is kept only when its name carries every word of
//! the query. A kept node is a lead into the leaked records, never proof that the person is the
//! one named: each becomes a `Document` keyed by its node URL, so it never merges into a namesake
//! from another source, and every node the search returned is kept in the evidence.

use serde_json::Value;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SOURCE: &str = "icij_offshore";
const ENDPOINT: &str = "https://offshoreleaks.icij.org/api/v1/reconcile";
const NODE_URL: &str = "https://offshoreleaks.icij.org/nodes/";
/// A lead into leaked records: below a register entry, above a bare search hit.
const NODE_CONFIDENCE: f64 = 0.5;
/// The most result nodes read from one answer.
const MAX_NODES: usize = 50;

pub type Report = crate::lookup_report::SourceReport;

/// The form body the reconciliation API reads: one query named `q0`. **Pure.**
#[must_use]
pub fn request_body(name: &str) -> Vec<u8> {
    let queries = serde_json::json!({ "q0": { "query": name } }).to_string();
    format!("queries={}", percent_encode_unreserved(&queries)).into_bytes()
}

/// Whether `node_name` carries every word of `query`. **Pure.**
fn names_query(node_name: &str, query: &str) -> bool {
    let wanted = crate::textnorm::name_match_keys(query);
    if wanted.is_empty() {
        return false;
    }
    let have = crate::textnorm::name_match_keys(node_name);
    wanted.iter().all(|word| have.contains(word))
}

/// Look up `name` in the Offshore Leaks databases.
///
/// # Errors
/// A network-boundary error when the guarded fetch refuses the request.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let request = Request::post(ENDPOINT, request_body(name))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json");
    let fetched = fetch(
        transport,
        request,
        None,
        &FetchOptions::no_redirects().paced(),
        SOURCE,
        now_unix,
    )?;
    Ok(interpret(&fetched, name, scan_id, now_unix).unwrap_or_else(Report::miss))
}

/// Turn one answer into a report; `Err` is the outcome of an answer that was not a readable
/// reconciliation result. **Pure.**
fn interpret(
    fetched: &crate::fetch::Fetched,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let response = whole_response(fetched, "ICIJ Offshore Leaks")?;
    answer(fetched, "ICIJ Offshore Leaks")?;
    let body: Value = decode_json(response, SOURCE, now_unix, "ICIJ Offshore Leaks")?;
    let Some(nodes) = body
        .get("q0")
        .and_then(|q| q.get("result"))
        .and_then(Value::as_array)
    else {
        return Err(SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::SchemaDrift,
            Some(response.status),
            "ICIJ reconciliation answer has no q0.result array",
        ));
    };

    let mut entities: Vec<Entity> = Vec::new();
    let mut others = 0usize;
    let mut unreadable = 0usize;
    for node in nodes.iter().take(MAX_NODES) {
        let id = node.get("id").and_then(|id| match id {
            Value::String(text) => Some(text.trim().to_owned()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        });
        let node_name = node.get("name").and_then(Value::as_str).map(str::trim);
        let (Some(id), Some(node_name)) = (id.filter(|id| !id.is_empty()), node_name) else {
            unreadable += 1;
            continue;
        };
        if !id.bytes().all(|b| b.is_ascii_digit()) {
            unreadable += 1;
            continue;
        }
        if !names_query(node_name, name) {
            others += 1;
            continue;
        }
        push_entity(
            &mut entities,
            EntityKind::Document,
            &format!("{NODE_URL}{id}"),
            NODE_CONFIDENCE,
            scan_id,
            node_evidence(node, &id, node_name, scan_id),
            &["icij", "offshore-leaks", "lead"],
        );
    }
    merge_by_uid(&mut entities);

    let mut remarks = Vec::new();
    if others > 0 {
        remarks.push(format!("{others} nodes the search returned name others"));
    }
    if unreadable > 0 {
        remarks.push(format!("{unreadable} nodes had no readable id or name"));
    }
    if nodes.len() > MAX_NODES {
        remarks.push(format!(
            "{} nodes beyond the first {MAX_NODES} were not read",
            nodes.len() - MAX_NODES
        ));
    }
    // A node that could not be read, or one past the cap that was never examined, may be the
    // subject: an empty result with either is inconclusive, never a clean "not in the leaks".
    let could_hide_a_match = unreadable > 0 || nodes.len() > MAX_NODES;
    let mut outcome = if !entities.is_empty() {
        SourceExecutionOutcome::success(SOURCE, now_unix, entities.len())
            .with_http_status(response.status)
    } else if could_hide_a_match {
        SourceExecutionOutcome::failed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            Some(response.status),
            "no readable node matched, but nodes were unreadable or beyond the cap",
        )
    } else {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_http_status(response.status)
    };
    if !remarks.is_empty() {
        let detail = match outcome.detail.take() {
            Some(base) if !base.is_empty() => format!("{base}; {}", remarks.join("; ")),
            _ => remarks.join("; "),
        };
        outcome = outcome.with_detail(detail);
    }
    Ok(Report { entities, outcome })
}

/// The evidence for one matched node, keeping every field the node carried verbatim.
fn node_evidence(node: &Value, id: &str, node_name: &str, scan_id: &str) -> Evidence {
    let node_type = node
        .get("types")
        .and_then(Value::as_array)
        .and_then(|types| types.first())
        .and_then(|t| t.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("Node");
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "ICIJ Offshore Leaks {node_type} node {id} ({node_name}) names every word of the query; a lead into leaked records, not proof it is the same person"
        ),
    )
    .with_attr("dataset", "ICIJ Offshore Leaks")
    .with_attr("node_id", id)
    .with_attr("node_name", node_name)
    .with_attr("node_type", node_type);
    if let Some(description) = node.get("description").and_then(Value::as_str) {
        evidence = evidence.with_attr("description", description);
    }
    if let Some(score) = node.get("score").and_then(Value::as_f64) {
        evidence = evidence.with_attr("icij_score", format!("{score:.1}"));
    }
    if let Some(matched) = node.get("match").and_then(Value::as_bool) {
        evidence = evidence.with_attr("icij_match", matched.to_string());
    }
    evidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    /// The shape the live API returned for "Ruja Ignatova" on 2026-11-07, with one node that
    /// does name her added.
    const ANSWER: &str = r#"{"q0":{"result":[
      {"id":"85044618","name":"RUJA FM","description":"Entity node","score":38.4,"match":false,"types":[{"id":"x","name":"Entity"}]},
      {"id":"200802736","name":"IGNATOVA TRUST","score":78.5,"match":false,"types":[{"id":"x","name":"Entity"}]},
      {"id":"23167","name":"Tatiana P. Ignatova","score":55.5,"match":false,"types":[{"id":"x","name":"Officer"}]},
      {"id":"99","name":"Ignatova, Ruja","description":"Officer node","score":90.0,"match":true,"types":[{"id":"x","name":"Officer"}]},
      {"id":"not-a-number","name":"Ruja Ignatova"}
    ]}}"#;

    #[test]
    fn a_node_is_kept_only_when_it_names_every_word_of_the_query() {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(ANSWER))]);
        let report = lookup(&transport, "Ruja Ignatova", "scan", 1).expect("lookup");
        let values: Vec<&str> = report
            .entities
            .iter()
            .map(|e| e.raw_value.as_str())
            .collect();
        assert_eq!(
            values,
            ["https://offshoreleaks.icij.org/nodes/99"],
            "{values:?}"
        );
        assert_eq!(report.entities[0].kind, EntityKind::Document);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let detail = report.outcome.detail.clone().unwrap_or_default();
        assert!(
            detail.contains("3 nodes the search returned name others"),
            "{detail}"
        );
        assert!(detail.contains("1 nodes had no readable id"), "{detail}");
        let request = &transport.seen.borrow()[0];
        assert!(request.url.starts_with(ENDPOINT));
    }

    #[test]
    fn an_unreadable_node_or_an_over_cap_result_is_inconclusive_not_a_clean_zero() {
        use std::fmt::Write as _;
        // The only node that names the subject has a non-numeric id: unreadable, no clean zero.
        let unreadable = r#"{"q0":{"result":[
          {"id":"1","name":"RUJA FM","types":[]},
          {"id":"not-a-number","name":"Ruja Ignatova"}
        ]}}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(unreadable))]);
        let report = lookup(&transport, "Ruja Ignatova", "scan", 1).expect("lookup");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("no readable id or name"),
            "{:?}",
            report.outcome
        );

        // 51 non-matching nodes: node 51 is never read, so a zero cannot be a clean negative.
        let mut over = String::from(r#"{"q0":{"result":["#);
        for id in 1000..1051 {
            if id > 1000 {
                over.push(',');
            }
            let _ = write!(over, r#"{{"id":"{id}","name":"Someone Else","types":[]}}"#);
        }
        over.push_str("]}}");
        let transport = ScriptedTransport::new(vec![Ok(json_ok(&over))]);
        let report = lookup(&transport, "Ruja Ignatova", "scan", 1).expect("lookup");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("beyond the first 50"),
            "{:?}",
            report.outcome
        );
    }

    #[test]
    fn only_strangers_is_a_clean_zero_and_a_bad_shape_is_drift() {
        let strangers = r#"{"q0":{"result":[{"id":"1","name":"RUJA FM","types":[]}]}}"#;
        let transport = ScriptedTransport::new(vec![Ok(json_ok(strangers))]);
        let report = lookup(&transport, "Ruja Ignatova", "scan", 1).expect("lookup");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);

        let transport = ScriptedTransport::new(vec![Ok(json_ok(r#"{"other":1}"#))]);
        let report = lookup(&transport, "Ruja Ignatova", "scan", 1).expect("lookup");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SchemaDrift);
    }

    #[test]
    fn the_body_is_one_form_encoded_query() {
        let body = String::from_utf8(request_body("Ruja Ignatova")).expect("utf8");
        assert!(body.starts_with("queries=%7B%22q0%22"), "{body}");
        assert!(body.contains("Ruja%20Ignatova"), "{body}");
    }
}
