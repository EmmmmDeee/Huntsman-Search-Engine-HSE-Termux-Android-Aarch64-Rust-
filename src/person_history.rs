//! Read-only, source-attributed review of every person in retained saved scans.
//!
//! Person names are scoped to their scan: equal names in different searches are NOT
//! proof of one human identity. A historical place label is contextual geography,
//! never evidence of birth, ethnicity, nationality, citizenship or parentage.
//! No network requests, provider keys, raw-record rewrites or new dependencies.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use serde::Serialize;

use crate::entity::{EntityKind, Evidence};
use crate::scan_store::{ScanRecord, ScanResults, ScanStore};

const DUSHANBE_HISTORY_SOURCE: &str = "https://www.iranicaonline.org/articles/dushanbe/";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HistoricalContext {
    pub location: String,
    pub date_claim: Option<String>,
    pub contemporary_place_name: String,
    pub contemporary_jurisdiction: String,
    pub source_url: &'static str,
    pub qualification: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BirthClaim {
    pub value: String,
    pub attribute: String,
    pub source: String,
    pub recorded_at_unix: u64,
    pub operator_seed: bool,
    pub inferred: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PersonHistoryRow {
    pub record_type: &'static str,
    pub scan_id: String,
    pub scan_created_ms: u64,
    pub scan_target: String,
    pub scan_target_type: String,
    pub person_name: String,
    /// UIDs are evidence pointers, not a global assertion of real-world identity.
    pub entity_uids: Vec<String>,
    pub discovered_as: Vec<String>,
    pub flagged_false_positive: bool,
    pub place_of_birth_claims: Vec<BirthClaim>,
    pub date_of_birth_claims: Vec<BirthClaim>,
    pub birthplace_status: &'static str,
    pub historical_context: Vec<HistoricalContext>,
    pub identity_status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ScanReadError {
    pub record_type: &'static str,
    pub scan_id: String,
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct AuditSummary {
    pub record_type: &'static str,
    pub scans_retained: usize,
    pub scans_read: usize,
    pub scans_unreadable: usize,
    pub person_scan_records: usize,
    pub with_birthplace_claim: usize,
    pub with_conflicting_birthplace_claims: usize,
    pub without_birthplace_claim: usize,
    /// This audit has no access to deleted, pruned, unsaved or remote history.
    pub history_scope: &'static str,
    pub complete_for_retained_scans: bool,
}

const PLACE_KEYS: &[&str] = &[
    "place_of_birth",
    "birth_place",
    "birthplace",
    "pob",
    "birth_city",
    "birth_town",
];
const DATE_KEYS: &[&str] = &["date_of_birth", "birth_date", "dob"];

fn facts(evidence: &Evidence, keys: &[&str]) -> Vec<BirthClaim> {
    let mut facts = Vec::new();
    for (key, raw) in &evidence.attributes {
        if !keys.iter().any(|wanted| key.eq_ignore_ascii_case(wanted)) {
            continue;
        }
        // Keep the original source's values and their provenance. Only split
        // the delimiter Evidence::with_attr itself uses for repeated values.
        for value in raw.split("; ").map(str::trim).filter(|v| !v.is_empty()) {
            facts.push(BirthClaim {
                value: value.to_owned(),
                attribute: key.clone(),
                source: evidence.provenance.source.clone(),
                recorded_at_unix: evidence.provenance.recorded_at_unix,
                operator_seed: evidence.is_operator_seed(),
                inferred: evidence.is_inferred,
            });
        }
    }
    facts
}

fn key(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Only an unambiguous year (year or ISO date) is usable for historical context.
fn birth_date(date: &str) -> Option<(i32, Option<&str>)> {
    let date = date.trim();
    let year = date.get(..4)?.parse::<i32>().ok()?;
    if !(1800..=2100).contains(&year) {
        return None;
    }
    if date.len() == 4 {
        return Some((year, None));
    }
    let iso = date.get(..10)?;
    let bytes = iso.as_bytes();
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let month = iso.get(5..7)?.parse::<u8>().ok()?;
    let day = iso.get(8..10)?.parse::<u8>().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, Some(iso)))
}

/// Historically attested names are only applied to a *claimed* birthplace.
/// Unrecognised locations deliberately receive no invented historical context.
fn dushanbe(place: &str, date: Option<&str>) -> Option<HistoricalContext> {
    let simple = place.trim().to_lowercase();
    let valid = [
        "dushanbe",
        "душанбе",
        "stalinabad",
        "сталинабад",
        "stalinobod",
        "сталинобод",
        "dyushambe",
        "дюшамбе",
        "dushanbe, tajikistan",
        "dushanbe, tajik ssr",
    ]
    .contains(&simple.as_str());
    if !valid {
        return None;
    }

    let (name, jurisdiction) = match date.and_then(birth_date) {
        Some((year, _)) if year < 1929 => (
            "Dyushambe / Dushanbe (period-dependent)",
            "Historical jurisdiction must be checked for the exact birth date",
        ),
        Some((1929 | 1961, _)) => (
            "Year of city renaming",
            "Exact effective renaming date unresolved",
        ),
        Some((year, _)) if (1930..1961).contains(&year) => {
            ("Stalinabad", "Tajik Soviet Socialist Republic, USSR")
        }
        Some((year, _)) if (1962..1991).contains(&year) => {
            ("Dushanbe", "Tajik Soviet Socialist Republic, USSR")
        }
        Some((1991, Some(iso))) if iso < "1991-09-09" => {
            ("Dushanbe", "Tajik Soviet Socialist Republic, USSR")
        }
        Some((1991, Some(_))) => (
            "Dushanbe",
            "Republic of Tajikistan (independence declared 9 September 1991)",
        ),
        Some((1991, None)) => ("Dushanbe", "1991 transition; full birth date needed"),
        Some((year, _)) if year > 1991 => ("Dushanbe", "Republic of Tajikistan"),
        _ => (
            "Dushanbe / Stalinabad / Dyushambe (date-dependent)",
            "Birth date not established",
        ),
    };
    Some(HistoricalContext {
        location: place.to_owned(),
        date_claim: date.map(str::to_owned),
        contemporary_place_name: name.to_owned(),
        contemporary_jurisdiction: jurisdiction.to_owned(),
        source_url: DUSHANBE_HISTORY_SOURCE,
        qualification: "Conditional historical context only: neither the person's birthplace nor citizenship is verified",
    })
}

fn distinct_values(claims: &[BirthClaim]) -> usize {
    claims
        .iter()
        .map(|claim| key(&claim.value))
        .collect::<BTreeSet<_>>()
        .len()
}

fn people_in_scan(scan: &ScanRecord, results: Option<&ScanResults>) -> Vec<PersonHistoryRow> {
    let mut found = BTreeMap::<String, PersonHistoryRow>::new();

    let mut add = |name: &str, source: &str| {
        if name.trim().is_empty() {
            return;
        }
        let index = key(name);
        let row = found.entry(index).or_insert_with(|| PersonHistoryRow {
            record_type: "person",
            scan_id: scan.id.clone(),
            scan_created_ms: scan.created,
            scan_target: scan.target.clone(),
            scan_target_type: scan.target_type.clone(),
            person_name: name.trim().to_owned(),
            entity_uids: Vec::new(),
            discovered_as: Vec::new(),
            flagged_false_positive: false,
            place_of_birth_claims: Vec::new(),
            date_of_birth_claims: Vec::new(),
            birthplace_status: "not_recorded",
            historical_context: Vec::new(),
            identity_status: "unverified_name_association",
        });
        if !row.discovered_as.iter().any(|part| part == source) {
            row.discovered_as.push(source.to_owned());
        }
    };

    if scan.kind == "people" || scan.target_type == "HUMAN_NAME" {
        add(&scan.target, "scan_target");
    }
    if let Some(results) = results {
        for entity in &results.entities {
            if entity.kind == EntityKind::Person {
                add(&entity.raw_value, "person_entity");
            }
        }
        for element in &results.elements {
            if element.kind == "HUMAN_NAME" {
                add(&element.data, "human_name_element");
            }
        }
        drop(add);

        for entity in &results.entities {
            if entity.kind != EntityKind::Person {
                continue;
            }
            if let Some(row) = found.get_mut(&key(&entity.raw_value)) {
                if !row.entity_uids.contains(&entity.uid) {
                    row.entity_uids.push(entity.uid.clone());
                }
                for evidence in &entity.evidence {
                    row.place_of_birth_claims
                        .extend(facts(evidence, PLACE_KEYS));
                    row.date_of_birth_claims.extend(facts(evidence, DATE_KEYS));
                }
            }
        }
        for element in &results.elements {
            if element.kind == "HUMAN_NAME" && element.fp {
                if let Some(row) = found.get_mut(&key(&element.data)) {
                    row.flagged_false_positive = true;
                }
            }
        }
    } else {
        drop(add);
    }

    for row in found.values_mut() {
        let unique = distinct_values(&row.place_of_birth_claims);
        row.birthplace_status = match unique {
            0 => "not_recorded",
            1 => "reported_unverified",
            _ => "conflicting_claims",
        };
        let mut seen = BTreeSet::new();
        for place in &row.place_of_birth_claims {
            if row.date_of_birth_claims.is_empty() {
                if let Some(context) = dushanbe(&place.value, None) {
                    let token = (context.location.clone(), context.date_claim.clone());
                    if seen.insert(token) {
                        row.historical_context.push(context);
                    }
                }
            }
            for dob in &row.date_of_birth_claims {
                if let Some(context) = dushanbe(&place.value, Some(&dob.value)) {
                    let token = (context.location.clone(), context.date_claim.clone());
                    if seen.insert(token) {
                        row.historical_context.push(context);
                    }
                }
            }
        }
    }

    found.into_values().collect()
}

fn emit<T: Serialize>(writer: &mut impl Write, row: &T) -> Result<(), String> {
    serde_json::to_writer(&mut *writer, row).map_err(|error| error.to_string())?;
    writer.write_all(b"\n").map_err(|error| error.to_string())
}

/// Stream a read-only JSONL record for *every* retained person occurrence.
/// A summary is emitted last; unreadable scans produce explicit error records.
///
/// The store's saved-scan listing has a 4096-scan cap and excludes deleted,
/// pruned and unsaved direct lookups; the output never claims more coverage.
/// Memory stays bounded to one scan's saved results rather than all scans.
pub fn audit_all(store: &ScanStore, writer: &mut impl Write) -> Result<AuditSummary, String> {
    let scans = store.list().map_err(|error| error.to_string())?;
    let mut summary = AuditSummary {
        record_type: "summary",
        scans_retained: scans.len(),
        history_scope: "retained_saved_scans_only",
        ..AuditSummary::default()
    };
    for scan in scans {
        let results = match store.results(&scan.id) {
            Ok(results) => results,
            Err(error) => {
                summary.scans_unreadable += 1;
                emit(
                    writer,
                    &ScanReadError {
                        record_type: "scan_read_error",
                        scan_id: scan.id,
                        error: error.to_string(),
                    },
                )?;
                continue;
            }
        };
        summary.scans_read += 1;
        for row in people_in_scan(&scan, results.as_ref()) {
            summary.person_scan_records += 1;
            match row.birthplace_status {
                "not_recorded" => summary.without_birthplace_claim += 1,
                "conflicting_claims" => {
                    summary.with_birthplace_claim += 1;
                    summary.with_conflicting_birthplace_claims += 1;
                }
                _ => summary.with_birthplace_claim += 1,
            }
            emit(writer, &row)?;
        }
    }
    summary.complete_for_retained_scans = summary.scans_unreadable == 0;
    emit(writer, &summary)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EvidenceProvenance};
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanStatus};

    fn record() -> ScanRecord {
        ScanRecord {
            format_version: FORMAT_VERSION,
            id: "0123456789abcdef".to_owned(),
            name: "sample".to_owned(),
            target: "Jane Citizen".to_owned(),
            target_type: "HUMAN_NAME".to_owned(),
            kind: "people".to_owned(),
            options: ScanOptions::default(),
            status: ScanStatus::Finished,
            created: 1000,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
            owner_started: None,
        }
    }

    #[test]
    fn retained_target_is_reported_even_without_results() {
        let rows = people_in_scan(&record(), None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].birthplace_status, "not_recorded");
        assert_eq!(rows[0].discovered_as, vec!["scan_target"]);
    }

    #[test]
    fn raw_source_claim_is_attributed_and_context_is_conditional() {
        let mut person = Entity::new(EntityKind::Person, "Jane Citizen", 0.4, "0123456789abcdef");
        person.add_evidence(
            Evidence::new(EvidenceProvenance::new("public_registry"), "birth claim")
                .with_attr("place_of_birth", "Dushanbe, Tajikistan")
                .with_attr("date_of_birth", "1985-05-05"),
        );
        let results = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: record().id,
            text: String::new(),
            entities: vec![person],
            outcomes: Vec::new(),
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        let rows = people_in_scan(&record(), Some(&results));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].place_of_birth_claims[0].source, "public_registry");
        assert_eq!(
            rows[0].historical_context[0].contemporary_place_name,
            "Dushanbe"
        );
        assert!(
            rows[0].historical_context[0]
                .contemporary_jurisdiction
                .contains("USSR")
        );
    }

    #[test]
    fn cannot_conflate_people_between_scans_or_infer_unprovided_birthplace() {
        let other = record();
        let mut renamed = record();
        renamed.id = "ffffffffffffffff".to_owned();
        assert_eq!(people_in_scan(&other, None)[0].scan_id, other.id);
        assert_eq!(people_in_scan(&renamed, None)[0].scan_id, renamed.id);
        assert!(
            people_in_scan(&other, None)[0]
                .historical_context
                .is_empty()
        );
    }

    #[test]
    fn renaming_and_independence_boundaries_are_not_guessed() {
        assert_eq!(
            dushanbe("Stalinabad", Some("1955-02-12"))
                .unwrap()
                .contemporary_place_name,
            "Stalinabad"
        );
        assert!(
            dushanbe("Dushanbe", Some("1961"))
                .unwrap()
                .contemporary_jurisdiction
                .contains("unresolved")
        );
        assert!(
            dushanbe("Dushanbe", Some("1991"))
                .unwrap()
                .contemporary_jurisdiction
                .contains("transition")
        );
        assert!(
            dushanbe("Dushanbe", Some("1991-09-08"))
                .unwrap()
                .contemporary_jurisdiction
                .contains("USSR")
        );
        assert!(
            dushanbe("Dushanbe", Some("1991-09-09"))
                .unwrap()
                .contemporary_jurisdiction
                .contains("Republic of Tajikistan")
        );
        assert!(dushanbe("Paris", Some("1985-01-01")).is_none());
    }

    #[test]
    fn distinct_birthplaces_are_retained_as_conflict() {
        let a = BirthClaim {
            value: "Dushanbe".into(),
            attribute: "pob".into(),
            source: "source_a".into(),
            recorded_at_unix: 1,
            operator_seed: false,
            inferred: false,
        };
        let mut b = a.clone();
        b.value = "Tashkent".into();
        assert_eq!(distinct_values(&[a, b]), 2);
    }
}
