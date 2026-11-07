//! Read-only, source-attributed review of every person in retained saved scans.
//!
//! Person names are scoped to their scan: equal names in different searches are NOT
//! proof of one human identity. A historical place label is contextual geography,
//! never evidence of birth, ethnicity, nationality, citizenship or parentage.
//! No network requests, provider keys, raw-record rewrites or new dependencies.

use std::collections::BTreeSet;
use std::io::Write;

use serde::Serialize;

use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
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
    /// Exact saved attribute text, before separating `Evidence::with_attr` values.
    pub raw_attribute_value: String,
    pub attribute: String,
    pub source: String,
    pub source_scan_id: Option<String>,
    pub recorded_at_unix: u64,
    pub merged_provenance: Vec<EvidenceProvenance>,
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
    /// Unique within the saved scan, not a real-world person identifier.
    pub occurrence_id: String,
    /// UIDs are evidence pointers, not a global assertion of real-world identity.
    pub entity_uids: Vec<String>,
    pub element_id: Option<String>,
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
                raw_attribute_value: raw.clone(),
                attribute: key.clone(),
                source: evidence.provenance.source.clone(),
                source_scan_id: evidence.provenance.scan_id.clone(),
                recorded_at_unix: evidence.provenance.recorded_at_unix,
                merged_provenance: evidence.merged_provenance.clone(),
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
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
    {
        return None;
    }
    let month = date.get(5..7)?.parse::<u8>().ok()?;
    let day = date.get(8..10)?.parse::<u8>().ok()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days {
        return None;
    }
    Some((year, Some(date)))
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

fn new_row(
    scan: &ScanRecord,
    name: &str,
    occurrence_id: String,
    discovered_as: &str,
) -> PersonHistoryRow {
    PersonHistoryRow {
        record_type: "person",
        scan_id: scan.id.clone(),
        scan_created_ms: scan.created,
        scan_target: scan.target.clone(),
        scan_target_type: scan.target_type.clone(),
        person_name: name.to_owned(),
        occurrence_id,
        entity_uids: Vec::new(),
        element_id: None,
        discovered_as: vec![discovered_as.to_owned()],
        flagged_false_positive: false,
        place_of_birth_claims: Vec::new(),
        date_of_birth_claims: Vec::new(),
        birthplace_status: "not_recorded",
        historical_context: Vec::new(),
        identity_status: "unverified_name_association",
    }
}

fn push_context(row: &mut PersonHistoryRow, places: &[BirthClaim], dates: &[BirthClaim]) {
    let mut insert = |place: &BirthClaim, date: Option<&BirthClaim>| {
        let context = dushanbe(&place.value, date.map(|date| date.value.as_str()));
        if let Some(context) = context {
            if !row.historical_context.contains(&context) {
                row.historical_context.push(context);
            }
        }
    };
    for place in places {
        // Date claims are only paired with places within the SAME Evidence.
        // Never take a Cartesian product of unrelated sources or identities.
        if dates.is_empty() {
            insert(place, None);
        } else {
            for date in dates {
                insert(place, Some(date));
            }
        }
    }
}

fn people_in_scan(scan: &ScanRecord, results: Option<&ScanResults>) -> Vec<PersonHistoryRow> {
    let mut rows = Vec::new();

    if (scan.kind == "people" || scan.target_type == "HUMAN_NAME") && !scan.target.trim().is_empty()
    {
        rows.push(new_row(
            scan,
            &scan.target,
            "scan_target".to_owned(),
            "scan_target",
        ));
    }

    if let Some(results) = results {
        for (index, entity) in results.entities.iter().enumerate() {
            if entity.kind != EntityKind::Person || entity.raw_value.trim().is_empty() {
                continue;
            }
            let mut row = new_row(
                scan,
                &entity.raw_value,
                format!("person_entity:{index}"),
                "person_entity",
            );
            row.entity_uids.push(entity.uid.clone());
            for evidence in &entity.evidence {
                let places = facts(evidence, PLACE_KEYS);
                let dates = facts(evidence, DATE_KEYS);
                push_context(&mut row, &places, &dates);
                row.place_of_birth_claims.extend(places);
                row.date_of_birth_claims.extend(dates);
            }
            rows.push(row);
        }

        for (index, element) in results.elements.iter().enumerate() {
            if element.kind != "HUMAN_NAME" || element.data.trim().is_empty() {
                continue;
            }
            let mut row = new_row(
                scan,
                &element.data,
                format!("human_name_element:{index}"),
                "human_name_element",
            );
            row.flagged_false_positive = element.fp;
            row.element_id = Some(element.id.clone());
            if let Some(uid) = &element.entity {
                row.entity_uids.push(uid.clone());
            }
            rows.push(row);
        }
    }

    for row in &mut rows {
        row.birthplace_status = match distinct_values(&row.place_of_birth_claims) {
            0 => "not_recorded",
            1 => "reported_unverified",
            _ => "conflicting_claims",
        };
    }

    rows
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
        // The store list may substitute an error placeholder for unreadable
        // scan.json. Detect it rather than misreporting complete coverage.
        if let Err(error) = store.get(&scan.id) {
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
        assert_eq!(rows.len(), 2);
        let entity = rows
            .iter()
            .find(|row| row.occurrence_id == "person_entity:0")
            .unwrap();
        assert_eq!(entity.place_of_birth_claims[0].source, "public_registry");
        assert_eq!(
            entity.place_of_birth_claims[0].raw_attribute_value,
            "Dushanbe, Tajikistan"
        );
        assert_eq!(
            entity.historical_context[0].contemporary_place_name,
            "Dushanbe"
        );
        assert!(
            entity.historical_context[0]
                .contemporary_jurisdiction
                .contains("USSR")
        );
        assert!(rows[0].historical_context.is_empty());
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
            raw_attribute_value: "Dushanbe".into(),
            attribute: "pob".into(),
            source: "source_a".into(),
            source_scan_id: None,
            recorded_at_unix: 1,
            merged_provenance: Vec::new(),
            operator_seed: false,
            inferred: false,
        };
        let mut b = a.clone();
        b.value = "Tashkent".into();
        assert_eq!(distinct_values(&[a, b]), 2);
    }
    #[test]
    fn same_name_is_not_a_verified_identity_join() {
        let mut a = Entity::new(EntityKind::Person, "Jane Citizen", 0.5, "0123456789abcdef");
        let mut b = a.clone();
        a.evidence.clear();
        b.evidence.clear();
        a.add_evidence(
            Evidence::new(EvidenceProvenance::new("registry_a"), "first claimant")
                .with_attr("place_of_birth", "Dushanbe")
                .with_attr("date_of_birth", "1988"),
        );
        b.add_evidence(
            Evidence::new(EvidenceProvenance::new("registry_b"), "second claimant")
                .with_attr("place_of_birth", "Tashkent")
                .with_attr("date_of_birth", "1990"),
        );
        let result = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: record().id,
            text: String::new(),
            entities: vec![a, b],
            outcomes: Vec::new(),
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        let rows = people_in_scan(&record(), Some(&result));
        assert_eq!(rows.len(), 3); // target and two separate person occurrences
        assert_eq!(rows[1].place_of_birth_claims[0].value, "Dushanbe");
        assert_eq!(rows[2].place_of_birth_claims[0].value, "Tashkent");
        assert_eq!(rows[1].birthplace_status, "reported_unverified");
        assert_eq!(rows[2].birthplace_status, "reported_unverified");
        assert!(rows[2].historical_context.is_empty());
    }

    #[test]
    fn dates_from_unrelated_evidence_never_become_a_birthplace_fact() {
        let mut person = Entity::new(EntityKind::Person, "Jane Citizen", 0.5, "0123456789abcdef");
        person.add_evidence(
            Evidence::new(EvidenceProvenance::new("registry_a"), "place only")
                .with_attr("birthplace", "Dushanbe"),
        );
        person.add_evidence(
            Evidence::new(EvidenceProvenance::new("registry_b"), "date only")
                .with_attr("date_of_birth", "1988-01-01"),
        );
        let result = ScanResults {
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
        let rows = people_in_scan(&record(), Some(&result));
        assert_eq!(rows[1].historical_context.len(), 1);
        assert_eq!(rows[1].historical_context[0].date_claim, None);
    }

    #[test]
    fn malformed_dates_do_not_claim_a_precise_historical_year() {
        for date in [
            "1900-02-29",
            "2000-02-30",
            "1991-13-01",
            "1991-00-00",
            "1991-09-09junk",
            "1985-02-31",
            "1985-12-00",
            "2026-04-31",
        ] {
            assert!(birth_date(date).is_none(), "{date}");
        }
        assert!(birth_date("2000-02-29").is_some());
        assert!(birth_date("1991-09-09").is_some());
    }
    #[test]
    fn persisted_audit_round_trip_preserves_every_original_byte() {
        use crate::sf_elements::DataElement;
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};

        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hse-person-audit-{}-{stamp}",
            std::process::id()
        ));
        let store = ScanStore::open(&path).unwrap();
        let row = record();
        store.create(&row).unwrap();

        let mut person = Entity::new(EntityKind::Person, "Jane Citizen", 0.7, &row.id);
        person.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("registry_a", &row.id), "claim")
                .with_attr("birth_place", "Dushanbe")
                .with_attr("dob", "1980"),
        );
        let results = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: row.id.clone(),
            text: "original collector data".into(),
            entities: vec![person],
            outcomes: Vec::new(),
            elements: vec![DataElement {
                id: "test-name-element".into(),
                kind: "HUMAN_NAME".into(),
                data: "Jane Citizen".into(),
                source: None,
                module: "test_registry".into(),
                confidence: 80,
                created: 1,
                fp: true,
                entity: None,
                raw: serde_json::Value::Null,
            }],
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        store.save_results(&results).unwrap();

        let row_file = path.join(&row.id).join("scan.json");
        let result_file = path.join(&row.id).join("results.json");
        let before_row = fs::read(&row_file).unwrap();
        let before_results = fs::read(&result_file).unwrap();
        let mut out = Vec::new();
        let summary = audit_all(&store, &mut out).unwrap();
        let lines: Vec<serde_json::Value> = out
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();

        assert_eq!(summary.scans_read, 1);
        assert_eq!(summary.scans_unreadable, 0);
        assert_eq!(summary.person_scan_records, 3);
        assert!(summary.complete_for_retained_scans);
        assert_eq!(lines.len(), 4); // target, entity, element, summary
        assert_eq!(lines[0]["occurrence_id"], "scan_target");
        assert_eq!(lines[1]["occurrence_id"], "person_entity:0");
        assert_eq!(lines[1]["place_of_birth_claims"][0]["source"], "registry_a");
        assert_eq!(lines[2]["occurrence_id"], "human_name_element:0");
        assert_eq!(lines[2]["flagged_false_positive"], true);
        assert_eq!(lines[3]["record_type"], "summary");
        assert_eq!(fs::read(&row_file).unwrap(), before_row);
        assert_eq!(fs::read(&result_file).unwrap(), before_results);
        fs::remove_dir_all(&path).unwrap();
    }

}
