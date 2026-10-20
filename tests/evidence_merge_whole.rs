//! Two records of one source saying the same thing about one entity merge into one, and the merge
//! keeps every value either record holds exactly as the source gave it. An attribute lists several
//! values joined by `; `, and a value can hold `; ` in its own text (a report comment, a pulse
//! name, a whole raw answer), so a merge never splits, sorts or rejoins a value. These run
//! `Entity::absorb` and `merge_by_uid`, which every lookup, `scan`, the recursion driver,
//! `correlate` and saved-scan loading use to fold entities with one uid. A fold can meet the same
//! records again (each recursion generation folds everything found so far), so each test merges
//! more than once.

use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};

/// One observation of the address, made in `scan` at `at`, holding `attrs` in order.
fn seen(scan: &str, at: u64, attrs: &[(&str, &str)]) -> Entity {
    let mut provenance = EvidenceProvenance::for_scan("abuseipdb", scan);
    provenance.recorded_at_unix = at;
    let evidence = attrs.iter().fold(
        Evidence::new(provenance, "reported"),
        |evidence, (key, value)| evidence.with_attr(*key, *value),
    );
    let mut entity = Entity::new(EntityKind::IpAddress, "45.155.205.233", 0.6, scan);
    entity.add_evidence(evidence);
    entity
}

fn held<'a>(entity: &'a Entity, key: &str) -> Option<&'a str> {
    assert_eq!(entity.evidence.len(), 1, "{:#?}", entity.evidence);
    entity.evidence[0].attributes.get(key).map(String::as_str)
}

#[test]
fn a_value_holding_the_separator_survives_every_merge_byte_for_byte() {
    let first = "Port scan; SSH brute force (22/tcp)";
    let second = "Web app attack; SQL injection on /login";
    let mut entity = seen("scan-1", 100, &[("comment", first)]);
    for _ in 0..3 {
        entity.absorb(seen("scan-2", 200, &[("comment", second)]));
        entity.absorb(seen("scan-1", 100, &[("comment", first)]));
    }
    assert_eq!(
        held(&entity, "comment"),
        Some("Port scan; SSH brute force (22/tcp); Web app attack; SQL injection on /login")
    );
}

#[test]
fn values_keep_the_order_they_were_observed_in() {
    let mut entity = seen("scan-1", 100, &[("port", "8080")]);
    entity.absorb(seen("scan-2", 200, &[("port", "443")]));
    entity.absorb(seen("scan-3", 300, &[("port", "22")]));
    entity.absorb(seen("scan-2", 200, &[("port", "443")]));
    assert_eq!(held(&entity, "port"), Some("8080; 443; 22"));
    assert_eq!(
        entity.evidence[0].attr_values("port").collect::<Vec<_>>(),
        ["8080", "443", "22"]
    );
}

#[test]
fn a_list_a_later_observation_continues_is_one_list() {
    let earlier = [("port", "80"), ("port", "443")];
    let later = [("port", "443"), ("port", "8080")];
    let mut entity = seen("scan-1", 100, &earlier);
    entity.absorb(seen("scan-2", 200, &later));
    entity.absorb(seen("scan-1", 100, &earlier));
    entity.absorb(seen("scan-2", 200, &later));
    assert_eq!(held(&entity, "port"), Some("80; 443; 8080"));
}

#[test]
fn a_record_holds_a_value_holding_the_separator_once() {
    let comment = "Port scan; SSH brute force (22/tcp)";
    let evidence = Evidence::new(EvidenceProvenance::new("abuseipdb"), "reported")
        .with_attr("comment", comment)
        .with_attr("comment", comment);
    assert_eq!(
        evidence.attributes.get("comment").map(String::as_str),
        Some(comment)
    );
}

/// OTX's answer for one address on two days: the pulse names hold `; `, and only the date differs.
const OLDER: &str = r#"{"pulses":[{"name":"Log4Shell; actively exploited","modified":"2022-01-13"},{"name":"Scanner; port 22"}]}"#;
const LATER: &str = r#"{"pulses":[{"name":"Log4Shell; actively exploited","modified":"2026-10-15"},{"name":"Scanner; port 22"}]}"#;

#[test]
fn two_raw_answers_stay_two_whole_documents() {
    let answer = |scan: &str, at: u64, raw: &str| seen(scan, at, &[("raw_answer", raw)]);
    let mut entities = vec![
        answer("scan-1", 100, OLDER),
        answer("scan-2", 200, LATER),
        answer("scan-2", 200, LATER),
        answer("scan-1", 100, OLDER),
        answer("scan-3", 300, LATER),
    ];
    merge_by_uid(&mut entities);
    merge_by_uid(&mut entities);
    assert_eq!(entities.len(), 1, "{entities:#?}");
    let records = &entities[0].evidence;
    let raw = |at: usize| records[at].attributes.get("raw_answer").map(String::as_str);
    assert_eq!(records.len(), 2, "{records:#?}");
    assert_eq!((raw(0), raw(1)), (Some(OLDER), Some(LATER)));
    for document in [raw(0), raw(1)].into_iter().flatten() {
        serde_json::from_str::<serde_json::Value>(document)
            .unwrap_or_else(|e| panic!("{e}: {document}"));
    }
    let scans = |at: usize| {
        std::iter::once(&records[at].provenance)
            .chain(&records[at].merged_provenance)
            .filter_map(|observation| observation.scan_id.as_deref())
            .collect::<Vec<_>>()
    };
    assert_eq!(scans(0), ["scan-1"]);
    assert_eq!(scans(1), ["scan-2", "scan-3"]);
}
