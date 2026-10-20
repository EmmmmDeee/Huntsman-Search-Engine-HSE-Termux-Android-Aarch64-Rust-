//! Two records of one source saying the same thing about one entity merge into one, and the merge
//! keeps every value either record holds exactly as the source gave it. An attribute lists several
//! values joined by `; `, and a value can hold `; ` in its own text (a report comment, a pulse
//! name, a page title), so a merge never splits, sorts or rejoins a value, and it keeps the values
//! in the order they were observed. These run `Entity::absorb`, which `merge_by_uid` uses for every
//! lookup, `scan`, the recursion driver, `correlate` and saved-scan loading. A fold can meet the
//! same records again (each recursion generation folds everything found so far), so each test
//! merges more than once.
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

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
