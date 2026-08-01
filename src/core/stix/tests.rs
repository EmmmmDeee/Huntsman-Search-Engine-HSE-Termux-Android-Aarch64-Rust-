// Unit tests for the STIX 2.1 bundle export. `include!`d into a `#[cfg(test)]
// module inside `mod.rs`, so `super::*` reaches the private builders/helpers.

use std::collections::HashSet;

use super::*;
use crate::core::correlator::{Correlation, Severity};
use crate::core::entity::{Entity, EntityKind};
use crate::core::relation::{Relation, RelationKind};
use crate::core::scan::{Scan, Target, TargetKind};

/// A fixed Unix instant so every fixture serialises deterministically.
const TS: u64 = 1_700_000_000;

fn scan() -> Scan {
    let mut s = Scan::new("scan-abc", Target::new(TargetKind::Domain, "example.com"));
    s.started_at = TS;
    s
}

fn ent(kind: EntityKind, value: &str) -> Entity {
    let mut e = Entity::new(kind, value, 0.9, "scan-abc");
    e.observed_at = TS;
    e
}

/// All top-level objects of a given STIX `type`.
fn objs_of<'a>(objs: &'a [Value], t: &str) -> Vec<&'a Value> {
    objs.iter()
        .filter(|o| o.get("type").and_then(Value::as_str) == Some(t))
        .collect()
}

#[test]
fn bundle_has_valid_top_level_shape() {
    let out = entities_to_stix(&[ent(EntityKind::Domain, "example.com")], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["type"], "bundle");
    assert!(
        v["id"].as_str().unwrap().starts_with("bundle--"),
        "bundle id prefix"
    );
    let objs = v["objects"].as_array().expect("objects array");
    // Producer identity + the one entity + the framing report.
    assert!(objs.len() >= 3, "producer + entity + report");
    for o in objs {
        assert!(o.get("type").and_then(Value::as_str).is_some(), "every object has a type");
        assert!(o.get("id").and_then(Value::as_str).is_some(), "every object has an id");
    }
}

#[test]
fn producer_identity_and_report_are_present() {
    let out = entities_to_stix(&[ent(EntityKind::Domain, "example.com")], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();

    let producers = objs_of(objs, "identity");
    let hse = producers
        .iter()
        .find(|o| o["name"] == "Huntsman Search Engine")
        .expect("producer identity present");
    assert_eq!(hse["identity_class"], "system");

    let reports = objs_of(objs, "report");
    assert_eq!(reports.len(), 1, "exactly one framing report");
    let report = reports[0];
    assert_eq!(report["x_huntsman_scan_id"], "scan-abc");
    assert!(
        report["name"].as_str().unwrap().contains("scan-abc"),
        "report names the scan"
    );
    assert!(
        !report["object_refs"].as_array().unwrap().is_empty(),
        "report references objects"
    );
}

#[test]
fn native_sco_mappings() {
    let entities = [
        ent(EntityKind::IpAddress, "93.184.216.34"),
        ent(EntityKind::IpAddress, "2001:db8::1"),
        ent(EntityKind::Domain, "example.com"),
        ent(EntityKind::Url, "https://example.com/x"),
        ent(EntityKind::Email, "a@example.com"),
        ent(EntityKind::Username, "alice"),
    ];
    let out = entities_to_stix(&entities, &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();

    assert_eq!(objs_of(objs, "ipv4-addr").len(), 1, "IPv4 → ipv4-addr");
    assert_eq!(objs_of(objs, "ipv6-addr").len(), 1, "IPv6 → ipv6-addr");
    assert_eq!(objs_of(objs, "domain-name").len(), 1);
    assert_eq!(objs_of(objs, "url").len(), 1);
    assert_eq!(objs_of(objs, "email-addr").len(), 1);

    let ua = objs_of(objs, "user-account");
    assert_eq!(ua.len(), 1);
    assert_eq!(ua[0]["account_login"], "alice");
}

#[test]
fn asn_maps_to_autonomous_system_number() {
    let out = entities_to_stix(&[ent(EntityKind::Asn, "AS13335")], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let as_objs = objs_of(objs, "autonomous-system");
    assert_eq!(as_objs.len(), 1);
    assert_eq!(as_objs[0]["number"], 13335, "ASN number is an integer");
}

#[test]
fn person_and_org_map_to_identity() {
    let entities = [
        ent(EntityKind::Person, "Ada Lovelace"),
        ent(EntityKind::Organisation, "ACME Pty Ltd"),
    ];
    let out = entities_to_stix(&entities, &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let ids = objs_of(objs, "identity");
    assert!(ids.iter().any(|o| o["identity_class"] == "individual"));
    assert!(ids.iter().any(|o| o["identity_class"] == "organization"));
}

#[test]
fn coordinates_map_to_location() {
    let out = entities_to_stix(&[ent(EntityKind::Coordinates, "-27.47,153.02")], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let locs = objs_of(objs, "location");
    assert_eq!(locs.len(), 1);
    assert_eq!(locs[0]["latitude"], -27.47);
    assert_eq!(locs[0]["longitude"], 153.02);
}

#[test]
fn unmapped_kind_becomes_custom_artifact() {
    let out = entities_to_stix(&[ent(EntityKind::Phone, "+61400000000")], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let arts = objs_of(objs, "x-huntsman-artifact");
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0]["x_huntsman_kind"], "phone");
    assert!(
        arts[0]["x_huntsman_value"].as_str().is_some(),
        "artifact preserves the value"
    );
}

#[test]
fn typed_relation_becomes_relationship_sro() {
    let dom = ent(EntityKind::Domain, "example.com");
    let ip = ent(EntityKind::IpAddress, "93.184.216.34");
    let rel = Relation::new(
        dom.uid.clone(),
        ip.uid.clone(),
        RelationKind::ResolvesTo,
        0.8,
        "scan-abc",
    );
    let out = entities_to_stix(&[dom, ip], &[rel], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let sros = objs_of(objs, "relationship");
    assert_eq!(sros.len(), 1);
    assert_eq!(sros[0]["relationship_type"], "resolves-to");
    assert_eq!(sros[0]["x_huntsman_relation_kind"], "resolves_to");
}

#[test]
fn relationship_dropped_when_an_endpoint_is_absent() {
    let dom = ent(EntityKind::Domain, "example.com");
    // Edge to a uid that is NOT among the exported entities.
    let rel = Relation::new(
        dom.uid.clone(),
        "deadbeef-not-in-set",
        RelationKind::ResolvesTo,
        0.8,
        "scan-abc",
    );
    let out = entities_to_stix(&[dom], &[rel], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    assert!(
        objs_of(objs, "relationship").is_empty(),
        "a dangling edge must not be emitted"
    );
}

#[test]
fn correlation_becomes_a_note() {
    let dom = ent(EntityKind::Domain, "example.com");
    let ip = ent(EntityKind::IpAddress, "93.184.216.34");
    let corr = Correlation {
        rule_id: "AU-001".to_string(),
        rule_name: "Test rule".to_string(),
        severity: Severity::High,
        description: "a corroborated finding".to_string(),
        entity_uids: vec![dom.uid.clone(), ip.uid.clone()],
        scan_id: "scan-abc".to_string(),
        ts: TS,
        rank: 2.5,
    };
    let out = entities_to_stix(&[dom, ip], &[], &[corr], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let notes = objs_of(objs, "note");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["x_huntsman_rule_id"], "AU-001");
    assert_eq!(notes[0]["content"], "a corroborated finding");
    assert_eq!(
        notes[0]["object_refs"].as_array().unwrap().len(),
        2,
        "note references both child objects"
    );
}

#[test]
fn correlation_with_no_surviving_children_is_skipped() {
    // The correlation references a uid absent from the exported entity set.
    let dom = ent(EntityKind::Domain, "example.com");
    let corr = Correlation {
        rule_id: "AU-999".to_string(),
        rule_name: "Orphan".to_string(),
        severity: Severity::Low,
        description: "no children present".to_string(),
        entity_uids: vec!["missing-uid".to_string()],
        scan_id: "scan-abc".to_string(),
        ts: TS,
        rank: 0.0,
    };
    let out = entities_to_stix(&[dom], &[], &[corr], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    assert!(objs_of(objs, "note").is_empty(), "empty-ref note is skipped");
}

#[test]
fn all_references_resolve_to_bundle_objects() {
    // Referential integrity: every source_ref/target_ref and every object_refs
    // entry must name an object that exists in the bundle.
    let dom = ent(EntityKind::Domain, "example.com");
    let ip = ent(EntityKind::IpAddress, "93.184.216.34");
    let person = ent(EntityKind::Person, "Ada Lovelace");
    let rel = Relation::new(
        dom.uid.clone(),
        ip.uid.clone(),
        RelationKind::ResolvesTo,
        0.8,
        "scan-abc",
    );
    let corr = Correlation {
        rule_id: "AU-001".to_string(),
        rule_name: "Test".to_string(),
        severity: Severity::Medium,
        description: "d".to_string(),
        entity_uids: vec![dom.uid.clone(), person.uid.clone()],
        scan_id: "scan-abc".to_string(),
        ts: TS,
        rank: 1.0,
    };
    let out = entities_to_stix(&[dom, ip, person], &[rel], &[corr], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();

    let ids: HashSet<&str> = objs
        .iter()
        .filter_map(|o| o.get("id").and_then(Value::as_str))
        .collect();

    for o in objs {
        for key in ["source_ref", "target_ref", "created_by_ref"] {
            if let Some(r) = o.get(key).and_then(Value::as_str) {
                assert!(ids.contains(r), "{key} {r} must resolve");
            }
        }
        if let Some(refs) = o.get("object_refs").and_then(Value::as_array) {
            for r in refs {
                let rid = r.as_str().unwrap();
                assert!(ids.contains(rid), "object_ref {rid} must resolve");
            }
        }
    }
}

#[test]
fn export_is_byte_deterministic() {
    let entities = [
        ent(EntityKind::Domain, "example.com"),
        ent(EntityKind::IpAddress, "93.184.216.34"),
        ent(EntityKind::Person, "Ada Lovelace"),
    ];
    let a = entities_to_stix(&entities, &[], &[], &scan());
    let b = entities_to_stix(&entities, &[], &[], &scan());
    assert_eq!(a, b, "no wall clock, no random ids ⇒ identical output");
}

#[test]
fn attack_technique_tags_surface_as_custom_property() {
    let mut e = ent(EntityKind::Domain, "example.com");
    e.tag("attack:T1596.002");
    e.tag("attack:T1590.001");
    let out = entities_to_stix(&[e], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).unwrap();
    let objs = v["objects"].as_array().unwrap();
    let dom = objs_of(objs, "domain-name");
    let attack = dom[0]["x_huntsman_attack"].as_array().unwrap();
    // Sorted + de-duplicated.
    assert_eq!(attack[0], "T1590.001");
    assert_eq!(attack[1], "T1596.002");
}

#[test]
fn empty_scan_still_yields_a_valid_bundle() {
    let out = entities_to_stix(&[], &[], &[], &scan());
    let v: Value = serde_json::from_str(&out).expect("valid JSON");
    let objs = v["objects"].as_array().unwrap();
    // Producer identity + report, both always present.
    assert_eq!(objs_of(objs, "identity").len(), 1);
    assert_eq!(objs_of(objs, "report").len(), 1);
}

#[test]
fn det_uuid_is_stable_and_well_formed() {
    let u = det_uuid("seed-x");
    assert_eq!(u, det_uuid("seed-x"), "deterministic");
    assert_ne!(u, det_uuid("seed-y"), "distinct seeds differ");
    let lens: Vec<usize> = u.split('-').map(str::len).collect();
    assert_eq!(lens, vec![8, 4, 4, 4, 12], "8-4-4-4-12 UUID shape");
    let compact: String = u.chars().filter(|c| *c != '-').collect();
    assert!(compact.chars().all(|c| c.is_ascii_hexdigit()), "hex only");
    assert_eq!(compact.chars().nth(12), Some('5'), "version 5 nibble");
    assert_eq!(compact.chars().nth(16), Some('8'), "RFC 4122 variant nibble");
}

#[test]
fn parse_asn_variants() {
    assert_eq!(parse_asn("AS13335"), Some(13335));
    assert_eq!(parse_asn("as65000"), Some(65000));
    assert_eq!(parse_asn("13335"), Some(13335));
    assert_eq!(parse_asn("not-an-asn"), None);
}

#[test]
fn parse_coords_validates_ranges() {
    assert_eq!(parse_coords("-27.47,153.02"), Some((-27.47, 153.02)));
    assert_eq!(parse_coords("0,0"), Some((0.0, 0.0)));
    assert_eq!(parse_coords("91.0,0.0"), None, "latitude out of range");
    assert_eq!(parse_coords("0.0,181.0"), None, "longitude out of range");
    assert_eq!(parse_coords("nonsense"), None);
}
