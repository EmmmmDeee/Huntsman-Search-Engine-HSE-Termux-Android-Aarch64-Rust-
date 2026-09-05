use super::{RansomwareLive, SRC, Victim, build_result};
use crate::core::{
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};

fn victim(name: &str, domain: &str, group: &str) -> Victim {
    Victim {
        victim: Some(name.into()),
        group: Some(group.into()),
        domain: Some(domain.into()),
        country: Some("IN".into()),
        activity: Some("Technology".into()),
        attackdate: Some("2026-09-01T13:08:59+00:00".into()),
        discovered: Some("2026-09-02T10:30:50+00:00".into()),
        claim_url: Some(String::new()),
        url: Some("https://www.ransomware.live/id/U2Vhc2lh".into()),
    }
}

#[test]
fn accepts_domain_and_org_only() {
    let m = RansomwareLive;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "acme.com")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
}

#[test]
fn module_name_is_stable() {
    assert_eq!(RansomwareLive.name(), "ransomware_live");
    assert_eq!(RansomwareLive.name(), SRC);
}

#[test]
fn domain_seed_keeps_only_the_matching_victim() {
    let victims = vec![
        victim("Seasia Infotech", "seasiainfotech.com", "thegentlemen"),
        // An unrelated victim only mentioned in a full-text match — must be dropped.
        victim("Other Co", "otherco.example", "lockbit"),
    ];
    let target = Target::new(TargetKind::Domain, "seasiainfotech.com");
    let r = build_result(&victims, &target, "s");

    // Exactly the one matching victim → Organisation + Domain + Url.
    let orgs: Vec<&str> = r
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(orgs, vec!["Seasia Infotech"]);
    assert!(r.entities.iter().all(|e| e.value != "Other Co"));
    assert!(r.entities.iter().all(|e| e.value != "otherco.example"));

    let org = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("victim org emitted");
    assert!(org.has_tag("ransomware-victim"));
    assert!(org.has_tag("group:thegentlemen"));
    assert_eq!(
        org.evidence[0].attributes.get("group").map(String::as_str),
        Some("thegentlemen")
    );
    assert_eq!(
        org.evidence[0].attributes.get("sector").map(String::as_str),
        Some("Technology")
    );

    // A durable reference URL is emitted for corroboration.
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Url && e.has_tag("reference"))
    );
}

#[test]
fn org_seed_matches_by_name_and_pivots_to_domain() {
    let victims = vec![victim(
        "Seasia Infotech",
        "seasiainfotech.com",
        "thegentlemen",
    )];
    let target = Target::new(TargetKind::Organisation, "Seasia Infotech");
    let r = build_result(&victims, &target, "s");
    // The org name matches, and its domain becomes a fresh Domain pivot.
    assert!(
        r.entities
            .iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "seasiainfotech.com")
    );
}

#[test]
fn incidental_description_match_is_dropped() {
    // A victim whose domain/name does NOT match the domain seed is not emitted,
    // even though the upstream full-text search returned it.
    let victims = vec![victim("Unrelated Ltd", "unrelated.example", "akira")];
    let target = Target::new(TargetKind::Domain, "acme.com");
    let r = build_result(&victims, &target, "s");
    assert_eq!(r.entities.len(), 0);
}

#[test]
fn empty_victim_list_yields_no_entities() {
    let target = Target::new(TargetKind::Domain, "acme.com");
    let r = build_result(&[], &target, "s");
    assert_eq!(r.entities.len(), 0);
}
