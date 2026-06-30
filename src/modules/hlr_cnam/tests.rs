use super::{CnamResp, HlrCnam, HlrResp, build_cnam_person, build_hlr_entities};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn metadata() {
    let m = HlrCnam;
    assert_eq!(m.name(), "hlr_cnam");
    assert_eq!(m.priority(), 138);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn build_hlr_entities_captures_msisdn_and_network_metadata() {
    let hlr = HlrResp {
        status: Some("connected".into()),
        mcc: Some("505".into()),
        mnc: Some("01".into()),
        original_network_name: Some("Optus".into()),
        current_network_name: Some("Telstra".into()),
        ported: Some(true),
        roaming: Some(false),
        roaming_country_code: None,
        // Provider's canonical international form — differs from the queried
        // local number; previously deserialized and dropped.
        msisdn: Some("+61400000000".into()),
    };
    let entities = build_hlr_entities(&hlr, "0400000000", "scan");
    let phone = entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .expect("phone entity");
    assert_eq!(phone.value, "0400000000");
    assert!(phone.has_tag("hlr-verified") && phone.has_tag("ported"));
    let attr = |k: &str| {
        phone.evidence[0]
            .attributes
            .get(k)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(attr("msisdn"), "+61400000000");
    assert_eq!(attr("hlr_status"), "connected");
    assert_eq!(attr("mcc"), "505");
    assert_eq!(attr("ported_from_carrier"), "Optus");
    // Carrier Organisation pivot.
    let org = entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("carrier org");
    assert_eq!(org.value, "Telstra");
    assert!(org.has_tag("carrier"));
}

#[test]
fn build_cnam_person_preserves_resolved_number() {
    let cnam = CnamResp {
        name: Some("Jane Roe".into()),
        // The number CNAM echoed back — previously deserialized and dropped.
        number: Some("+61400000000".into()),
    };
    let person = build_cnam_person(&cnam, "0400000000", "scan").expect("person");
    assert_eq!(person.kind, EntityKind::Person);
    assert_eq!(person.value, "Jane Roe");
    assert!(person.has_tag("pstn-subscriber"));
    let attr = |k: &str| {
        person.evidence[0]
            .attributes
            .get(k)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(attr("cnam_name"), "Jane Roe");
    assert_eq!(attr("cnam_number"), "+61400000000");
    // No usable name → no entity.
    assert!(build_cnam_person(&CnamResp::default(), "0400000000", "scan").is_none());
}
