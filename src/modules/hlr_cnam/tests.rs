use super::{
    CnamResp, HlrCnam, HlrResp, build_cnam_person, build_hlr_entities, cnam_pool_service,
    hlr_pool_service,
};
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

#[test]
fn build_cnam_person_rejects_carrier_placeholders() {
    let mk = |name: &str, number: &str| {
        build_cnam_person(
            &CnamResp {
                name: Some(name.into()),
                number: None,
            },
            number,
            "scan",
        )
    };
    // OpenCNAM's placeholder returns for unmatched / prepaid / VoIP numbers must
    // never become a fabricated Person (they recur verbatim → false-merge risk).
    for placeholder in [
        "WIRELESS CALLER",
        "Unavailable",
        "TOLL FREE",
        "UNKNOWN",
        "CELL PHONE",
        "Private",
        "V1234567",
    ] {
        assert!(
            mk(placeholder, "0400000000").is_none(),
            "{placeholder} must be rejected as a carrier placeholder"
        );
    }
    // The queried number echoed back as the "name" is not an identity.
    assert!(mk("0400000000", "0400000000").is_none());
    assert!(mk("+61 400 000 000", "0400000000").is_none());
    // A real subscriber name still resolves.
    assert!(mk("Jane Roe", "0400000000").is_some());
}

// ── Key-pool attribution for the two stages ─────────────────────────────────
//
// This module holds TWO independent keys. Stage 2 used to absorb 401/403/429
// silently, so a dead OpenCNAM key was never reported to any pool and the scan
// recorded "this number has no CNAM subscriber name" instead. Routing it through
// `keyed_ok_or_404` fixes that, but only if each stage names its own pool.
//
// Scope, stated honestly: this pins the two RESOLVERS, not the call sites. It
// would still pass if a call site handed `hlr_pool_service()` the CNAM key —
// that pairing is established by reading `process`, not by this test. What it
// does catch is the two names collapsing into one, which is what a lost or
// renamed service definition would do.
#[test]
fn the_two_key_pools_resolve_to_distinct_real_services() {
    assert_eq!(hlr_pool_service(), "hlrlookups");
    assert_eq!(cnam_pool_service(), "opencnam");
    assert_ne!(
        hlr_pool_service(),
        cnam_pool_service(),
        "the two stages must never burn each other's key"
    );
}

// Neither pool name may silently fall back to the module name: `super::SRC` is
// the `map_or` fallback in both helpers, so a missing or renamed service
// definition would quietly attribute key failures to a pool that holds no keys,
// and the dead key would never rotate. This is the failure mode the resolver
// test above cannot see on its own.
#[test]
fn neither_pool_falls_back_to_the_module_name() {
    assert_ne!(hlr_pool_service(), super::SRC);
    assert_ne!(cnam_pool_service(), super::SRC);
}
