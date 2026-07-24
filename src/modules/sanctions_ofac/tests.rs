use super::*;

use super::crypto::SanctionedAddress;
use super::entity::{ADDRESS_HIT_CONFIDENCE, HIT_CONFIDENCE};
use super::parse::SdnKind;

#[test]
fn accepts_names_organisations_and_crypto_addresses() {
    let m = SanctionsOfac;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Abu Abbas")));
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Banco Nacional de Cuba")));
    // A wallet is screenable because OFAC designates addresses inline in the
    // remarks this module already downloads.
    assert!(m.accepts(&Target::new(
        TargetKind::CryptoAddress,
        "1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
}

#[test]
fn module_metadata() {
    assert_eq!(SanctionsOfac.name(), "sanctions_ofac");
    assert_eq!(SanctionsOfac.priority(), 111);
    assert_eq!(SanctionsOfac.cost(), ModuleCost::Free);
}

#[test]
fn produces_person_organisation_and_crypto_address() {
    let kinds = SanctionsOfac.produces();
    assert!(kinds.contains(&EntityKind::Person));
    assert!(kinds.contains(&EntityKind::Organisation));
    assert!(kinds.contains(&EntityKind::CryptoAddress));
    assert_eq!(kinds.len(), 3);
}

fn individual_record() -> SdnRecord {
    SdnRecord {
        ent_num: 2674,
        name: "ABBAS, Abu".to_string(),
        kind: SdnKind::Individual,
        program: "SDGT".to_string(),
        title: "Director of PALESTINE LIBERATION FRONT".to_string(),
        remarks: "DOB 10 Dec 1948; Director of PALESTINE LIBERATION FRONT.".to_string(),
    }
}

fn organisation_record() -> SdnRecord {
    SdnRecord {
        ent_num: 36,
        name: "AEROCARIBBEAN AIRLINES".to_string(),
        kind: SdnKind::Organisation,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

fn vessel_record() -> SdnRecord {
    SdnRecord {
        ent_num: 4238,
        name: "MAR AZUL".to_string(),
        kind: SdnKind::Vessel,
        program: "CUBA".to_string(),
        title: String::new(),
        remarks: String::new(),
    }
}

/// An individual whose entry designates one Bitcoin wallet — the shape that
/// makes the name path a pivot into `chain_intel`.
fn wallet_record() -> SdnRecord {
    SdnRecord {
        ent_num: 31234,
        name: "IVANOV, Ivan".to_string(),
        kind: SdnKind::Individual,
        program: "CYBER2".to_string(),
        title: String::new(),
        remarks: "DOB 01 Jan 1980; Digital Currency Address - XBT \
                  1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2."
            .to_string(),
    }
}

#[test]
fn individual_hit_emits_person_with_reordered_name_and_caution() {
    let e = build_subject(&individual_record(), "s", Provenance::Name)
        .expect("individual should emit an entity");
    assert_eq!(e.kind, EntityKind::Person);
    assert_eq!(e.value, "Abu Abbas");
    assert!((e.confidence - HIT_CONFIDENCE).abs() < 1e-9);
    assert!(e.has_tag("sanctions") && e.has_tag("ofac") && e.has_tag("regulatory-action"));
    assert!(e.has_tag("needs-identity-verification"));
    let attrs = &e.evidence[0].attributes;
    assert!(attrs.contains_key("caution"));
    assert_eq!(attrs.get("program").map(String::as_str), Some("SDGT"));
    assert_eq!(
        attrs.get("title").map(String::as_str),
        Some("Director of PALESTINE LIBERATION FRONT")
    );
    assert!(
        attrs
            .get("remarks")
            .is_some_and(|r| r.contains("DOB 10 Dec 1948"))
    );
}

#[test]
fn hit_with_blank_title_omits_title_attribute() {
    let e = build_subject(&organisation_record(), "s", Provenance::Name)
        .expect("organisation should emit an entity");
    // organisation_record() has an empty title (the -0- placeholder normalises
    // to "") — the attribute must be absent, not present-and-empty.
    assert!(!e.evidence[0].attributes.contains_key("title"));
}

#[test]
fn organisation_hit_emits_organisation_without_reordering() {
    let e = build_subject(&organisation_record(), "s", Provenance::Name)
        .expect("organisation should emit an entity");
    assert_eq!(e.kind, EntityKind::Organisation);
    assert_eq!(e.value, "AEROCARIBBEAN AIRLINES");
    assert!(e.has_tag("sanctions") && e.has_tag("needs-identity-verification"));
    // No remarks on this record → the attribute is simply absent, not empty-string.
    assert!(!e.evidence[0].attributes.contains_key("remarks"));
}

#[test]
fn vessel_and_aircraft_rows_emit_no_subject() {
    assert!(build_subject(&vessel_record(), "s", Provenance::Name).is_none());
    let mut aircraft = vessel_record();
    aircraft.kind = SdnKind::Aircraft;
    assert!(build_subject(&aircraft, "s", Provenance::Address).is_none());
}

#[test]
fn address_provenance_grades_higher_and_drops_the_identity_hedge() {
    let name_hit = build_subject(&individual_record(), "s", Provenance::Name)
        .expect("individual should emit an entity");
    let addr_hit = build_subject(&individual_record(), "s", Provenance::Address)
        .expect("individual should emit an entity");

    assert!(
        addr_hit.confidence > name_hit.confidence,
        "an exact identifier match must outrank a fuzzy name match"
    );
    assert!((addr_hit.confidence - ADDRESS_HIT_CONFIDENCE).abs() < 1e-9);

    // The hedge exists because NAME matching is fuzzy; it must not survive onto
    // a finding reached by an exact identifier.
    assert!(!addr_hit.has_tag("needs-identity-verification"));
    let attrs = &addr_hit.evidence[0].attributes;
    assert!(!attrs.contains_key("caution"));
    assert!(attrs.contains_key("match_basis"));
    // Everything that is still true regardless of how the row was reached.
    assert!(addr_hit.has_tag("sanctions") && addr_hit.has_tag("ofac"));
    assert_eq!(attrs.get("program").map(String::as_str), Some("SDGT"));
}

#[test]
fn wallet_entity_records_ofacs_symbol_and_hses_inferred_chain_separately() {
    let sa = SanctionedAddress {
        symbol: "XBT".to_string(),
        address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    };
    let e = build_wallet(&wallet_record(), &sa, "s", Provenance::Address);

    assert_eq!(e.kind, EntityKind::CryptoAddress);
    assert_eq!(e.value, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    assert!(e.has_tag("sanctioned-wallet") && e.has_tag("crypto-address"));
    // HSE's shape-based inference, which `chain_intel` keys off…
    assert!(
        e.has_tag("chain:btc"),
        "a valid base58check BTC address must carry the pivot tag: {:?}",
        e.tags
    );
    // …kept distinct from Treasury's own statement of what it designated.
    let attrs = &e.evidence[0].attributes;
    assert_eq!(
        attrs.get("designated_currency").map(String::as_str),
        Some("XBT")
    );
    assert_eq!(
        attrs.get("designated_entity").map(String::as_str),
        Some("Ivan Ivanov"),
        "the wallet must name whose entry designated it, humanised like the subject"
    );
}

#[test]
fn a_wallet_reached_by_a_name_match_inherits_the_name_matchs_weakness() {
    let sa = SanctionedAddress {
        symbol: "XBT".to_string(),
        address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    };
    let pivot = build_wallet(&wallet_record(), &sa, "s", Provenance::Name);
    let direct = build_wallet(&wallet_record(), &sa, "s", Provenance::Address);

    // OFAC certainly designated this wallet either way — but reached via a
    // fuzzy name, its link to the operator's SUBJECT is only as strong as that
    // name match, so it must not be graded as if the operator had pasted it.
    assert!((pivot.confidence - HIT_CONFIDENCE).abs() < 1e-9);
    assert!(pivot.confidence < direct.confidence);
    assert!(pivot.has_tag("needs-identity-verification"));
    assert!(pivot.evidence[0].attributes.contains_key("caution"));
    // Both still assert the designation itself, which is not in doubt.
    assert!(pivot.has_tag("sanctioned-wallet") && direct.has_tag("sanctioned-wallet"));
}

#[test]
fn an_unrecognisable_address_shape_still_emits_the_designation() {
    // A symbol HSE has no classifier for (TRX, USDT, DASH, …) must not cause
    // the sanctions finding to be dropped — the designation is OFAC's, not
    // ours, and only the `chain:` pivot tag depends on our recognising it.
    let sa = SanctionedAddress {
        symbol: "TRX".to_string(),
        address: "TZ4UXDV5ZhNW7fb2AMSbgfAEZ7hWsnYS2g".to_string(),
    };
    let e = build_wallet(&wallet_record(), &sa, "s", Provenance::Address);
    assert_eq!(e.value, "TZ4UXDV5ZhNW7fb2AMSbgfAEZ7hWsnYS2g");
    assert!(e.has_tag("sanctioned-wallet"));
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("designated_currency")
            .map(String::as_str),
        Some("TRX")
    );
    assert!(
        !e.tags.iter().any(|t| t.starts_with("chain:")),
        "no chain tag may be invented for a shape HSE cannot classify: {:?}",
        e.tags
    );
}
