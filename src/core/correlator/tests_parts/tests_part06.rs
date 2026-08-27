/// AU-092's agreement branch must cite only the entities that named the
/// AGREEING state — an entity naming some OTHER, unrelated state on either
/// side must not be swept into `entity_uids` as if it corroborated this
/// specific finding. Mirrors AU-098's consensus-only uid scoping
/// (`rule_au_098_residency_consensus`'s "Contributing entity uids" comment).
#[test]
fn au092_agreement_cites_only_the_agreeing_states_entities_not_every_named_state() {
    // Breach side names BOTH QLD (agrees with footprint) and NSW (unrelated,
    // e.g. a stale prior address on a different breach row) — a DISTINCT
    // entity from `p` so the two sides' uids can't coincidentally collapse.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("state", "QLD"));
    let mut stray = Entity::new(EntityKind::Email, "stale-record@example.com", 0.9, "s2");
    stray.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "NSW"));
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s"); // Brisbane, QLD
    coord.add_evidence(Evidence::new("geocode", "geocoded subject fix"));

    let r = super::rules::rule_au_092_breach_locality_footprint_crosscheck(
        &RuleContext::new(&[p.clone(), stray.clone(), coord.clone()]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].rule_name.contains("corroborated"));
    assert!(
        r[0].entity_uids.contains(&p.uid),
        "the QLD breach entity DID name the agreeing state and must be cited"
    );
    assert!(
        r[0].entity_uids.contains(&coord.uid),
        "the QLD footprint entity DID name the agreeing state and must be cited"
    );
    assert!(
        !r[0].entity_uids.contains(&stray.uid),
        "the NSW breach entity named an UNRELATED state and must not be cited as evidence for the QLD agreement: {:?}",
        r[0].entity_uids
    );
}

#[test]
fn au092_requires_both_sides() {
    // Only a breach field, no footprint → nothing.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "QLD"));
    assert!(
        super::rules::rule_au_092_breach_locality_footprint_crosscheck(
            &RuleContext::new(&[p.clone()]),
            "s",
            0
        )
        .is_empty()
    );
    // Only a footprint, no breach field → nothing.
    let coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.6, "s");
    assert!(
        super::rules::rule_au_092_breach_locality_footprint_crosscheck(
            &RuleContext::new(&[coord]),
            "s",
            0
        )
        .is_empty()
    );
}

#[test]
fn au093_full_street_address_is_high_and_geocoded() {
    // Street + suburb + state + postcode in ONE record → dwelling-grade address.
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("street", "12 Smith St")
            .with_attr("suburb", "Maleny")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4552"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-093");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].rule_name.contains("residential address"));
    assert!(r[0].description.contains("12 Smith St"));
    assert!(r[0].description.contains("Maleny"));
    assert!(r[0].description.contains("QLD 4552"));
    assert!(
        r[0].description.contains("offline"),
        "postcode 4552 geocodes offline"
    );
}

#[test]
fn au093_does_not_assemble_an_address_from_an_accumulated_multi_value_record() {
    // Regression: `Evidence::with_attr`'s "a; b" accumulation (the same
    // mechanism `Entity::absorb`'s `merge_evidence_attrs` uses when two
    // breach rows sharing one (source, summary) — e.g. SeeKnow's per-dbname
    // summary — fold into one evidence record) can leave a single record's
    // "suburb"/"state" attribute holding TWO DIFFERENT real suburbs/states
    // from two different underlying rows. `merge_evidence_attrs` re-sorts
    // each key's accumulated values independently (a BTreeSet collapse), so
    // there is no reliable correspondence between which suburb goes with
    // which state even when both have the same count — record_attr must
    // refuse to assemble from an ambiguous record rather than guess a
    // (possibly wrong, possibly geographically-impossible) pairing.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("suburb", "Bondi Beach")
            .with_attr("suburb", "Richmond")
            .with_attr("state", "NSW")
            .with_attr("state", "VIC"),
    );
    assert!(
        super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0)
            .is_empty(),
        "an ambiguous accumulated suburb/state record must not assemble a fabricated address"
    );
}

#[test]
fn au093_geocode_reverse_geocode_is_not_labeled_breach() {
    // The proven defect, generalised: a reverse-geocode record carries the same
    // suburb/state/postcode attributes as a leaked address, but `geocode` is not
    // a breach source — it must NOT be assembled and reported as a dwelling.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(
        Evidence::new("geocode", "reverse geocode")
            .with_attr("suburb", "Darwin")
            .with_attr("state", "NT")
            .with_attr("postcode", "0800"),
    );
    assert!(
        super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0)
            .is_empty(),
        "a geocoded suburb must never be reported as a breach-sourced address"
    );
}

#[test]
fn au093_registry_enricher_is_not_labeled_breach() {
    // A non-geo enricher (electoral roll) also stamps suburb/state/postcode but
    // is not a leaked breach record — the same gate excludes it.
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(
        Evidence::new("au_electoral", "electoral roll")
            .with_attr("suburb", "Darwin")
            .with_attr("state", "NT")
            .with_attr("postcode", "0800"),
    );
    assert!(
        super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0)
            .is_empty(),
        "a registry-enricher locality is not a breach-sourced address"
    );
}

#[test]
fn au093_mixed_breach_and_geocode_counts_only_the_breach_source() {
    // The SAME address on a real breach record AND a geocode record → exactly one
    // finding, counting only the breach source (geocode excluded, not deduped).
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("suburb", "Brisbane")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4000"),
    );
    p.add_evidence(
        Evidence::new("geocode", "reverse geocode")
            .with_attr("suburb", "Brisbane")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4000"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(
        r[0].description.contains("1 breach record source"),
        "geocode must be excluded from the count: {}",
        r[0].description
    );
    assert!(r[0].description.contains("oathnet_pro"));
    assert!(
        !r[0].description.contains("geocode"),
        "geocode must not be named as a breach source: {}",
        r[0].description
    );
}

#[test]
fn au090_geocode_state_is_not_a_breach_record() {
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("geocode", "reverse geocode").with_attr("state", "NT"));
    assert!(
        super::rules::rule_au_090_au_jurisdiction(&RuleContext::new(&[p]), "s", 0).is_empty(),
        "a geocoded state is not a breach-record jurisdiction"
    );
}

#[test]
fn au091_geocode_postcode_is_not_a_breach_record() {
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("geocode", "reverse geocode").with_attr("postcode", "0800"));
    assert!(
        super::rules::rule_au_091_au_postcode_locality(&RuleContext::new(&[p]), "s", 0).is_empty(),
        "a geocoded postcode is not a breach-record locality"
    );
}

#[test]
fn au093_suburb_only_is_medium_with_postcode_derived_state() {
    // No street; suburb + postcode (state derived from the postcode).
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("city", "Brisbane")
            .with_attr("postcode", "4000"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].rule_name.contains("suburb"));
    assert!(r[0].description.contains("Brisbane"));
    assert!(r[0].description.contains("QLD 4000"));
}

#[test]
fn au093_requires_suburb_plus_state_or_postcode() {
    // A suburb with no state/postcode anywhere in the record → nothing (that is
    // AU-090/091 territory, not an assembled locality).
    let mut p = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    p.add_evidence(Evidence::new("see_know", "breach").with_attr("suburb", "Maleny"));
    assert!(
        super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0)
            .is_empty()
    );
    // A state with no suburb → nothing (AU-090 already covers a bare state).
    let mut q = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    q.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "QLD"));
    assert!(
        super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[q]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au093_dedups_same_address_across_sources() {
    // Two sources naming the same dwelling collapse to one finding (2 sources).
    let mut p = Entity::new(EntityKind::Person, "Cindy Haynes", 0.9, "s");
    p.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("street", "12 Smith St")
            .with_attr("suburb", "Maleny")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4552"),
    );
    p.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("street", "12 Smith St")
            .with_attr("suburb", "Maleny")
            .with_attr("state", "QLD")
            .with_attr("postcode", "4552"),
    );
    let r = super::rules::rule_au_093_au_address_from_breach(&RuleContext::new(&[p]), "s", 0);
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("2 breach record source"));
}

#[test]
fn au098_three_classes_agree_is_high_consensus() {
    // Brisbane coordinate (QLD) + a QLD address + a breach state=QLD → 3 classes.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let mut person = Entity::new(EntityKind::Person, "Jo Citizen", 0.9, "s");
    person.add_evidence(Evidence::new("see_know", "breach").with_attr("state", "Queensland"));
    let r = super::rules::rule_au_098_residency_consensus(
        &RuleContext::new(&[coord, addr, person]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-098");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("3 of 3"));
    assert!(r[0].description.contains("no dissenting signal"));
    // The Brisbane coordinate sharpens the state verdict to a locality.
    assert!(
        r[0].description.contains("near Brisbane"),
        "consensus sharpened to locality: {}",
        r[0].description
    );
}

#[test]
fn au098_two_classes_medium_and_surfaces_dissent() {
    // A QLD coordinate + a QLD phone (07) agree; a lone VIC address dissents.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.7, "s"); // 07 → QLD
    let addr = Entity::new(EntityKind::Address, "Melbourne VIC 3000", 0.7, "s");
    let r = super::rules::rule_au_098_residency_consensus(
        &RuleContext::new(&[coord, phone, addr]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    // QLD is supported by 2 classes (coordinate + phone) → Medium; the lone VIC
    // address is the dissenting minority.
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("2 of 3"));
    assert!(r[0].description.contains("QLD"));
    assert!(r[0].description.contains("dissenting minority: VIC"));
}

#[test]
fn au098_single_class_does_not_fire() {
    // Only a coordinate — one class — is the single-signal rules' job, not AU-098.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored: a real 1-class case
    assert!(
        super::rules::rule_au_098_residency_consensus(&RuleContext::new(&[coord]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au098_appends_australian_isp_network_corroboration() {
    // Coordinate + address agree on QLD (2 classes); an IP on Telstra adds a
    // domestic-connection corroboration to the verdict.
    let mut coord = Entity::new(EntityKind::Coordinates, "-27.4705,153.0260", 0.7, "s");
    coord.add_evidence(Evidence::new("exif_geo", "photo GPS")); // person-anchored, not infra
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let mut ip = Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.8, "s");
    ip.add_evidence(Evidence::new("ip_geo", "geo").with_attr("isp", "Telstra"));
    let r = super::rules::rule_au_098_residency_consensus(
        &RuleContext::new(&[coord, addr, ip]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert!(r[0].description.contains("QLD"));
    assert!(
        r[0].description.contains("Australian ISP (Telstra)"),
        "network corroboration appended: {}",
        r[0].description
    );
}

#[test]
fn au101_five_identity_facets_is_high_resolution() {
    // Name + email + phone + username + address → 5 distinct facet classes.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.8, "s");
    let user = Entity::new(EntityKind::Username, "haigenb", 0.8, "s");
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let r = super::rules::rule_au_101_identity_resolution(
        &RuleContext::new(&[person, email, phone, user, addr]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-101");
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("5 independent identity facets"));
    assert!(r[0].description.contains("legal name"));
    assert!(r[0].description.contains("physical address"));
}

#[test]
fn au101_four_facets_is_medium_resolution() {
    // Exactly four facet classes → Medium (n == 4).
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.8, "s");
    let user = Entity::new(EntityKind::Username, "haigenb", 0.8, "s");
    let r = super::rules::rule_au_101_identity_resolution(
        &RuleContext::new(&[person, email, phone, user]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("4 independent identity facets"));
}

#[test]
fn au101_counts_phone_and_email_facets_from_breach_evidence_attributes() {
    // A breach record carries the subject's phone + DOB as evidence ATTRIBUTES (no
    // standalone Phone entity). With the legal name and a physical address that is
    // four resolved facets — but the phone facet only counts via the new
    // evidence-attribute path; without it the footprint stays at 3 and is silent.
    let mut person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person.add_evidence(
        Evidence::new("oathnet", "breach")
            .with_attr("phone", "+61 7 3123 4567")
            .with_attr("date_of_birth", "1990-01-01"),
    );
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let r = super::rules::rule_au_101_identity_resolution(
        &RuleContext::new(&[person, addr.clone()]),
        "s",
        0,
    );
    assert_eq!(
        r.len(),
        1,
        "name + address + DOB-attr + phone-attr = 4 facets must fire"
    );
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("phone"));

    // Control: WITHOUT the phone attribute only 3 facets (name, address, DOB) →
    // below the n>=4 floor → silent, proving the phone facet is what tips it over.
    let mut person_no_phone = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person_no_phone
        .add_evidence(Evidence::new("oathnet", "breach").with_attr("date_of_birth", "1990-01-01"));
    assert!(
        super::rules::rule_au_101_identity_resolution(
            &RuleContext::new(&[person_no_phone, addr]),
            "s",
            0
        )
        .is_empty(),
        "without the phone facet the footprint is only 3 facets"
    );
}

#[test]
fn au101_does_not_count_a_name_intel_permutation_as_a_breach_facet() {
    // Every OTHER attribute-based facet scan in this file (AU-073/074/075/090/
    // 091/092/104/105) gates on is_breach_source immediately after
    // scan_evidence; AU-101's four attribute loops (DOB, government ID, phone,
    // email) never did. `name_intel` is a listed ENRICHMENT_ONLY_SOURCE -- a
    // deterministic name-permutation guess, not an independent observation --
    // exactly the source is_breach_source exists to exclude. Person + Address
    // + Username is 3 facets (below the n>=4 floor, silent); a name_intel
    // guessed email attribute must not tip it to a fabricated 4th facet.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    let mut user = Entity::new(EntityKind::Username, "hbamford", 0.7, "s");
    user.add_evidence(
        Evidence::new("name_intel", "permuted guess")
            .with_attr("email", "haigen.bamford@gmail.com"),
    );
    let r = super::rules::rule_au_101_identity_resolution(
        &RuleContext::new(&[person, addr, user]),
        "s",
        0,
    );
    assert!(
        r.is_empty(),
        "a name_intel-guessed email attribute must not fabricate a 4th identity facet: {r:?}"
    );
}

#[test]
fn au101_thin_footprint_and_low_confidence_do_not_fire() {
    // Three facets is below the threshold — the single-facet rules' job.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    let phone = Entity::new(EntityKind::Phone, "+61731234567", 0.8, "s");
    // A low-confidence Person and Address are not counted as resolved facets, so
    // adding them does not push a 3-facet footprint over the line.
    let weak_name = Entity::new(EntityKind::Person, "J Bloggs", 0.30, "s");
    let weak_addr = Entity::new(EntityKind::Address, "somewhere", 0.30, "s");
    assert!(
        super::rules::rule_au_101_identity_resolution(
            &RuleContext::new(&[person, email, phone, weak_name, weak_addr]),
            "s",
            0
        )
        .is_empty()
    );
}

#[test]
fn au101_breach_dob_and_gov_id_count_as_facets() {
    // Name + email are two entity facets; a breach DOB field and a checksum-valid
    // TFN add the "date of birth" and "government ID" facets → 4 classes, Medium.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let mut email = Entity::new(EntityKind::Email, "h@example.com", 0.8, "s");
    email.add_evidence(
        Evidence::new("oathnet_pro", "breach")
            .with_attr("date_of_birth", "1990-04-12")
            .with_attr("tfn", "123456782"), // checksum-valid TFN
    );
    let r =
        super::rules::rule_au_101_identity_resolution(&RuleContext::new(&[person, email]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("date of birth"));
    assert!(r[0].description.contains("government ID"));
}

#[test]
fn au101_ignores_non_breach_sourced_dob_gov_id_phone_and_email_attributes() {
    // AU-101 duplicated AU-073/AU-074's DOB/gov-ID key vocabularies (plus its own
    // phone/email attribute scan) but, unlike those two rules, never gated on
    // `is_breach_source` — so a public, non-breach source emitting the identical
    // attribute keys silently inflated the facet count. Name + address is 2 real
    // facets; a non-breach DOB + checksum-valid TFN + valid phone + valid email
    // must not add 4 more — the total must stay at 2, below the n>=4 firing floor.
    let person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    let mut addr = Entity::new(EntityKind::Address, "Spring Hill QLD 4000", 0.7, "s");
    addr.add_evidence(
        Evidence::new("search_engines", "public record")
            .with_attr("date_of_birth", "1990-01-01")
            .with_attr("tfn", "123456782") // checksum-valid TFN
            .with_attr("phone", "+61 7 3123 4567")
            .with_attr("email", "namesake@example.com"),
    );
    assert!(
        super::rules::rule_au_101_identity_resolution(&RuleContext::new(&[person, addr]), "s", 0)
            .is_empty(),
        "a non-breach source's DOB/gov-ID/phone/email attributes must not count as resolved facets"
    );
}

// ─── AU-104 tests (Australian bank account / institution exposure) ────────────

#[test]
fn au104_resolves_bsb_to_institution_medium() {
    // A CBA BSB in a breach record, no account number → Medium attribution.
    let mut person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person.add_evidence(Evidence::new("oathnet_pro", "breach").with_attr("bsb", "062-000"));
    let r = super::rules::rule_au_104_bank_account_exposure(&RuleContext::new(&[person]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].rule_id, "AU-104");
    assert_eq!(r[0].severity, super::Severity::Medium);
    assert!(r[0].description.contains("Commonwealth Bank"));
    assert!(r[0].description.contains("BSB only"));
}

#[test]
fn au104_escalates_to_high_when_account_number_co_occurs() {
    // BSB + account number = a full, directly-abusable account credential → High.
    let mut person = Entity::new(EntityKind::Person, "Haigen Bamford", 0.9, "s");
    person.add_evidence(
        Evidence::new("stealer_log", "stealer")
            .with_attr("bank_state_branch", "012003") // ANZ
            .with_attr("account_number", "123456789"),
    );
    let r = super::rules::rule_au_104_bank_account_exposure(&RuleContext::new(&[person]), "s", 0);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].severity, super::Severity::High);
    assert!(r[0].description.contains("ANZ"));
    assert!(r[0].description.contains("account number"));
}

#[test]
fn au104_silent_for_unresolvable_or_absent_bsb() {
    // An unallocated BSB resolves to no bank → no (potentially wrong) finding.
    let mut p1 = Entity::new(EntityKind::Person, "X", 0.9, "s");
    p1.add_evidence(Evidence::new("src", "breach").with_attr("bsb", "999-999"));
    assert!(
        super::rules::rule_au_104_bank_account_exposure(&RuleContext::new(&[p1]), "s", 0)
            .is_empty()
    );
    // No BSB field at all → nothing fires.
    let p2 = Entity::new(EntityKind::Person, "Y", 0.9, "s");
    assert!(
        super::rules::rule_au_104_bank_account_exposure(&RuleContext::new(&[p2]), "s", 0)
            .is_empty()
    );
}

#[test]
fn au105_flags_plaintext_password_reused_across_breaches() {
    // The same plaintext password across three distinct breaches → High, and the
    // finding NEVER echoes the secret.
    let mut email = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    for db in ["pemiblanc.com", "gamigo.com", "2844databases"] {
        email.add_evidence(
            Evidence::new("see_know", "breach")
                .with_attr("dbname", db)
                .with_attr("password", "mnimp316895007"),
        );
    }
    let r = super::rules::rule_au_105_credential_reuse(&RuleContext::new(&[email]), "s", 0);
    assert_eq!(r.len(), 1, "one reuse finding");
    assert_eq!(r[0].rule_id, "AU-105");
    assert_eq!(r[0].severity, Severity::High, "plaintext reuse is High");
    assert!(r[0].description.contains("3 distinct breaches"));
    assert!(
        !r[0].description.contains("mnimp316895007"),
        "the secret value must never be echoed"
    );
}

#[test]
fn au105_reads_the_see_know_source_db_breach_name() {
    // SeekNow (`see_know`) records carry the breach DB name in a raw `source`
    // field, which the extractor renames to `source_db` (so it can't clobber the
    // provenance `source` attr). Before the fix, `breach_of` read only `dbname`/
    // `breach`, so every SeekNow breach collapsed to the bare module name
    // "see_know": a genuine cross-breach password reuse counted as ONE breach and
    // AU-105 stayed silent. Reading `source_db` recovers the two distinct breaches.
    let mut email = Entity::new(EntityKind::Email, "j@x.com", 0.9, "s");
    for db in ["linkedin.com", "adobe.com"] {
        email.add_evidence(
            Evidence::new("see_know", "SeekNow record")
                .with_attr("source_db", db)
                .with_attr("password", "reused-pw-9931"),
        );
    }
    let r = super::rules::rule_au_105_credential_reuse(&RuleContext::new(&[email]), "s", 0);
    assert_eq!(r.len(), 1, "cross-breach reuse via source_db must fire");
    assert_eq!(r[0].rule_id, "AU-105");
    assert_eq!(r[0].severity, Severity::High, "plaintext reuse is High");
    assert!(r[0].description.contains("2 distinct breaches"));
    assert!(
        r[0].description.contains("linkedin.com") && r[0].description.contains("adobe.com"),
        "both recovered breach names must appear: {}",
        r[0].description
    );
}

#[test]
fn au105_groups_a_hash_case_insensitively_across_sources() {
    // The same hash dumped UPPER-case by one source and lower-case by another is
    // ONE reused secret (Medium) — case must not split it.
    let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
    a.add_evidence(
        Evidence::new("snusbase", "breach")
            .with_attr("dbname", "teg.com.au")
            .with_attr("password_hash", "00346D91DD87"),
    );
    let mut b = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
    b.add_evidence(
        Evidence::new("oathnet", "breach")
            .with_attr("dbname", "ticketek.com.au")
            .with_attr("password_hash", "00346d91dd87"),
    );
    let r = super::rules::rule_au_105_credential_reuse(&RuleContext::new(&[a, b]), "s", 0);
    assert_eq!(r.len(), 1, "case variants of one hash = one reuse");
    assert_eq!(r[0].severity, Severity::Medium, "hash reuse is Medium");
}

#[test]
fn au105_does_not_link_on_a_common_password_hash_collision() {
    // A hash whose plaintext is a COMMON password (here md5("password")) recurs
    // for countless unrelated people, so sharing it across breaches is a
    // collision, NOT a reuse link — AU-105 must not fire. A genuinely unique hash
    // of the same length still does, proving the gate keys on the collision, not
    // the shape.
    let common = "5f4dcc3b5aa765d61d8327deb882cf99"; // md5("password")
    let uniq = "00112233445566778899aabbccddeeff"; // not a common-password digest
    let mk = |db: &str, hash: &str| {
        let mut e = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
        e.add_evidence(
            Evidence::new("breach", "rec")
                .with_attr("dbname", db)
                .with_attr("password_hash", hash),
        );
        e
    };
    assert!(
        super::rules::rule_au_105_credential_reuse(
            &RuleContext::new(&[mk("db1", common), mk("db2", common)]),
            "s",
            0
        )
        .is_empty(),
        "a common-password hash is a collision, not a reuse link"
    );
    let r = super::rules::rule_au_105_credential_reuse(
        &RuleContext::new(&[mk("db1", uniq), mk("db2", uniq)]),
        "s",
        0,
    );
    assert_eq!(r.len(), 1, "a unique hash IS a real reuse link");
}

#[test]
fn au105_bridges_a_plaintext_to_the_same_password_leaked_as_a_hash() {
    // The synergy: account A leaked the PLAINTEXT in one breach; account B leaked a
    // HASH of the SAME (uncommon) password in another. Recomputing the plaintext's
    // digests offline bridges them into ONE reuse finding spanning both breaches —
    // High, because the plaintext is known. No brute force, no network query.
    let pw = "Tr0ub4dor&3xY-uncommon";
    let digs = crate::util::hashcat::digests_of(pw);
    let mut a = Entity::new(EntityKind::Email, "a@x.com", 0.9, "s");
    a.add_evidence(
        Evidence::new("b", "rec")
            .with_attr("dbname", "breach1")
            .with_attr("password", pw),
    );
    let mut b = Entity::new(EntityKind::Username, "alias", 0.9, "s");
    b.add_evidence(
        Evidence::new("b", "rec")
            .with_attr("dbname", "breach2")
            .with_attr("password_hash", digs[1].as_str()), // sha1(pw)
    );
    let r = super::rules::rule_au_105_credential_reuse(&RuleContext::new(&[a, b]), "s", 0);
    assert_eq!(
        r.len(),
        1,
        "plaintext + its hash across two breaches = one reuse"
    );
    assert_eq!(
        r[0].severity,
        Severity::High,
        "the plaintext is known → High"
    );
}

#[test]
fn au105_silent_for_a_single_use_secret() {
    // A password seen in only ONE breach is not reuse → no finding.
    let mut e = Entity::new(EntityKind::Email, "s@x.com", 0.9, "s");
    e.add_evidence(
        Evidence::new("see_know", "breach")
            .with_attr("dbname", "onlyone.com")
            .with_attr("password", "uniquepass1"),
    );
    assert!(super::rules::rule_au_105_credential_reuse(&RuleContext::new(&[e]), "s", 0).is_empty());
}

#[test]
fn au106_links_accounts_sharing_a_unique_device_fingerprint() {
    // A stealer/breach device fingerprint (hwid) carried against two DISTINCT
    // accounts means both were used on the same physical machine — one controller.
    let mut dev = Entity::new(EntityKind::DeviceId, "HWID-7f3a9c2e1b8d4056", 0.55, "scan");
    dev.tag("stealer");
    dev.add_evidence(Evidence::new("oathnet", "rec1").with_attr("username", "ghost_91"));
    dev.add_evidence(Evidence::new("oathnet", "rec2").with_attr("username", "nightcrawler"));
    let u1 = Entity::new(EntityKind::Username, "ghost_91", 0.6, "scan");
    let u2 = Entity::new(EntityKind::Username, "nightcrawler", 0.6, "scan");
    let hits = super::rules::rule_au_106_shared_device_identity(
        &RuleContext::new(&[dev.clone(), u1.clone(), u2.clone()]),
        "scan",
        0,
    );
    assert_eq!(
        hits.len(),
        1,
        "a shared device fingerprint across 2 distinct accounts must link them"
    );
    assert_eq!(hits[0].rule_id, "AU-106");
    assert_eq!(hits[0].severity, Severity::High);
    assert!(hits[0].entity_uids.contains(&dev.uid));
    assert!(hits[0].entity_uids.contains(&u1.uid) && hits[0].entity_uids.contains(&u2.uid));

    // SAFETY: a short/generic hostname (`USER-PC`) is not a hardware fingerprint
    // and must NOT link people, even across two distinct accounts.
    let mut generic = Entity::new(EntityKind::DeviceId, "USER-PC", 0.55, "scan");
    generic.add_evidence(Evidence::new("oathnet", "r").with_attr("username", "ghost_91"));
    generic.add_evidence(Evidence::new("oathnet", "r").with_attr("username", "nightcrawler"));
    assert!(
        super::rules::rule_au_106_shared_device_identity(&RuleContext::new(&[generic]), "scan", 0)
            .is_empty(),
        "a short/generic hostname must not link people"
    );

    // SAFETY: an email and its MATCHING username from ONE record are one account
    // (the canonical-handle fold), so a single device record cannot self-fire.
    let mut one = Entity::new(EntityKind::DeviceId, "HWID-aaaa1111bbbb2222", 0.55, "scan");
    one.add_evidence(
        Evidence::new("oathnet", "r")
            .with_attr("email", "alice@example.com")
            .with_attr("username", "alice"),
    );
    assert!(
        super::rules::rule_au_106_shared_device_identity(&RuleContext::new(&[one]), "scan", 0)
            .is_empty(),
        "one account described two ways from one record is not a link"
    );
}

#[test]
fn au106_discloses_when_the_identifier_list_is_truncated() {
    // Same "(+N more)" disclosure convention as AU-047/AU-048/AU-076 — a device
    // genuinely shared across MANY accounts must say so, not silently cut the
    // enumerated list at 6 with no indication.
    let mut dev = Entity::new(
        EntityKind::DeviceId,
        "HWID-widelysharedmachine01",
        0.55,
        "scan",
    );
    dev.tag("stealer");
    for i in 0..9 {
        dev.add_evidence(
            Evidence::new("oathnet", format!("rec{i}"))
                .with_attr("username", format!("user_account_{i}")),
        );
    }
    let hits =
        super::rules::rule_au_106_shared_device_identity(&RuleContext::new(&[dev]), "scan", 0);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0]
            .description
            .contains("9 otherwise-separate accounts"),
        "the true total must still be stated: {}",
        hits[0].description
    );
    assert!(
        hits[0].description.contains("(+3 more)"),
        "the enumerated (top-6) identifier list must disclose the 3 it omitted: {}",
        hits[0].description
    );
}
