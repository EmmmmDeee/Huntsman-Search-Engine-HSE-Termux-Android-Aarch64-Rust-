//! Tests for the affiliation edge family.
//!
//! Every fixture is shaped like the REAL module output that grounds the builder
//! under test (the attribute keys, the tags, and which entity carries them are
//! copied from `src/modules`), so a test passing here means the builder fires on
//! data the engine actually produces — not on a shape invented to suit it.

use super::*;
use crate::core::entity::Evidence;

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "aff-scan")
}

/// A Person carrying the engine's seed anchor — the only Person the
/// subject-scoped path may bind to.
fn subject(value: &str, conf: f64) -> Entity {
    let mut p = ent(EntityKind::Person, value, conf);
    p.tag("subject");
    p
}

/// An `Organisation` shaped like `proxycurl`'s employer/education output: the
/// company name, the module tag, and the role attribute it attaches.
fn tagged_org(value: &str, conf: f64, tag: &str, role_attr: Option<(&str, &str)>) -> Entity {
    let mut o = ent(EntityKind::Organisation, value, conf);
    o.tag(tag);
    let mut ev = Evidence::new("proxycurl", format!("Employer: {value}"));
    if let Some((k, v)) = role_attr {
        ev = ev.with_attr(k, v);
    }
    o.add_evidence(ev);
    o
}

/// The set of `(from, to, kind)` triples an edge list asserts, order-independent.
fn triples(rels: &[Relation]) -> std::collections::BTreeSet<(String, String, &'static str)> {
    rels.iter()
        .map(|r| (r.from_uid.clone(), r.to_uid.clone(), r.kind.as_str()))
        .collect()
}

// ── OfficerOf ────────────────────────────────────────────────────────────────

#[test]
fn officership_links_a_register_named_director_to_the_company() {
    // `asic_director`'s shape: every entity minted from a result row carries
    // `director_name` + `company_name`.
    let mut org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    org.add_evidence(
        Evidence::new(
            "asic_director",
            "ASIC director record: JANE CITIZEN → Acme Pty Ltd",
        )
        .with_attr("director_name", "Jane Citizen")
        .with_attr("company_name", "Acme Pty Ltd")
        .with_attr("register", "ASIC"),
    );
    let jane = ent(EntityKind::Person, "Jane Citizen", 0.8);
    // An unrelated person in the same scan must NOT pick up the office.
    let mark = ent(EntityKind::Person, "Mark Roe", 0.7);

    let ents = vec![org.clone(), jane.clone(), mark.clone()];
    let rels = derive_officership(&ents, "s");

    assert_eq!(rels.len(), 1, "only the named director links");
    assert_eq!(rels[0].kind, RelationKind::OfficerOf);
    assert_eq!(rels[0].from_uid, jane.uid, "Person → Organisation");
    assert_eq!(rels[0].to_uid, org.uid);
    // A register published the office: full endpoint trust, no damp.
    assert!(
        (rels[0].confidence - 0.8).abs() < 1e-9,
        "min(0.8, 0.9) undamped, got {}",
        rels[0].confidence
    );
}

#[test]
fn officership_links_an_opencorporates_officer_and_ignores_an_absent_one() {
    let mut org = ent(EntityKind::Organisation, "Widget Holdings", 0.72);
    org.add_evidence(
        Evidence::new(
            "opencorporates",
            "OpenCorporates officer search: Widget Holdings",
        )
        .with_attr("officer_name", "Jane Citizen")
        .with_attr("officer_position", "secretary"),
    );
    let mut absent = ent(EntityKind::Organisation, "Ghost Co", 0.72);
    absent.add_evidence(
        Evidence::new("opencorporates", "officer").with_attr("officer_name", "Nobody Here"),
    );
    let jane = ent(EntityKind::Person, "Jane Citizen", 0.8);

    let rels = derive_officership(&[org.clone(), absent, jane.clone()], "s");
    assert_eq!(
        triples(&rels),
        [(jane.uid.clone(), org.uid.clone(), "officer_of")]
            .into_iter()
            .collect(),
        "a registry name matching no present Person links nothing"
    );
}

#[test]
fn officership_ignores_soft_owner_attributes() {
    // The precision line OfficerOf exists to hold: `owner` / `contact_name` name
    // someone connected to a record; only a register's officer field asserts an
    // OFFICE. Those keys feed the identity builders, never this one.
    let mut org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    org.add_evidence(
        Evidence::new("whois", "registrant")
            .with_attr("owner", "Jane Citizen")
            .with_attr("contact_name", "Jane Citizen")
            .with_attr("registrant_name", "Jane Citizen"),
    );
    let jane = ent(EntityKind::Person, "Jane Citizen", 0.8);

    assert!(
        derive_officership(&[org, jane], "s").is_empty(),
        "a soft owner attribute must never be reported as a registered office"
    );
}

// ── EmployedBy ───────────────────────────────────────────────────────────────

#[test]
fn employment_links_each_profile_listed_employer() {
    // `proxycurl` writes the still-open experience entries as ONE `", "`-joined
    // attribute; each listed company must reach its own Organisation node.
    let mut jane = ent(EntityKind::Person, "Jane Citizen", 0.85);
    jane.add_evidence(
        Evidence::new("proxycurl", "LinkedIn profile: Jane Citizen")
            .with_attr("current_companies", "Acme Pty Ltd, Widget Holdings"),
    );
    let acme = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.7);
    let widget = ent(EntityKind::Organisation, "Widget Holdings", 0.6);

    let rels = derive_employment(&[jane.clone(), acme.clone(), widget.clone()], "s");
    assert_eq!(
        triples(&rels),
        [
            (jane.uid.clone(), acme.uid.clone(), "employed_by"),
            (jane.uid.clone(), widget.uid.clone(), "employed_by"),
        ]
        .into_iter()
        .collect(),
        "both listed employers link, split on the module's own separator"
    );
    // Named on the person's own record → full endpoint trust.
    for r in &rels {
        let expect = if r.to_uid == acme.uid { 0.7 } else { 0.6 };
        assert!(
            (r.confidence - expect).abs() < 1e-9,
            "named employment is undamped, got {}",
            r.confidence
        );
    }
}

#[test]
fn employment_binds_a_tagged_employer_to_the_subject_only_and_damps_it() {
    // `proxycurl` tags a still-open experience `current-employer` without naming
    // the person (they were the module's own target), so the tie binds to the
    // SUBJECT — and is damped, because that binding is inferred.
    let jane = subject("Jane Citizen", 0.85);
    let bystander = ent(EntityKind::Person, "Mark Roe", 0.8);
    let acme = tagged_org("Acme Pty Ltd", 0.7, "current-employer", None);

    let rels = derive_employment(&[jane.clone(), bystander, acme.clone()], "s");
    assert_eq!(
        triples(&rels),
        [(jane.uid.clone(), acme.uid.clone(), "employed_by")]
            .into_iter()
            .collect(),
        "only the subject may accrete a subject-scoped affiliation"
    );
    let expect = 0.7 * SUBJECT_AFFILIATION_DAMP;
    assert!(
        (rels[0].confidence - expect).abs() < 1e-9,
        "expected min(0.85, 0.7) × {SUBJECT_AFFILIATION_DAMP}, got {}",
        rels[0].confidence
    );
}

#[test]
fn a_named_employment_is_not_downgraded_by_also_being_tagged() {
    // Both paths describe the same pair. The named one runs first and claims the
    // pair, so the damped path can't overwrite it with a weaker edge.
    let mut jane = subject("Jane Citizen", 0.85);
    jane.add_evidence(
        Evidence::new("proxycurl", "profile").with_attr("current_companies", "Acme Pty Ltd"),
    );
    let acme = tagged_org("Acme Pty Ltd", 0.7, "current-employer", None);

    let rels = derive_employment(&[jane, acme], "s");
    assert_eq!(rels.len(), 1, "one edge per pair");
    assert!(
        (rels[0].confidence - 0.7).abs() < 1e-9,
        "the named tie keeps full trust, got {}",
        rels[0].confidence
    );
}

#[test]
fn employment_covers_the_asic_adviser_affiliations() {
    // `asic_persons` emits the AFS licensee an adviser operates under and the
    // authorised-rep firm that appointed them, both tagged and both subject-scoped.
    let jane = subject("Jane Citizen", 0.9);
    let licensee = tagged_org("Big Bank Advice Ltd", 0.62, "afs-licensee", None);
    let rep_firm = tagged_org("Citizen Advisory", 0.55, "authorised-rep-firm", None);

    let rels = derive_employment(&[jane.clone(), licensee.clone(), rep_firm.clone()], "s");
    assert_eq!(
        triples(&rels),
        [
            (jane.uid.clone(), licensee.uid.clone(), "employed_by"),
            (jane.uid.clone(), rep_firm.uid.clone(), "employed_by"),
        ]
        .into_iter()
        .collect()
    );
}

// ── MemberOf ─────────────────────────────────────────────────────────────────

#[test]
fn membership_links_a_listed_alma_mater_and_never_reads_as_employment() {
    let jane = subject("Jane Citizen", 0.9);
    let school = tagged_org("University of Queensland", 0.55, "education", None);
    let employer = tagged_org("Acme Pty Ltd", 0.7, "current-employer", None);
    let ents = vec![jane.clone(), school.clone(), employer.clone()];

    assert_eq!(
        triples(&derive_membership(&ents, "s")),
        [(jane.uid.clone(), school.uid.clone(), "member_of")]
            .into_iter()
            .collect(),
        "an alma mater is a membership, and an employer is not one"
    );
    assert_eq!(
        triples(&derive_employment(&ents, "s")),
        [(jane.uid.clone(), employer.uid.clone(), "employed_by")]
            .into_iter()
            .collect(),
        "and the two kinds never cross-fire"
    );
}

// ── ControlledBy ─────────────────────────────────────────────────────────────

/// A GLEIF Level 2 relative: reached THROUGH `via_org`, playing `role`.
fn gleif_relative(name: &str, conf: f64, via: &str, role: &str) -> Entity {
    let mut e = ent(EntityKind::Organisation, name, conf);
    e.tag("corporate-family");
    e.add_evidence(
        Evidence::new("gleif_lei", format!("{name} / {via} (GLEIF Level 2)"))
            .with_attr("relationship", "IS_DIRECTLY_CONSOLIDATED_BY")
            .with_attr("relationship_role", role)
            .with_attr("via_org", via),
    );
    e
}

#[test]
fn corporate_control_orients_parents_up_and_subsidiaries_down() {
    let seed = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    let parent = gleif_relative("Acme Holdings", 0.8, "Acme Pty Ltd", "corporate-parent");
    let ultimate = gleif_relative("Acme Group NV", 0.8, "Acme Pty Ltd", "ultimate-parent");
    let child = gleif_relative(
        "Acme Logistics",
        0.8,
        "Acme Pty Ltd",
        "corporate-subsidiary",
    );

    let rels = derive_corporate_control(
        &[
            seed.clone(),
            parent.clone(),
            ultimate.clone(),
            child.clone(),
        ],
        "s",
    );
    assert_eq!(
        triples(&rels),
        [
            // The seed is the child of both its parents: edges run UP.
            (seed.uid.clone(), parent.uid.clone(), "controlled_by"),
            (seed.uid.clone(), ultimate.uid.clone(), "controlled_by"),
            // A subsidiary is controlled BY the seed: the edge flips.
            (child.uid.clone(), seed.uid.clone(), "controlled_by"),
        ]
        .into_iter()
        .collect(),
        "a chain of ControlledBy edges must walk up the ownership tree"
    );
}

#[test]
fn corporate_control_skips_an_unmapped_relationship_role() {
    // GLEIF can publish a relationship type whose direction this code has not
    // been taught. Guessing would invert an ownership claim, so it links nothing.
    let seed = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    let odd = gleif_relative("Acme Branch", 0.8, "Acme Pty Ltd", "is-fund-managed-by");
    assert!(derive_corporate_control(&[seed, odd], "s").is_empty());
}

#[test]
fn corporate_control_links_an_asic_licence_controller() {
    // `asic_persons` records the controller pointing DOWN at the licensee it
    // controls, so the edge is emitted licensee → controller.
    let licensee = ent(EntityKind::Organisation, "Small Advice Pty Ltd", 0.62);
    let mut controller = ent(EntityKind::Organisation, "Big Bank Ltd", 0.58);
    controller.tag("afs-licensee-controller");
    controller.add_evidence(
        Evidence::new("asic_persons", "Controls AFS licensee Small Advice Pty Ltd")
            .with_attr("relationship", "licence_controlled_by")
            .with_attr("controls_licensee", "Small Advice Pty Ltd"),
    );

    let rels = derive_corporate_control(&[licensee.clone(), controller.clone()], "s");
    assert_eq!(
        triples(&rels),
        [(
            licensee.uid.clone(),
            controller.uid.clone(),
            "controlled_by"
        )]
        .into_iter()
        .collect()
    );
}

#[test]
fn corporate_control_links_an_individual_controller() {
    // `asic_persons::classify_linked` can resolve a controller to a Person; the
    // edge permits it, because "controlled by an individual" is the finding.
    let licensee = ent(EntityKind::Organisation, "Small Advice Pty Ltd", 0.62);
    let mut person = ent(EntityKind::Person, "Jane Citizen", 0.58);
    person.add_evidence(
        Evidence::new("asic_persons", "controls")
            .with_attr("controls_licensee", "Small Advice Pty Ltd"),
    );

    let rels = derive_corporate_control(&[licensee.clone(), person.clone()], "s");
    assert_eq!(
        triples(&rels),
        [(licensee.uid.clone(), person.uid.clone(), "controlled_by")]
            .into_iter()
            .collect()
    );
}

// ── OperatedBy ───────────────────────────────────────────────────────────────

#[test]
fn asset_operator_names_the_service_behind_a_wallet() {
    // `chain_intel` writes Blockscout's curated label onto BOTH the address and
    // the label's own Organisation entity.
    let mut addr = ent(
        EntityKind::CryptoAddress,
        "0x00000000219ab540356cbb839cbe05303d7705fa",
        0.9,
    );
    addr.tag("crypto-address");
    addr.add_evidence(
        Evidence::new("chain_intel", "Blockscout enrichment")
            .with_attr("known_name", "Beacon Deposit"),
    );
    let mut label = ent(EntityKind::Organisation, "Beacon Deposit", 0.82);
    label.tag("known-name");
    label.add_evidence(
        Evidence::new("chain_intel", "Blockscout known-name label")
            .with_attr("known_name", "Beacon Deposit")
            .with_attr("address", "0x00000000219ab540356cbb839cbe05303d7705fa"),
    );

    let rels = derive_asset_operator(&[addr.clone(), label.clone()], "s");
    assert_eq!(
        triples(&rels),
        [(addr.uid.clone(), label.uid.clone(), "operated_by")]
            .into_iter()
            .collect(),
        "the wallet links to its operator, and the label must not self-link"
    );
}

#[test]
fn asset_operator_links_a_business_contact_point_to_the_employer_site() {
    // `employer_pivot` stamps the domain whose contact pages published each
    // extracted business contact point. The host is folded the way the Domain
    // normaliser folds entity values, so a `www.`/mixed-case attribute still hits.
    let mut office = ent(
        EntityKind::Address,
        "12 Rose Street, Brisbane QLD 4000",
        0.7,
    );
    office.add_evidence(
        Evidence::new("employer_pivot", "Business address")
            .with_attr("employer_domain", "www.Acme.com"),
    );
    let mut phone = ent(EntityKind::Phone, "+61738000000", 0.8);
    phone.add_evidence(
        Evidence::new("employer_pivot", "Business phone").with_attr("employer_domain", "acme.com"),
    );
    let domain = ent(EntityKind::Domain, "acme.com", 0.85);

    let rels = derive_asset_operator(&[office.clone(), phone.clone(), domain.clone()], "s");
    assert_eq!(
        triples(&rels),
        [
            (office.uid.clone(), domain.uid.clone(), "operated_by"),
            (phone.uid.clone(), domain.uid.clone(), "operated_by"),
        ]
        .into_iter()
        .collect()
    );
}

// ── Organisation identity & place ────────────────────────────────────────────

#[test]
fn org_identity_links_a_company_to_its_registry_number_and_registered_office() {
    // `asic_director` attaches its `company_name` evidence to EVERY entity it
    // mints from one result row — the company, its ACN, its registered office and
    // that office's coordinates. Before this builder all four were unlinked.
    let ev = || {
        Evidence::new("asic_director", "ASIC director record")
            .with_attr("company_name", "Acme Pty Ltd")
            .with_attr("director_name", "Jane Citizen")
    };
    let org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    let mut acn = ent(EntityKind::AbnAcn, "004085616", 0.82);
    acn.add_evidence(ev().with_attr("acn", "004085616"));
    let mut office = ent(
        EntityKind::Address,
        "12 Rose Street, Brisbane QLD 4000",
        0.72,
    );
    office.add_evidence(ev().with_attr("registered_office", "12 Rose Street, Brisbane QLD 4000"));
    let mut coords = ent(EntityKind::Coordinates, "-27.4698,153.0251", 0.62);
    coords.add_evidence(ev());

    let rels = derive_org_identity(
        &[org.clone(), acn.clone(), office.clone(), coords.clone()],
        "s",
    );
    assert_eq!(
        triples(&rels),
        [
            (org.uid.clone(), acn.uid.clone(), "identified_by"),
            (org.uid.clone(), office.uid.clone(), "located_at"),
            (org.uid.clone(), coords.uid.clone(), "located_at"),
        ]
        .into_iter()
        .collect(),
        "identifiers become IdentifiedBy; places become LocatedAt"
    );
}

#[test]
fn org_identity_reads_every_grounding_register_key() {
    // One key per grounding module, so dropping any from ORG_NAME_ATTRS fails here.
    let org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    let keys = [
        "company_name",
        "org",
        "business_name",
        "organisation",
        "licensee",
        "known_name",
    ];
    let ids: Vec<Entity> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let mut e = ent(EntityKind::Email, &format!("contact{i}@acme.com"), 0.7);
            e.add_evidence(Evidence::new("register", "record").with_attr(*k, "Acme Pty Ltd"));
            e
        })
        .collect();

    let mut ents = vec![org.clone()];
    ents.extend(ids.iter().cloned());
    let rels = derive_org_identity(&ents, "s");
    assert_eq!(
        rels.len(),
        keys.len(),
        "every curated organisation-name key must resolve its record"
    );
    assert!(
        rels.iter()
            .all(|r| r.from_uid == org.uid && r.kind == RelationKind::IdentifiedBy)
    );
}

#[test]
fn org_identity_does_not_restate_whois_registration() {
    // A domain's registrant is already the RegisteredBy edge derive_registration
    // emits; `registrant_org` is deliberately absent from ORG_NAME_ATTRS so one
    // WHOIS fact isn't double-counted as two different relations.
    let org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    let mut domain = ent(EntityKind::Domain, "acme.com", 0.85);
    domain.add_evidence(
        Evidence::new("whois", "registrant").with_attr("registrant_org", "Acme Pty Ltd"),
    );
    assert!(derive_org_identity(&[org, domain], "s").is_empty());
}

#[test]
fn asset_operator_names_the_network_operator_every_infra_module_records() {
    // The widest source family: eleven modules mint an Organisation for an
    // address's operator and write the asset into the evidence SUMMARY. One
    // fixture per distinct summary convention actually found in `src/modules`.
    let ip = ent(EntityKind::IpAddress, "104.16.132.229", 0.9);
    let asn = ent(EntityKind::Asn, "AS13335", 0.88);
    let cidr = ent(EntityKind::Cidr, "104.16.0.0/12", 0.8);

    let org = |summary: &str, attrs: &[(&str, &str)]| {
        let mut o = ent(EntityKind::Organisation, summary, 0.7);
        let mut ev = Evidence::new("infra", summary);
        for (k, v) in attrs {
            ev = ev.with_attr(*k, *v);
        }
        o.add_evidence(ev);
        o
    };
    // shodan / censys / criminal_ip / ip_geo / ip_whois_geo — IP in the summary.
    let shodan = org("Organisation for 104.16.132.229", &[]);
    let censys = org("Network operator for 104.16.132.229", &[]);
    // ip_registry — ASN in the summary AND in a keyed `asn` attribute.
    let registry = org("Operator of AS13335", &[("asn", "AS13335")]);
    // ip_geo — IP in the summary, ASN only as an attribute.
    let ip_geo = org("IP org for 104.16.132.229", &[("asn", "AS13335")]);
    // A prefix named in an announced-prefix record.
    let prefix_op = org("Announced by 104.16.0.0/12", &[]);

    let ents = vec![
        ip.clone(),
        asn.clone(),
        cidr.clone(),
        shodan.clone(),
        censys.clone(),
        registry.clone(),
        ip_geo.clone(),
        prefix_op.clone(),
    ];
    let got = triples(&derive_asset_operator(&ents, "s"));
    let want: std::collections::BTreeSet<_> = [
        (ip.uid.clone(), shodan.uid.clone(), "operated_by"),
        (ip.uid.clone(), censys.uid.clone(), "operated_by"),
        (asn.uid.clone(), registry.uid.clone(), "operated_by"),
        (ip.uid.clone(), ip_geo.uid.clone(), "operated_by"),
        (asn.uid.clone(), ip_geo.uid.clone(), "operated_by"),
        (cidr.uid.clone(), prefix_op.uid.clone(), "operated_by"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        got, want,
        "every infra convention must resolve its asset, in the asset \u{2192} operator direction"
    );
}

#[test]
fn asset_operator_never_reads_a_domain_out_of_an_organisations_evidence() {
    // The precision gate on the summary sweep. A domain appears in an
    // organisation's evidence for a dozen reasons that are not operatorship, so
    // Domain is excluded from OPERATED_ASSET_KINDS; only a literal address,
    // prefix or AS label can link this way.
    let domain = ent(EntityKind::Domain, "cloudflare.com", 0.9);
    let mut org = ent(EntityKind::Organisation, "Cloudflare Inc", 0.8);
    org.add_evidence(Evidence::new(
        "search_engines",
        "Result mentioning cloudflare.com for Cloudflare Inc",
    ));

    assert!(
        derive_asset_operator(&[domain, org], "s").is_empty(),
        "a domain named in an org's evidence is not an operator claim"
    );
}

#[test]
fn asset_operator_requires_the_asset_to_be_present() {
    // A summary naming an address the scan never surfaced links nothing — the
    // named-endpoints-only rule.
    let mut org = ent(EntityKind::Organisation, "Cloudflare Inc", 0.8);
    org.add_evidence(Evidence::new("shodan", "Organisation for 104.16.132.229"));
    let unrelated = ent(EntityKind::IpAddress, "8.8.8.8", 0.9);
    assert!(derive_asset_operator(&[org, unrelated], "s").is_empty());
}

#[test]
fn org_identity_reads_the_tie_from_whichever_side_the_source_stamped_it() {
    // `hunter_io` stamps `domain` on the ORGANISATION; `asic_director` stamps
    // `company_name` on the identifier. Both must reach the same edge, because
    // reading one direction only would drop every source that chose the other.
    let mut hunter_org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.85);
    hunter_org.add_evidence(
        Evidence::new("hunter_io", "Hunter.io resolved organisation for acme.com")
            .with_attr("domain", "www.ACME.com"),
    );
    let domain = ent(EntityKind::Domain, "acme.com", 0.9);
    let mut acn = ent(EntityKind::AbnAcn, "004085616", 0.82);
    acn.add_evidence(
        Evidence::new("asic_director", "acn").with_attr("company_name", "Acme Pty Ltd"),
    );

    let rels = derive_org_identity(&[hunter_org.clone(), domain.clone(), acn.clone()], "s");
    assert_eq!(
        triples(&rels),
        [
            (hunter_org.uid.clone(), domain.uid.clone(), "identified_by"),
            (hunter_org.uid.clone(), acn.uid.clone(), "identified_by"),
        ]
        .into_iter()
        .collect(),
        "the organisation-side `domain` folds like a Domain value, and the \
         identifier-side `company_name` still resolves"
    );
}

#[test]
fn org_identity_ignores_an_owned_identifier_that_is_not_present() {
    let mut org = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.85);
    org.add_evidence(Evidence::new("hunter_io", "org").with_attr("domain", "never-seen.example"));
    let other = ent(EntityKind::Domain, "acme.com", 0.9);
    assert!(derive_org_identity(&[org, other], "s").is_empty());
}

#[test]
fn employment_covers_every_module_that_mints_an_employer_organisation() {
    // One tagged Organisation per emitting module, so dropping any row from
    // SUBJECT_AFFILIATION_TAGS fails here.
    let jane = subject("Jane Citizen", 0.9);
    let tags = [
        ("current-employer", "Acme Pty Ltd"),        // proxycurl
        ("employer", "Widget Holdings"),             // gravatar / fullcontact
        ("employer-field", "Breach Corp"),           // oathnet_pro
        ("afs-licensee", "Big Bank Advice Ltd"),     // asic_persons
        ("authorised-rep-firm", "Citizen Advisory"), // asic_persons
    ];
    let orgs: Vec<Entity> = tags
        .iter()
        .map(|(tag, name)| tagged_org(name, 0.6, tag, None))
        .collect();

    let mut ents = vec![jane.clone()];
    ents.extend(orgs.iter().cloned());
    let rels = derive_employment(&ents, "s");
    assert_eq!(
        rels.len(),
        tags.len(),
        "every employer-minting module must reach the subject"
    );
    assert!(
        rels.iter()
            .all(|r| r.from_uid == jane.uid && r.kind == RelationKind::EmployedBy)
    );
}

// ── Cross-cutting invariants ─────────────────────────────────────────────────

/// The shape every builder in this file has: entities + scan id → edges.
type Builder = fn(&[Entity], &str) -> Vec<Relation>;

/// Every builder in this file, so an invariant test can't silently skip one.
const EVERY_BUILDER: &[(&str, Builder)] = &[
    ("officership", derive_officership),
    ("employment", derive_employment),
    ("membership", derive_membership),
    ("corporate_control", derive_corporate_control),
    ("asset_operator", derive_asset_operator),
    ("org_identity", derive_org_identity),
];

/// One entity set exercising every grounding path at once.
fn full_fixture() -> Vec<Entity> {
    let mut jane = subject("Jane Citizen", 0.85);
    jane.add_evidence(
        Evidence::new("proxycurl", "profile").with_attr("current_companies", "Widget Holdings"),
    );
    let mut acme = ent(EntityKind::Organisation, "Acme Pty Ltd", 0.9);
    acme.add_evidence(
        Evidence::new("asic_director", "record")
            .with_attr("director_name", "Jane Citizen")
            .with_attr("company_name", "Acme Pty Ltd"),
    );
    let mut acn = ent(EntityKind::AbnAcn, "004085616", 0.82);
    acn.add_evidence(
        Evidence::new("asic_director", "acn").with_attr("company_name", "Acme Pty Ltd"),
    );
    let mut office = ent(
        EntityKind::Address,
        "12 Rose Street, Brisbane QLD 4000",
        0.72,
    );
    office.add_evidence(
        Evidence::new("asic_director", "registered office")
            .with_attr("company_name", "Acme Pty Ltd")
            .with_attr("registered_office", "12 Rose Street, Brisbane QLD 4000"),
    );
    let mut wallet = ent(
        EntityKind::CryptoAddress,
        "0xdeadbeef00000000000000000000000000000000",
        0.8,
    );
    wallet.add_evidence(
        Evidence::new("chain_intel", "label").with_attr("known_name", "Acme Pty Ltd"),
    );
    vec![
        jane,
        acme,
        acn,
        office,
        wallet,
        tagged_org("Widget Holdings", 0.6, "current-employer", None),
        tagged_org("University of Queensland", 0.55, "education", None),
        gleif_relative("Acme Holdings", 0.8, "Acme Pty Ltd", "corporate-parent"),
    ]
}

#[test]
fn every_builder_is_order_independent_and_deduped() {
    let ents = full_fixture();
    let mut reversed = ents.clone();
    reversed.reverse();

    for (name, build) in EVERY_BUILDER {
        let a = build(&ents, "s");
        let b = build(&reversed, "s");
        assert!(!a.is_empty(), "{name}: fixture must exercise this builder");
        assert_eq!(
            a.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            b.iter().map(|r| r.id.clone()).collect::<Vec<_>>(),
            "{name}: edge set and order must not depend on entity order"
        );
        let mut ids: Vec<&str> = a.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "{name}: emitted a duplicate edge");
    }
}

#[test]
fn every_builder_is_empty_without_the_endpoint_it_needs() {
    // No Organisation in the set → nothing to affiliate with, and no panic.
    let lonely = vec![
        subject("Jane Citizen", 0.85),
        ent(EntityKind::Email, "j@x.com", 0.7),
    ];
    for (name, build) in EVERY_BUILDER {
        assert!(
            build(&lonely, "s").is_empty(),
            "{name}: emitted an edge with no organisation present"
        );
    }
    for (name, build) in EVERY_BUILDER {
        assert!(build(&[], "s").is_empty(), "{name}: empty input");
    }
}

#[test]
fn every_builder_emits_confidence_in_range_and_endpoints_that_resolve() {
    let ents = full_fixture();
    let uids: std::collections::HashSet<&str> = ents.iter().map(|e| e.uid.as_str()).collect();
    for (name, build) in EVERY_BUILDER {
        for r in build(&ents, "s") {
            assert!(
                (0.0..=1.0).contains(&r.confidence),
                "{name}: confidence out of range: {}",
                r.confidence
            );
            assert!(
                uids.contains(r.from_uid.as_str()),
                "{name}: dangling from_uid"
            );
            assert!(uids.contains(r.to_uid.as_str()), "{name}: dangling to_uid");
            assert_ne!(r.from_uid, r.to_uid, "{name}: self-loop");
            assert_eq!(r.scan_id, "s");
        }
    }
}

#[test]
fn derive_all_carries_the_whole_affiliation_family() {
    // The wiring test: the import path and the live scan both go through
    // derive_all, so an unwired builder is invisible in production even with
    // every unit test above green.
    let rels = super::super::derive_all(&full_fixture(), "s");
    let kinds: std::collections::BTreeSet<&str> = rels.iter().map(|r| r.kind.as_str()).collect();
    for expected in [
        "officer_of",
        "employed_by",
        "member_of",
        "controlled_by",
        "operated_by",
    ] {
        assert!(
            kinds.contains(expected),
            "derive_all must emit {expected}; got {kinds:?}"
        );
    }
    assert!(
        kinds.contains("identified_by") && kinds.contains("located_at"),
        "and the organisation's own identity edges; got {kinds:?}"
    );
}
