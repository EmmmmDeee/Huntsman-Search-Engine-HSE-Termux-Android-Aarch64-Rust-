//! End-to-end diagnostic contracts for orthogonal OSINT acquisition proposals.
//! These tests never reach external services and never establish identity links.

use huntsman_recon::analysis::analyze_snapshot;
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::evidence_ancestry::EvidenceAncestryGraph;
use huntsman_recon::orthogonal_osint::{MAX_OPPORTUNITIES, discover};
use huntsman_recon::pipeline::AnalysisSnapshot;

fn email_from_two_mirrors() -> Entity {
    let mut entity = Entity::new(EntityKind::Email, "person@example.org", 0.55, "test");
    entity.add_evidence(
        Evidence::new(EvidenceProvenance::new("hibp"), "Corpus").with_attr("breach", "Adobe"),
    );
    entity.add_evidence(
        Evidence::new(EvidenceProvenance::new("dehashed"), "Same upstream")
            .with_attr("dbname", "ADOBE"),
    );
    entity
}

#[test]
fn two_collectors_one_corpus_do_not_become_independent_or_complete() {
    let email = email_from_two_mirrors();
    let initial = email.clone();
    let graph = EvidenceAncestryGraph::default();
    let report = discover(std::slice::from_ref(&email), &graph);
    assert_eq!(email, initial);
    assert_eq!(report.entities_examined, 1);
    assert_eq!(report.eligible_entities, 1);
    assert_eq!(report.opportunities.len(), 2);
    for opportunity in &report.opportunities {
        assert_eq!(opportunity.observed_modalities, ["breach"]);
        assert_eq!(opportunity.declared_upstream_families, ["adobe"]);
        assert_eq!(opportunity.observed_collector_count, 2);
        assert_eq!(opportunity.proven_independent_routes, 0);
        assert_eq!(opportunity.independence_status, "not_recorded");
    }
    assert_eq!(
        report
            .opportunities
            .iter()
            .map(|o| o.missing_modality)
            .collect::<Vec<_>>(),
        ["email_intel", "code"]
    );
}

#[test]
fn authenticated_registry_lineage_is_not_spoofable_by_serialized_labels() {
    let mut good = Entity::new(
        EntityKind::Organisation,
        "Example Organisation",
        0.7,
        "test",
    );
    good.add_evidence(
        Evidence::new(EvidenceProvenance::new("abn_lookup"), "ABR row")
            .with_attr("registry", "ABR"),
    );
    let good_result = discover(&[good], &EvidenceAncestryGraph::default());
    assert_eq!(
        good_result
            .opportunities
            .iter()
            .map(|x| x.missing_modality)
            .collect::<Vec<_>>(),
        ["knowledge_graph", "search", "code"]
    );
    assert_eq!(
        good_result.opportunities[0].declared_upstream_families,
        ["abr"]
    );

    let mut fake = Entity::new(EntityKind::Organisation, "Other Organisation", 0.7, "test");
    let mut evidence = Evidence::new(EvidenceProvenance::new("mirror"), "Claimed register")
        .with_attr("registry", "ABR");
    evidence.provenance.source_family = "abn_lookup".to_owned();
    fake.add_evidence(evidence);
    let fake_result = discover(&[fake], &EvidenceAncestryGraph::default());
    assert_eq!(fake_result.opportunities.len(), 4);
    assert!(
        fake_result
            .opportunities
            .iter()
            .all(|o| o.declared_upstream_families.is_empty())
    );
    assert_eq!(
        fake_result.opportunities[0].missing_modality,
        "knowledge_graph"
    );
    assert_eq!(fake_result.opportunities[1].missing_modality, "identity_registry");
}

#[test]
fn inferred_enrichment_is_not_an_observed_acquisition() {
    let mut entity = Entity::new(EntityKind::Domain, "example.org", 0.7, "test");
    let mut inferred = Evidence::new(EvidenceProvenance::new("github_user"), "Generated guess");
    inferred.is_inferred = true;
    entity.add_evidence(inferred);
    let result = discover(&[entity], &EvidenceAncestryGraph::default());
    assert_eq!(result.opportunities.len(), 3);
    assert!(
        result
            .opportunities
            .iter()
            .all(|o| o.observed_modalities.is_empty())
    );
}

#[test]
fn ordering_duplicate_entities_and_overflow_are_deterministic() {
    let a = email_from_two_mirrors();
    let mut b = Entity::new(EntityKind::Username, "public_handle", 0.6, "test");
    b.add_evidence(Evidence::new(
        EvidenceProvenance::new("hacker_news"),
        "Public post",
    ));
    let graph = EvidenceAncestryGraph::default();
    let baseline = discover(&[a.clone(), b.clone()], &graph);
    let shuffled = discover(&[b, a.clone(), a], &graph);
    assert_eq!(baseline.opportunities, shuffled.opportunities);
    assert_eq!(baseline.eligible_entities, 2);
    assert_eq!(shuffled.eligible_entities, 2);

    let many: Vec<_> = (0..200)
        .map(|n| Entity::new(EntityKind::Domain, format!("s{n}.example.org"), 0.5, "test"))
        .collect();
    let result = discover(&many, &graph);
    assert_eq!(result.opportunities.len(), MAX_OPPORTUNITIES);
    assert_eq!(result.omitted_opportunities, 600 - MAX_OPPORTUNITIES);
    assert!(result.truncated);
    assert_eq!(result.eligible_entities, 200);
}


#[test]
fn real_network_collectors_satisfy_only_their_actual_acquisition_modality() {
    let cases: &[(EntityKind, &str, &str, &[&str])] = &[
        (EntityKind::Asn, "13335", "peeringdb", &["infra"]),
        (EntityKind::Domain, "example.org", "certspotter", &["infra"]),
        (EntityKind::Domain, "example.org", "crtsh", &["infra"]),
        (EntityKind::Domain, "example.org", "wayback_cdx", &["search"]),
        (EntityKind::Username, "public_handle", "gitlab_user", &["code"]),
        (EntityKind::Username, "public_handle", "bluesky_user", &["social"]),
        (EntityKind::Organisation, "Example Organisation", "gleif", &["identity_registry"]),
        (EntityKind::Organisation, "Example Organisation", "wikidata", &["knowledge_graph"]),
        (EntityKind::Person, "Public Example", "wikidata", &["knowledge_graph"]),
        (EntityKind::Email, "public@example.org", "xposedornot", &["breach"]),
    ];
    for (kind, value, collector, modalities) in cases {
        let mut entity = Entity::new(kind.clone(), *value, 0.6, "test");
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::new(collector),
            "Recorded source observation",
        ));
        let report = discover(&[entity], &EvidenceAncestryGraph::default());
        assert!(!report.opportunities.is_empty(), "{collector}");
        assert_eq!(
            report.opportunities[0].observed_modalities,
            *modalities,
            "source={collector}"
        );
        assert!(
            report.opportunities.iter().all(|o| o.missing_modality != modalities[0]),
            "source={collector} was incorrectly suggested as uncollected"
        );
        assert!(
            report.opportunities.iter().all(|o| o.proven_independent_routes == 0),
            "source={collector}: collector is not an independence proof"
        );
    }
}

#[test]
fn wikipedia_like_community_sources_are_not_promoted_to_official_registry_proofs() {
    let mut org = Entity::new(EntityKind::Organisation, "Public Organisation", 0.5, "test");
    let mut evidence = Evidence::new(
        EvidenceProvenance::new("wikidata"),
        "Community-curated statement",
    );
    // An attacker-provided metadata label must not spoof an authoritative
    // registry, and an unrecognised collector cannot become an observation
    // merely by claiming the source family.
    evidence.provenance.source_family = "identity_registry".to_owned();
    org.add_evidence(evidence);
    let report = discover(&[org], &EvidenceAncestryGraph::default());
    assert_eq!(report.opportunities.len(), 3);
    assert!(report.opportunities.iter().all(|o| o.observed_modalities == ["knowledge_graph"]));
    assert!(report.opportunities.iter().any(|o| o.missing_modality == "identity_registry"));
    assert!(report.opportunities.iter().all(|o| o.independence_status == "not_recorded"));
    // This is a richer acquisition label only. Correlation/identity merging
    // keeps the pre-existing strict classifier unchanged.
    assert_eq!(huntsman_recon::correlator::source_family("wikidata"), "other");
}

#[test]
fn unknown_collectors_and_inferred_live_source_names_do_not_fill_coverage() {
    let mut org = Entity::new(EntityKind::Organisation, "Other Organisation", 0.5, "test");
    let mut fake = Evidence::new(
        EvidenceProvenance::new("unverified_fake_source"),
        "Unsubstantiated claim",
    );
    fake.provenance.source_family = "identity_registry".to_owned();
    org.add_evidence(fake);
    let report = discover(&[org], &EvidenceAncestryGraph::default());
    assert_eq!(report.opportunities.len(), 4);
    assert!(report.opportunities.iter().all(|o| o.observed_modalities.is_empty()));

    let mut domain = Entity::new(EntityKind::Domain, "example.org", 0.5, "test");
    let mut invented = Evidence::new(EvidenceProvenance::new("certspotter"), "Guess");
    invented.is_inferred = true;
    domain.add_evidence(invented);
    let report = discover(&[domain], &EvidenceAncestryGraph::default());
    assert_eq!(report.opportunities.len(), 3);
    assert!(report.opportunities.iter().all(|o| o.observed_modalities.is_empty()));
}

#[test]
fn immutable_analysis_fanout_exports_the_same_orthogonal_report() {
    let entities = vec![email_from_two_mirrors()];
    let snapshot = AnalysisSnapshot {
        entities: entities.clone(),
        relations: Vec::new(),
        coverage: Vec::new(),
        ancestry: EvidenceAncestryGraph::default(),
        truncated: false,
    };
    let report = analyze_snapshot(&snapshot);
    assert_eq!(report.orthogonal, discover(&entities, &snapshot.ancestry));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["orthogonal"]["opportunities"][0]["missing_modality"],
        "email_intel"
    );
    assert_eq!(
        json["orthogonal"]["opportunities"][0]["proven_independent_routes"],
        0
    );
    assert!(!json["orthogonal"]["truncated"].as_bool().unwrap());
}
