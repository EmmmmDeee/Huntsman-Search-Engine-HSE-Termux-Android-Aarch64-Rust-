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
    let report = discover(&[email.clone()], &graph);
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
        ["search", "code"]
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
    assert_eq!(fake_result.opportunities.len(), 3);
    assert!(
        fake_result
            .opportunities
            .iter()
            .all(|o| o.declared_upstream_families.is_empty())
    );
    assert_eq!(
        fake_result.opportunities[0].missing_modality,
        "identity_registry"
    );
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
