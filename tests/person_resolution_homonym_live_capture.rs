use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::collection::{
    CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin,
};
use huntsman_recon::dependency::{Target, TargetKind};
use huntsman_recon::entity::{Entity, EntityKind};
use huntsman_recon::evidence_ancestry::{
    EvidenceNodeId, IndependenceBasis, IndependenceEvidence,
};
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::pipeline::{AnalysisSnapshot, PipelineLimits, normalize_observations};
use huntsman_recon::resolve::automatic_clusters;
use huntsman_recon::retrieval_artifact::ArtifactId;
use huntsman_recon::source_outcome::SourceOutcomeKind;

const SCAN_ID: &str = "andrew-gallant-homonym-live-capture-2026-10-07";

fn target() -> Target {
    Target::new(TargetKind::FullName, "Andrew Gallant")
}

fn origin(provider: &str, dataset: &str, artifact: &str) -> UpstreamOrigin {
    UpstreamOrigin {
        provider: Some(provider.to_string()),
        dataset: Some(dataset.to_string()),
        artifact: Some(artifact.to_string()),
    }
}

fn observation(
    provider_id: &str,
    upstream: UpstreamOrigin,
    kind: EntityKind,
    value: &str,
    summary: &str,
) -> RawObservation {
    RawObservation {
        provider_id: provider_id.to_string(),
        upstream: Some(upstream),
        target: target(),
        kind,
        value: value.to_string(),
        summary: summary.to_string(),
        attributes: BTreeMap::new(),
        observed_at_unix: Some(1_760_000_000),
    }
}

fn event(provider_id: &str, upstream: UpstreamOrigin, finding_count: usize) -> CollectionEvent {
    CollectionEvent {
        scan_id: SCAN_ID.to_string(),
        provider_id: provider_id.to_string(),
        target: target(),
        outcome: SourceOutcomeKind::Success,
        finding_count,
        truncated: false,
        started_at_unix: 1_760_000_000,
        finished_at_unix: 1_760_000_001,
        credential_fingerprint: None,
        upstream: Some(upstream),
    }
}

// Public-source capture verified on 2026-10-07.
// Rust Project governance pages bind Andrew Gallant to the GitHub handle BurntSushi.
// GitHub's public BurntSushi profile identifies Andrew Gallant and the ripgrep project.
// Durham University independently identifies a different Andrew Gallant as a professor.
fn captured_public_homonyms() -> ObservationBatch {
    let rust = origin(
        "rust_project",
        "governance_team",
        "https://rust-lang.org/governance/teams/library/",
    );
    let github = origin(
        "github_public_profile",
        "burntsushi",
        "https://github.com/BurntSushi",
    );
    let durham = origin(
        "durham_university",
        "staff_profile",
        "https://dur.ac.uk/staff/a-j-gallant/",
    );

    ObservationBatch {
        events: vec![
            event("rust_project", rust.clone(), 2),
            event("github_profile", github.clone(), 2),
            event("durham_profile", durham.clone(), 2),
        ],
        observations: vec![
            observation(
                "rust_project",
                rust,
                EntityKind::Person,
                "Andrew Gallant",
                "Rust Project governance member; GitHub handle BurntSushi",
            ),
            observation(
                "rust_project",
                origin(
                    "rust_project",
                    "governance_team",
                    "https://rust-lang.org/governance/teams/library/",
                ),
                EntityKind::Username,
                "BurntSushi",
                "GitHub handle bound to Andrew Gallant by the Rust Project",
            ),
            observation(
                "github_profile",
                github,
                EntityKind::Person,
                "Andrew Gallant",
                "Public GitHub profile for BurntSushi",
            ),
            observation(
                "github_profile",
                origin(
                    "github_public_profile",
                    "burntsushi",
                    "https://github.com/BurntSushi",
                ),
                EntityKind::Document,
                "ripgrep",
                "Pinned public project on the BurntSushi profile",
            ),
            observation(
                "durham_profile",
                durham,
                EntityKind::Person,
                "Andrew Gallant",
                "Professor of Electronic Engineering",
            ),
            observation(
                "durham_profile",
                origin(
                    "durham_university",
                    "staff_profile",
                    "https://dur.ac.uk/staff/a-j-gallant/",
                ),
                EntityKind::Organisation,
                "Durham University",
                "Employer on the public staff profile",
            ),
        ],
        truncated: false,
    }
}

fn person_from_source<'a>(snapshot: &'a AnalysisSnapshot, source: &str) -> &'a Entity {
    snapshot
        .entities
        .iter()
        .find(|entity| {
            entity.kind == EntityKind::Person
                && entity
                    .evidence
                    .iter()
                    .any(|evidence| evidence.provenance.source == source)
        })
        .unwrap_or_else(|| panic!("missing person candidate from {source}"))
}

fn evidence_node(entity: &Entity) -> EvidenceNodeId {
    entity
        .evidence
        .first()
        .and_then(|evidence| evidence.ancestry_node.clone())
        .expect("person candidate must retain ancestry")
}

fn only_root(snapshot: &AnalysisSnapshot, node: &EvidenceNodeId) -> EvidenceNodeId {
    let roots = snapshot
        .ancestry
        .resolved_root_ids(node)
        .expect("captured ancestry must resolve");
    assert_eq!(roots.len(), 1, "each captured public source has one root");
    roots.into_iter().next().expect("length checked")
}

#[test]
fn live_public_homonyms_survive_collection_and_only_evidence_backed_pair_merges() {
    let mut snapshot =
        normalize_observations(captured_public_homonyms(), &PipelineLimits::default())
            .expect("captured public observations must normalize");

    let people = snapshot
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person && entity.value == "andrew gallant")
        .collect::<Vec<_>>();
    assert_eq!(
        people.len(),
        3,
        "three source observations must remain three candidates before resolution"
    );
    assert!(
        snapshot.relations.iter().all(|relation| {
            !people.iter().any(|person| person.uid == relation.from_uid)
                || !people.iter().any(|person| person.uid == relation.to_uid)
        }),
        "canonical-name equality must not emit a person-to-person identity edge"
    );

    let rust = person_from_source(&snapshot, "rust_project governance_team");
    let github = person_from_source(&snapshot, "github_public_profile burntsushi");
    let durham = person_from_source(&snapshot, "durham_university staff_profile");

    let rust_uid = rust.uid.clone();
    let github_uid = github.uid.clone();
    let durham_uid = durham.uid.clone();
    let rust_node = evidence_node(rust);
    let github_node = evidence_node(github);
    let durham_node = evidence_node(durham);
    let rust_root = only_root(&snapshot, &rust_node);
    let github_root = only_root(&snapshot, &github_node);

    snapshot
        .ancestry
        .insert_independence_evidence(IndependenceEvidence {
            left_root: rust_root,
            right_root: github_root,
            basis: IndependenceBasis::ExplicitUpstreamProvenance,
            method_id: "benchmark:public-primary-origins".to_string(),
            method_version: 1,
            supporting_artifact_ids: BTreeSet::from([
                ArtifactId::from("url:https://rust-lang.org/governance/teams/library/"),
                ArtifactId::from("url:https://github.com/BurntSushi"),
            ]),
            observed_at_unix: 1_760_000_000,
        })
        .expect("independence proof must be admissible");

    let rust_github = IdentityResolutionDecision {
        left_entity_uid: rust_uid.clone(),
        right_entity_uid: github_uid.clone(),
        state: ResolutionState::Match,
        probability: Some(0.99),
        supporting: vec![rust_node.clone(), github_node],
        contradicting: Vec::new(),
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1_760_000_002,
    };
    let rust_durham = IdentityResolutionDecision {
        left_entity_uid: rust_uid.clone(),
        right_entity_uid: durham_uid.clone(),
        state: ResolutionState::NonMatch,
        probability: Some(0.01),
        supporting: vec![rust_node, durham_node],
        contradicting: Vec::new(),
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1_760_000_002,
    };

    assert!(
        rust_github.allows_automatic_merge(&snapshot.ancestry, AutoMergePolicy::default()),
        "the independently supported Rust/GitHub identity must pass the merge gate"
    );
    assert!(
        !rust_durham.allows_automatic_merge(&snapshot.ancestry, AutoMergePolicy::default()),
        "the Durham homonym must remain separate"
    );

    let clusters = automatic_clusters(
        &[rust_github, rust_durham],
        &snapshot.ancestry,
        AutoMergePolicy::default(),
    );

    assert_eq!(clusters.len(), 2, "resolution must finish with two real people");
    assert!(clusters.iter().any(|cluster| {
        cluster.members.len() == 2
            && cluster.members.contains(&rust_uid)
            && cluster.members.contains(&github_uid)
    }));
    assert!(clusters.iter().any(|cluster| {
        cluster.members.len() == 1 && cluster.members.contains(&durham_uid)
    }));
}
