use std::collections::BTreeMap;

use huntsman_recon::collection::{
    CollectionEvent, ObservationBatch, RawObservation, UpstreamOrigin,
};
use huntsman_recon::dependency::{Target, TargetKind};
use huntsman_recon::entity::EntityKind;
use huntsman_recon::pipeline::{PipelineLimits, normalize_observations};
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

/// Captured from public pages verified on 2026-10-07:
/// - Rust Project team pages bind Andrew Gallant to GitHub handle BurntSushi.
/// - Durham University identifies a different Andrew Gallant as Professor of Electronic Engineering.
/// The benchmark is intentionally a homonym collision: a resolver must preserve two candidate
/// identities until evidence-backed resolution proves a merge.
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
                "Rust Project team member",
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

#[test]
fn live_captured_same_name_people_do_not_collapse_before_resolution() {
    let snapshot = normalize_observations(captured_public_homonyms(), &PipelineLimits::default())
        .expect("captured public observations must normalize");

    let people = snapshot
        .entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Person && entity.value == "andrew gallant")
        .collect::<Vec<_>>();

    assert_eq!(
        people.len(),
        2,
        "two independently evidenced real people with the same normalized name must remain separate candidates before identity resolution"
    );

    assert!(
        people.iter().all(|person| person.evidence.len() < 3),
        "evidence from the Rust/GitHub identity and Durham identity must not be silently fused into one person entity"
    );
}
