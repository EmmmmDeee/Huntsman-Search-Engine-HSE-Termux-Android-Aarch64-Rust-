use huntsman_recon::EntityKind;
use huntsman_recon::capability::{CapabilityRoute, EvidenceRole, RetrievalMode, ValueTransform};
use huntsman_recon::source_registry::{registry, routes_for};

#[test]
fn every_source_route_is_a_registered_pivot_only_lead() {
    let registry = registry();
    assert_ne!(registry.capabilities(), []);
    assert!(registry.capabilities().iter().all(|capability| {
        capability.mode == RetrievalMode::PivotOnly
            && capability.evidence_role == EvidenceRole::LeadOnly
    }));
}

#[test]
fn username_transform_is_owned_by_each_capability_not_the_entity_kind() {
    let routes = routes_for(&EntityKind::Username, "@octocat");
    let google = routes
        .iter()
        .find(|route| route.capability_id == "google_exact")
        .expect("google exact username route");
    let github = routes
        .iter()
        .find(|route| route.capability_id == "github_users")
        .expect("github username route");

    assert!(google.url.contains("%40octocat"), "{}", google.url);
    assert!(
        github.url.contains("q=octocat&type=users"),
        "{}",
        github.url
    );

    let registry = registry();
    let descriptors = registry.capabilities();
    assert_eq!(
        descriptors
            .iter()
            .find(|item| item.id == "google_exact")
            .expect("google descriptor")
            .transform,
        ValueTransform::Preserve
    );
    assert_eq!(
        descriptors
            .iter()
            .find(|item| item.id == "github_users")
            .expect("github descriptor")
            .transform,
        ValueTransform::BareUsername
    );
}

#[test]
fn domain_transforms_are_canonical_before_rendering() {
    let routes = routes_for(&EntityKind::Domain, "EXAMPLE.com.");
    assert_ne!(routes, [] as [CapabilityRoute; 0]);
    assert!(
        routes
            .iter()
            .all(|route| !route.url.contains("EXAMPLE.com.")),
        "{routes:?}"
    );
    assert!(
        routes.iter().all(|route| route.url.contains("example.com")),
        "{routes:?}"
    );
}

#[test]
fn malformed_double_at_username_is_not_guessed() {
    assert_eq!(
        routes_for(&EntityKind::Username, "@@octocat"),
        [] as [CapabilityRoute; 0]
    );
}
