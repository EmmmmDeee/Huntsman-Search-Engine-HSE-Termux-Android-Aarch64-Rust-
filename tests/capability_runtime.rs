use huntsman_recon::capability::{
    AccessClass, CapabilityDescriptor, CapabilityRegistry, EvidenceRole, RegistryError,
    RetrievalMode, ValueTransform, VerificationLevel,
};
use huntsman_recon::dependency::ModuleCategory;
use huntsman_recon::entity::EntityKind;

const USERNAME: &[EntityKind] = &[EntityKind::Username];
const DOMAIN: &[EntityKind] = &[EntityKind::Domain];

fn pivot(
    id: &'static str,
    category: ModuleCategory,
    kinds: &'static [EntityKind],
    transform: ValueTransform,
    template: &'static str,
) -> CapabilityDescriptor {
    CapabilityDescriptor {
        id,
        name: id,
        category,
        accepted_kinds: kinds,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some(template),
        reference_url: "https://example.test/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    }
}

#[test]
fn source_specific_username_transforms_do_not_destroy_query_semantics() {
    let exact = pivot(
        "exact",
        ModuleCategory::Search,
        USERNAME,
        ValueTransform::Preserve,
        "https://search.example/?q=%22{value}%22",
    );
    let github = pivot(
        "github",
        ModuleCategory::Social,
        USERNAME,
        ValueTransform::BareUsername,
        "https://github.com/search?q={value}&type=users",
    );
    let registry = CapabilityRegistry::new(&[exact, github]).expect("valid registry");

    let routes = registry.routes_for(&EntityKind::Username, "@octocat");
    assert_eq!(routes.len(), 2);
    assert_eq!(
        routes
            .iter()
            .find(|route| route.capability_id == "exact")
            .expect("exact route")
            .url,
        "https://search.example/?q=%22%40octocat%22"
    );
    assert_eq!(
        routes
            .iter()
            .find(|route| route.capability_id == "github")
            .expect("github route")
            .url,
        "https://github.com/search?q=octocat&type=users"
    );
}

#[test]
fn provider_specific_domain_routes_receive_the_canonical_domain() {
    let whois = pivot(
        "whois",
        ModuleCategory::Infrastructure,
        DOMAIN,
        ValueTransform::CanonicalDomain,
        "https://whois.example/{value}",
    );
    let registry = CapabilityRegistry::new(&[whois]).expect("valid registry");

    let routes = registry.routes_for(&EntityKind::Domain, "EXAMPLE.com.");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].url, "https://whois.example/example.com");
}

#[test]
fn pivot_only_capabilities_can_never_claim_evidence_bearing_output() {
    let mut invalid = pivot(
        "bad-pivot",
        ModuleCategory::Search,
        DOMAIN,
        ValueTransform::CanonicalDomain,
        "https://search.example/{value}",
    );
    invalid.evidence_role = EvidenceRole::EvidenceBearing;

    assert!(matches!(
        CapabilityRegistry::new(&[invalid]),
        Err(RegistryError::PivotMustBeLeadOnly("bad-pivot"))
    ));
}

#[test]
fn duplicate_ids_are_rejected_before_the_registry_can_count_them_as_coverage() {
    let first = pivot(
        "duplicate",
        ModuleCategory::Search,
        DOMAIN,
        ValueTransform::CanonicalDomain,
        "https://one.example/{value}",
    );
    let second = pivot(
        "duplicate",
        ModuleCategory::Infrastructure,
        DOMAIN,
        ValueTransform::CanonicalDomain,
        "https://two.example/{value}",
    );

    assert!(matches!(
        CapabilityRegistry::new(&[first, second]),
        Err(RegistryError::DuplicateId("duplicate"))
    ));
}

#[test]
fn pivot_routes_expose_their_non_evidentiary_and_verification_state() {
    let route = pivot(
        "domain-pivot",
        ModuleCategory::Search,
        DOMAIN,
        ValueTransform::CanonicalDomain,
        "https://search.example/{value}",
    );
    let registry = CapabilityRegistry::new(&[route]).expect("valid registry");
    let routes = registry.routes_for(&EntityKind::Domain, "example.com");

    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].mode, RetrievalMode::PivotOnly);
    assert_eq!(routes[0].evidence_role, EvidenceRole::LeadOnly);
    assert_eq!(routes[0].verification, VerificationLevel::ReferenceOnly);
}
