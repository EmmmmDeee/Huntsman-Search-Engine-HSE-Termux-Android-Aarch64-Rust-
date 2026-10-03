//! Source metadata contracts.

use huntsman_recon::EntityKind;
use huntsman_recon::capability::{AccessClass, EvidenceRole, RetrievalMode, VerificationLevel};
use huntsman_recon::source_registry::routes_for;

#[test]
fn urlscan_uses_public_pivot_metadata_without_overclaiming_verification() {
    let routes = routes_for(&EntityKind::Domain, "example.com");
    let route = routes
        .iter()
        .find(|route| route.capability_id == "urlscan")
        .expect("urlscan domain route");

    assert_eq!(route.access, AccessClass::Public);
    assert_eq!(route.mode, RetrievalMode::PivotOnly);
    assert_eq!(route.evidence_role, EvidenceRole::LeadOnly);
    assert_eq!(route.verification, VerificationLevel::ReferenceOnly);
    assert_eq!(route.verified_at_unix, None);
    assert_eq!(route.url, "https://urlscan.io/search/#domain:example.com");
}
