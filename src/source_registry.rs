//! Curated pivot capabilities.
//!
//! This module owns only the bootstrap catalogue. Runtime semantics, validation,
//! transformations and route rendering are owned by `crate::capability` so adding a
//! source cannot create a second execution/evidence contract.

use crate::capability::{
    AccessClass, CapabilityDescriptor, CapabilityRegistry, CapabilityRoute, EvidenceRole,
    RetrievalMode, ValueTransform, VerificationLevel,
};
use crate::dependency::ModuleCategory;
use crate::entity::EntityKind;

const IDENTITY_SEARCH: &[EntityKind] = &[
    EntityKind::Person,
    EntityKind::Organisation,
    EntityKind::Email,
    EntityKind::Username,
];
const DOMAIN_ONLY: &[EntityKind] = &[EntityKind::Domain];
const IP_ONLY: &[EntityKind] = &[EntityKind::IpAddress];
const USERNAME_ONLY: &[EntityKind] = &[EntityKind::Username];
const COORDINATES_ONLY: &[EntityKind] = &[EntityKind::Coordinates];

/// Independently curated bootstrap pivots. `ReferenceOnly` is deliberate: a prior
/// browser/curl observation does not establish current production-path execution.
static CAPABILITIES: &[CapabilityDescriptor] = &[
    CapabilityDescriptor {
        id: "google_exact",
        name: "Google exact search",
        category: ModuleCategory::Search,
        accepted_kinds: IDENTITY_SEARCH,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::Preserve,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://www.google.com/search?q=%22{value}%22"),
        reference_url: "https://www.google.com/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "bing_exact",
        name: "Bing exact search",
        category: ModuleCategory::Search,
        accepted_kinds: IDENTITY_SEARCH,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::Preserve,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://www.bing.com/search?q=%22{value}%22"),
        reference_url: "https://www.bing.com/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "google_site",
        name: "Google site search",
        category: ModuleCategory::Search,
        accepted_kinds: DOMAIN_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::CanonicalDomain,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://www.google.com/search?q=site%3A{value}"),
        reference_url: "https://www.google.com/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "wayback",
        name: "Internet Archive Wayback Machine",
        category: ModuleCategory::Web,
        accepted_kinds: DOMAIN_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::CanonicalDomain,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://web.archive.org/web/*/{value}/*"),
        reference_url: "https://web.archive.org/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "whois",
        name: "Whois.com",
        category: ModuleCategory::Infrastructure,
        accepted_kinds: DOMAIN_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::CanonicalDomain,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://www.whois.com/whois/{value}"),
        reference_url: "https://www.whois.com/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "crtsh",
        name: "crt.sh certificate search",
        category: ModuleCategory::Infrastructure,
        accepted_kinds: DOMAIN_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::CanonicalDomain,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://crt.sh/?q=%25.{value}"),
        reference_url: "https://crt.sh/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "urlscan",
        name: "urlscan.io domain search",
        category: ModuleCategory::Web,
        accepted_kinds: DOMAIN_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::CanonicalDomain,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://urlscan.io/search/#domain:{value}"),
        reference_url: "https://urlscan.io/search/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "shodan_host",
        name: "Shodan host view",
        category: ModuleCategory::Infrastructure,
        accepted_kinds: IP_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::Preserve,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://www.shodan.io/host/{value}"),
        reference_url: "https://www.shodan.io/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "bgp_he",
        name: "Hurricane Electric BGP Toolkit",
        category: ModuleCategory::Infrastructure,
        accepted_kinds: IP_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::Preserve,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://bgp.he.net/ip/{value}"),
        reference_url: "https://bgp.he.net/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "github_users",
        name: "GitHub user search",
        category: ModuleCategory::Social,
        accepted_kinds: USERNAME_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::BareUsername,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://github.com/search?q={value}&type=users"),
        reference_url: "https://github.com/",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
    CapabilityDescriptor {
        id: "google_maps",
        name: "Google Maps coordinates",
        category: ModuleCategory::Geo,
        accepted_kinds: COORDINATES_ONLY,
        emitted_kinds: &[],
        mode: RetrievalMode::PivotOnly,
        access: AccessClass::Public,
        transform: ValueTransform::Preserve,
        evidence_role: EvidenceRole::LeadOnly,
        route_template: Some("https://www.google.com/maps?q={value}"),
        reference_url: "https://www.google.com/maps",
        verification: VerificationLevel::ReferenceOnly,
        verified_at_unix: None,
    },
];

#[must_use]
pub fn registry() -> CapabilityRegistry {
    CapabilityRegistry::new(CAPABILITIES).expect("static source capability registry is valid")
}

#[must_use]
pub fn routes_for(kind: &EntityKind, value: &str) -> Vec<CapabilityRoute> {
    registry().routes_for(kind, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_valid_https_and_pivot_only() {
        let registry = registry();
        assert_eq!(registry.capabilities().len(), CAPABILITIES.len());
        for capability in registry.capabilities() {
            assert!(capability.reference_url.starts_with("https://"));
            assert!(
                capability
                    .route_template
                    .expect("pivot template")
                    .starts_with("https://")
            );
            assert_eq!(capability.mode, RetrievalMode::PivotOnly);
            assert_eq!(capability.evidence_role, EvidenceRole::LeadOnly);
            assert_eq!(capability.verification, VerificationLevel::ReferenceOnly);
        }
    }

    #[test]
    fn domain_fans_out_without_turning_routes_into_evidence() {
        let routes = routes_for(&EntityKind::Domain, "example.com");
        assert_eq!(routes.len(), 5);
        assert!(
            routes
                .iter()
                .all(|route| route.evidence_role == EvidenceRole::LeadOnly)
        );
        assert!(routes.iter().any(|route| route.capability_id == "wayback"));
        assert!(routes.iter().any(|route| route.capability_id == "crtsh"));
    }

    #[test]
    fn username_transforms_are_source_specific() {
        let routes = routes_for(&EntityKind::Username, "@octocat");
        let github = routes
            .iter()
            .find(|route| route.capability_id == "github_users")
            .expect("github_users route");
        let google = routes
            .iter()
            .find(|route| route.capability_id == "google_exact")
            .expect("google_exact route");
        assert_eq!(github.url, "https://github.com/search?q=octocat&type=users");
        assert_eq!(
            google.url,
            "https://www.google.com/search?q=%22%40octocat%22"
        );
    }

    #[test]
    fn malformed_handles_yield_no_routes() {
        assert_eq!(routes_for(&EntityKind::Username, "@"), []);
        assert_eq!(routes_for(&EntityKind::Username, "@@octocat"), []);
        assert_eq!(routes_for(&EntityKind::Username, "@ada lovelace"), []);
    }

    #[test]
    fn coordinates_route_to_maps() {
        let routes = routes_for(&EntityKind::Coordinates, "-27.4698,153.0251");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].capability_id, "google_maps");
        assert_eq!(
            routes[0].url,
            "https://www.google.com/maps?q=-27.4698%2C153.0251"
        );
    }

    #[test]
    fn human_query_is_rfc3986_encoded() {
        let routes = routes_for(&EntityKind::Person, "Ada Lovelace");
        assert_eq!(routes.len(), 2);
        assert!(
            routes
                .iter()
                .all(|route| route.url.contains("Ada%20Lovelace"))
        );
        assert!(
            routes
                .iter()
                .all(|route| !route.url.contains("Ada Lovelace"))
        );
    }
}
