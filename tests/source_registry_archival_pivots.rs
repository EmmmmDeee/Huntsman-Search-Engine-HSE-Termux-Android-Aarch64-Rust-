//! Offline regression contracts for public archival pivot routes.
use huntsman_recon::EntityKind;
use huntsman_recon::source_registry::{EvidenceRole, ExecutionMode, SourceAccess, routes_for};

const ARCHIVE_IDS: &[&str] = &[
    "au_qld_bdm_history",
    "au_qld_archives",
    "au_slq_history",
    "au_naa_namesearch",
    "au_austlii",
    "uk_tna_discovery",
    "global_familysearch_index",
];

#[test]
fn historical_routes_are_bounded_provenance_leads_not_identity_evidence() {
    for kind in [EntityKind::Person, EntityKind::Organisation] {
        let routes = routes_for(&kind, "W Bramston");
        for id in ARCHIVE_IDS {
            let route = routes.iter().find(|route| route.source_id == *id)
                .unwrap_or_else(|| panic!("missing archival source {id}"));
            assert_eq!(route.evidence_role, EvidenceRole::LeadOnly, "{id}");
            assert_eq!(route.execution, ExecutionMode::SearchUrl, "{id}");
            assert!(route.url.starts_with("https://"), "{id}");
            assert!(route.reference_url.starts_with("https://"), "{id}");
            assert!(route.url.contains("W%20Bramston"), "{id}");
            assert!(!route.url.contains("W Bramston"), "{id}");
            let access = if *id == "global_familysearch_index" {
                SourceAccess::Account
            } else {
                SourceAccess::Public
            };
            assert_eq!(route.access, access, "{id}");
        }
        let uk = routes.iter().find(|route| route.source_id == "uk_tna_discovery").unwrap();
        assert_eq!(uk.url,
            "https://discovery.nationalarchives.gov.uk/advanced-search?_q=W%20Bramston");
    }
}

#[test]
fn archival_pivots_never_accept_credentials_or_network_identifiers() {
    for kind in [
        EntityKind::Email,
        EntityKind::Username,
        EntityKind::Domain,
        EntityKind::IpAddress,
        EntityKind::Credential,
        EntityKind::ApiKey,
        EntityKind::DeviceId,
    ] {
        assert!(!routes_for(&kind, "example.org").iter().any(|route| {
            ARCHIVE_IDS.contains(&route.source_id)
        }), "{kind:?}");
    }
}

#[test]
fn malformed_raw_selectors_are_refused_before_url_emission() {
    for selector in [
        "W Bramston\\n",
        "\\tW Bramston",
        "W\\rBramston",
        "W\\u{0000}Bramston",
    ] {
        let raw = selector.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r").replace("\\u{0000}", "\u{0000}");
        assert!(routes_for(&EntityKind::Person, &raw).is_empty(), "{raw:?}");
    }
    assert!(routes_for(&EntityKind::Person, &"x".repeat(513)).is_empty());
    assert!(routes_for(&EntityKind::Person, &"é".repeat(257)).is_empty());
    assert!(!routes_for(&EntityKind::Person, "W Bramston").is_empty());
}
