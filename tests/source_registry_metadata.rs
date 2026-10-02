//! Live-verified source metadata contracts.

use huntsman_recon::EntityKind;
use huntsman_recon::source_registry::{SourceAccess, routes_for};

#[test]
fn urlscan_uses_supported_search_ui_and_records_public_access() {
    let routes = routes_for(&EntityKind::Domain, "example.com");
    let route = routes
        .iter()
        .find(|route| route.source_id == "urlscan")
        .expect("urlscan domain route");

    // Unauthenticated `domain:` search is quota-limited, not login-gated:
    // https://urlscan.io/docs/api/
    assert_eq!(route.access, SourceAccess::Public);
    assert_eq!(route.url, "https://urlscan.io/search/#domain:example.com");
}
