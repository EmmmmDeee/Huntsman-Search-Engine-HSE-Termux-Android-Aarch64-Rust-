//! Live-verified source metadata contracts.

use huntsman_recon::EntityKind;
use huntsman_recon::source_registry::{SourceAccess, routes_for};

#[test]
fn urlscan_uses_supported_search_ui_and_records_account_requirement() {
    let routes = routes_for(&EntityKind::Domain, "example.com");
    let route = routes
        .iter()
        .find(|route| route.source_id == "urlscan")
        .expect("urlscan domain route");

    assert_eq!(route.access, SourceAccess::Account);
    assert_eq!(route.url, "https://urlscan.io/search/#domain:example.com");
}
