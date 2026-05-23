//! Module registry. Adding a new module is a one-file change:
//!   1. Create `src/modules/foo.rs` implementing `Module`.
//!   2. `pub mod foo;` here.
//!   3. Push `Arc::new(foo::Foo)` into `registry()`.
//!
//! Nothing else in the codebase needs to know about the new module.

pub mod alienvault_otx;
pub mod arp_scan;
pub mod bgpview;
pub mod cell_survey;
pub mod crtsh;
pub mod dns_resolver;
pub mod email_to_username;
pub mod github_user;
pub mod gps_fix;
pub mod gravatar;
pub mod hudsonrock;
pub mod ip_geo;
pub mod net_interfaces;
pub mod phone_intl;
pub mod reverse_dns;
pub mod username_search;
pub mod wayback;
pub mod whois;
pub mod wifi_connect;
pub mod wifi_scan;

use std::sync::Arc;

use crate::core::module::Module;

/// Built-in module set. The engine sorts by priority — order here is irrelevant.
pub fn registry() -> Vec<Arc<dyn Module>> {
    vec![
        // Identity / breach / infrastructure (v0.1 → v0.4)
        Arc::new(hudsonrock::HudsonRock),
        Arc::new(alienvault_otx::AlienVaultOtx),
        Arc::new(crtsh::Crtsh),
        Arc::new(dns_resolver::DnsResolver),
        Arc::new(reverse_dns::ReverseDns),
        Arc::new(whois::Whois),
        Arc::new(ip_geo::IpGeo),
        Arc::new(email_to_username::EmailToUsername),
        // Username / identity expansion (sherlock/Maigret-style)
        Arc::new(username_search::UsernameSearch),
        Arc::new(github_user::GithubUser),
        // Email identity
        Arc::new(gravatar::Gravatar),
        // Phone metadata (offline)
        Arc::new(phone_intl::PhoneIntl),
        // ASN / BGP
        Arc::new(bgpview::BgpView),
        // Domain history
        Arc::new(wayback::Wayback),
        // Termux sensors (v0.6+). Accept any target, is_passive=true.
        // Off-device they no-op cleanly via the termux_cmd helper.
        Arc::new(wifi_connect::WifiConnect),
        Arc::new(gps_fix::GpsFix),
        Arc::new(wifi_scan::WifiScan),
        Arc::new(cell_survey::CellSurvey),
        Arc::new(arp_scan::ArpScan),
        Arc::new(net_interfaces::NetInterfaces),
    ]
}
