//! Module registry. Adding a new module is a one-file change:
//!   1. Create `src/modules/foo.rs` implementing `Module`.
//!   2. `pub mod foo;` here.
//!   3. Push `Arc::new(foo::Foo)` into `registry()`.
//!
//! Nothing else in the codebase needs to know about the new module.

pub mod abn_lookup;
pub mod alienvault_otx;
pub mod api_key_probe;
pub mod arp_scan;
pub mod bgpview;
pub mod caa_records;
pub mod cell_intel;
pub mod criminal_ip;
pub mod crtsh;
pub mod dehashed;
pub mod dns_blocklist;
pub mod dns_brute;
pub mod dns_resolver;
pub mod email_parse;
pub mod geo_intel;
pub mod geocode;
pub mod github_user;
pub mod gps_fix;
pub mod gravatar;
pub mod hudsonrock;
pub mod intelx;
pub mod ip_geo;
pub mod ip_rdap;
pub mod ip_whois_geo;
pub mod ipqs;
pub mod leakix;
pub mod net_interfaces;
pub mod numverify;
pub mod oathnet_pro;
pub mod phone_intl;
pub mod rdap_domain;
pub mod reverse_dns;
pub mod search_engines;
pub mod securitytrails;
pub mod shodan;
pub mod shodan_internetdb;
pub mod social_probe;
pub mod ssl_probe;
pub mod threatfox;
pub mod tor_exit_check;
pub mod urlhaus;
pub mod username_search;
pub mod wayback;
pub mod web_crawler;
pub mod webserver_banner;
pub mod whois;
pub mod wifi_connect;
pub mod wifi_intel;
pub mod wigle;
pub mod xposed_or_not;

use std::sync::Arc;

use crate::core::module::Module;

/// Built-in module set. The engine sorts by priority — order here is irrelevant.
pub fn registry() -> Vec<Arc<dyn Module>> {
    vec![
        Arc::new(hudsonrock::HudsonRock),
        Arc::new(xposed_or_not::XposedOrNot),
        Arc::new(alienvault_otx::AlienVaultOtx),
        Arc::new(oathnet_pro::OathnetPro),
        Arc::new(urlhaus::UrlHaus),
        Arc::new(shodan::Shodan),
        Arc::new(dehashed::DeHashed),
        Arc::new(intelx::IntelX),
        Arc::new(securitytrails::SecurityTrails),
        Arc::new(leakix::LeakIx),
        Arc::new(criminal_ip::CriminalIp),
        Arc::new(ipqs::IpQs),
        Arc::new(numverify::Numverify),
        Arc::new(wigle::Wigle),
        Arc::new(crtsh::Crtsh),
        Arc::new(dns_resolver::DnsResolver),
        Arc::new(reverse_dns::ReverseDns),
        Arc::new(dns_brute::DnsBrute),
        Arc::new(whois::Whois),
        Arc::new(ip_rdap::IpRdap),
        Arc::new(ip_geo::IpGeo),
        Arc::new(ip_whois_geo::IpWhois),
        Arc::new(geo_intel::GeoIntel),
        // Bidirectional geocoding (Address ↔ Coordinates) via Nominatim.
        // Replaces the former forward_geocode + reverse_geocode pair.
        Arc::new(geocode::Geocode),
        Arc::new(tor_exit_check::TorExitCheck),
        Arc::new(dns_blocklist::DnsBlocklist),
        Arc::new(ssl_probe::SslProbe),
        Arc::new(shodan_internetdb::ShodanInternetDb),
        Arc::new(caa_records::CaaRecords),
        Arc::new(threatfox::ThreatFox),
        Arc::new(rdap_domain::RdapDomain),
        Arc::new(search_engines::SearchEngines),
        Arc::new(webserver_banner::WebserverBanner),
        Arc::new(web_crawler::WebCrawler),
        // Email parsing: domain extraction + username derivation in one pass.
        // Replaces the former email_to_domain + email_to_username pair.
        Arc::new(email_parse::EmailParse),
        Arc::new(social_probe::SocialProbe),
        Arc::new(username_search::UsernameSearch),
        Arc::new(github_user::GithubUser),
        Arc::new(gravatar::Gravatar),
        Arc::new(phone_intl::PhoneIntl),
        Arc::new(bgpview::BgpView),
        Arc::new(wayback::Wayback),
        Arc::new(wifi_connect::WifiConnect),
        Arc::new(gps_fix::GpsFix),
        // Cell tower survey + geolocation in one pass (single termux call).
        // Replaces the former cell_survey + cell_locate pair.
        Arc::new(cell_intel::CellIntel),
        // WiFi AP survey + BSSID geolocation in one pass (single termux call).
        // Replaces the former wifi_scan + bssid_locate pair.
        Arc::new(wifi_intel::WifiIntel),
        Arc::new(arp_scan::ArpScan),
        Arc::new(net_interfaces::NetInterfaces),
        Arc::new(abn_lookup::AbnLookup),
        Arc::new(api_key_probe::ApiKeyProbe),
    ]
}
