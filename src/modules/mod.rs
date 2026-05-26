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
pub mod cell_survey;
pub mod criminal_ip;
pub mod crtsh;
pub mod dehashed;
pub mod dns_blocklist;
pub mod dns_brute;
pub mod dns_resolver;
pub mod email_to_domain;
pub mod email_to_username;
pub mod forward_geocode;
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
pub mod reverse_geocode;
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
pub mod wifi_scan;
pub mod wigle;
pub mod xposed_or_not;

use std::sync::Arc;

use crate::core::module::Module;

/// Built-in module set. The engine sorts by priority — order here is irrelevant.
pub fn registry() -> Vec<Arc<dyn Module>> {
    vec![
        // Identity / breach / infrastructure (v0.1 → v0.4)
        Arc::new(hudsonrock::HudsonRock),
        Arc::new(xposed_or_not::XposedOrNot),
        Arc::new(alienvault_otx::AlienVaultOtx),
        // Paid premium breach search (v0.10+). Key-gated via
        // HUNTSMAN_OATHNET_KEY; engine emits ModuleError and moves on
        // if the key is absent or the request fails.
        Arc::new(oathnet_pro::OathnetPro),
        // Threat intel — abuse.ch URLhaus host check (free, no key).
        Arc::new(urlhaus::UrlHaus),
        // Paid / key-gated integrations (v0.11+). Each silently no-ops
        // when its key is missing — engine emits ModuleError once and
        // moves on so the rest of the scan still proceeds.
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
        // Subdomain enumeration via a bounded common-name dictionary.
        Arc::new(dns_brute::DnsBrute),
        Arc::new(whois::Whois),
        // RDAP registry view of an IP (complements whois + bgpview).
        Arc::new(ip_rdap::IpRdap),
        Arc::new(ip_geo::IpGeo),
        // Second-source HTTPS IP geolocation (ipwho.is). Two independent
        // geo sources on the same IP let AU-014 geo-cluster fire.
        Arc::new(ip_whois_geo::IpWhois),
        // Reverse geocoding via OpenStreetMap Nominatim — converts
        // Coordinates entities from ip_geo/gps_fix into Address entities
        // with country, state, city, street. Free, no API key.
        Arc::new(reverse_geocode::ReverseGeocode),
        // Forward geocoding — Address text to GPS coordinates via
        // OSM Nominatim. Closes the geo loop: Address → Coordinates.
        Arc::new(forward_geocode::ForwardGeocode),
        // Tor exit-relay membership check (free, single fetch cached).
        Arc::new(tor_exit_check::TorExitCheck),
        // DNS blocklist (DNSBL) checker — pure DNS queries against 8
        // blocklists (Spamhaus, SpamCop, SORBS, etc.). Zero API keys.
        Arc::new(dns_blocklist::DnsBlocklist),
        // SSL/TLS certificate probe — extracts SANs, issuer, validity.
        // SAN discovery reveals subdomains not visible via DNS/CT. Free.
        Arc::new(ssl_probe::SslProbe),
        // Free OSINT modules from PR #34 (re-implemented against current main).
        Arc::new(shodan_internetdb::ShodanInternetDb),
        Arc::new(caa_records::CaaRecords),
        Arc::new(threatfox::ThreatFox),
        Arc::new(rdap_domain::RdapDomain),
        // Multi-engine search scraping (13 engines: Yahoo, Bing, AOL,
        // DuckDuckGo, Google, Brave, Mojeek, Startpage, Yandex, Ecosia,
        // Qwant, Dogpile, Swisscows) — discovers subdomains, linked
        // domains, emails from search result URLs and snippets. Zero
        // API keys.
        Arc::new(search_engines::SearchEngines),
        // Web stack fingerprint via HEAD on the domain's homepage.
        Arc::new(webserver_banner::WebserverBanner),
        // Recursive BFS web crawler — link discovery, content extraction,
        // framework fingerprinting, page classification, security header
        // audit. Supersedes SpiderFoot's sfp_spider + sfp_pageinfo +
        // sfp_webframework + sfp_webserver in a single async module.
        Arc::new(web_crawler::WebCrawler),
        Arc::new(email_to_domain::EmailToDomain),
        Arc::new(email_to_username::EmailToUsername),
        // Direct social profile probing — HEAD/GET 20+ platforms to
        // confirm profile existence. Uses curl for TLS compatibility.
        Arc::new(social_probe::SocialProbe),
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
        // Australian Business Register lookup — ABN/ACN/name search.
        // Key-gated via HUNTSMAN_ABR_GUID (free registration).
        Arc::new(abn_lookup::AbnLookup),
        // API key identification — probes a raw key against 17+ service
        // endpoints, identifies the service, extracts account metadata,
        // and auto-stores valid keys in the key pool.
        Arc::new(api_key_probe::ApiKeyProbe),
    ]
}
