//! Module registry. Adding a new module is a one-file change:
//!   1. Create `src/modules/foo.rs` implementing `Module`.
//!   2. `pub mod foo;` here.
//!   3. Push `Arc::new(foo::Foo)` into `registry()`.
//!
//! Nothing else in the codebase needs to know about the new module.

pub mod abuseipdb;
pub mod alienvault_otx;
pub mod arp_scan;
pub mod bgpview;
pub mod caa_records;
pub mod cell_survey;
pub mod criminal_ip;
pub mod crtsh;
pub mod dehashed;
pub mod dns_brute;
pub mod dns_resolver;
pub mod email_to_username;
pub mod emailrep;
pub mod fullhunt;
pub mod github_user;
pub mod gps_fix;
pub mod gravatar;
pub mod greynoise;
pub mod haveibeenpwned;
pub mod hudsonrock;
pub mod intelx;
pub mod ip2location;
pub mod ip_geo;
pub mod ip_rdap;
pub mod ipinfo;
pub mod ipqs;
pub mod leakix;
pub mod name_to_email;
pub mod net_interfaces;
pub mod nominatim;
pub mod numverify;
pub mod oathnet_pro;
pub mod phone_intl;
pub mod rdap_domain;
pub mod reverse_dns;
pub mod securitytrails;
pub mod shodan;
pub mod shodan_internetdb;
pub mod threatfox;
pub mod tor_exit_check;
pub mod urlhaus;
pub mod username_search;
pub mod wayback;
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
        // Threat intel — abuse.ch ThreatFox IOC search. Key-gated via
        // HUNTSMAN_THREATFOX_KEY (free to register; required on every
        // request per https://threatfox.abuse.ch/api).
        Arc::new(threatfox::ThreatFox),
        // Shodan InternetDB — free, anonymous port/CVE/hostname lookup.
        Arc::new(shodan_internetdb::ShodanInternetDb),
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
        // DNS CAA — certificate-authority authorization policy.
        Arc::new(caa_records::CaaRecords),
        // Subdomain enumeration via a bounded common-name dictionary.
        Arc::new(dns_brute::DnsBrute),
        Arc::new(whois::Whois),
        // RDAP registry view of an IP (complements whois + bgpview).
        Arc::new(ip_rdap::IpRdap),
        // RDAP registry view of a Domain (structured complement to whois).
        Arc::new(rdap_domain::RdapDomain),
        Arc::new(ip_geo::IpGeo),
        // Tor exit-relay membership check (free, single fetch cached).
        Arc::new(tor_exit_check::TorExitCheck),
        // Web stack fingerprint via HEAD on the domain's homepage.
        Arc::new(webserver_banner::WebserverBanner),
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
        // ── People-centric ──
        Arc::new(emailrep::EmailRep),
        Arc::new(haveibeenpwned::HaveIBeenPwned),
        Arc::new(name_to_email::NameToEmail),
        // ── Geolocation ──
        Arc::new(ipinfo::IpInfo),
        Arc::new(ip2location::Ip2Location),
        Arc::new(nominatim::Nominatim),
        // ── IP abuse / threat intel ──
        Arc::new(abuseipdb::AbuseIpDb),
        Arc::new(greynoise::GreyNoise),
        // ── Attack surface discovery ──
        Arc::new(fullhunt::FullHunt),
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
