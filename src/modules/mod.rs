//! Module registry. Adding a new module is a one-file change:
//!   1. Create `src/modules/foo.rs` implementing `Module`.
//!   2. `pub mod foo;` here.
//!   3. Push `Arc::new(foo::Foo)` into `registry()`.
//!
//! Nothing else in the codebase needs to know about the new module.

pub mod abn_lookup;
pub mod abuseipdb;
pub mod acnc_charities;
pub mod api_key_probe;
pub mod bgpview;
pub mod breach_timezone;
pub mod cell_intel;
pub mod censys;
pub mod cert_intel;
pub mod chain_intel;
pub mod cloud_storage;
pub mod contact_enrich;
pub mod crates_io;
pub mod criminal_ip;
pub mod crtsh;
pub mod dehashed;
pub mod device_sensors;
pub mod disposable_check;
pub mod dns_axfr;
pub mod dns_intel;
pub mod doh_resolver;
pub mod domainsdb;
pub mod email_canonical;
pub mod email_header_geo;
pub mod email_locale;
pub mod email_parse;
pub mod emailrep;
pub mod employer_pivot;
pub mod epieos;
pub mod exa_search;
pub mod exif_geo;
pub mod fullcontact;
pub mod geo_domain_classifier;
pub mod geo_intel;
pub mod geocode;
pub mod github_user;
pub mod gleif_lei;
pub mod gravatar;
pub mod greynoise;
pub mod hacker_news;
pub mod hackertarget;
pub mod hibp;
pub mod hudsonrock;
pub mod hunter_io;
pub mod intelx;
pub mod ip2location;
pub mod ip_geo;
pub mod ip_registry;
pub mod ip_reputation;
pub mod ip_whois_geo;
pub mod ipapi;
pub mod ipinfo;
pub mod ipqs;
pub mod ipquery;
pub mod keybase;
pub mod leakix;
pub mod local_net;
pub mod mls;
pub mod mylnikov;
pub mod name_intel;
pub mod netblock;
pub mod niamonx;
pub mod npm_author;
pub mod numverify;
pub mod oathnet_pro;
pub mod opencorporates;
pub mod osintcat;
pub mod overpass;
pub mod pgp;
pub mod phone_area_geo;
pub mod phone_carrier_geo;
pub mod phone_intl;
pub mod photon;
pub mod portscan;
pub mod proxycurl;
pub mod psbdmp;
pub mod pwned_passwords;
pub mod qld_unclaimed;
pub mod rdap_domain;
pub mod reddit_user;
pub mod ripestat;
pub mod search_engines;
pub mod securitytrails;
pub mod see_know;
pub mod seon;
pub mod shodan;
pub mod smtp_vrfy;
pub mod social_location;
pub mod social_probe;
pub mod subdomain_takeover;
pub mod sunrise_sunset;
pub mod threatfox;
pub mod typosquat;
pub mod urlhaus;
pub mod urlscan;
pub mod username_search;
pub mod username_variants;
pub mod virustotal;
pub mod waf_detect;
pub mod wayback;
pub mod web_crawler;
pub mod webserver_banner;
pub mod whois;
pub mod whoisxml;
pub mod wifi_intel;
pub mod wigle;
pub mod wikidata;
pub mod xposed_or_not;

use std::sync::Arc;

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::core::module::Module;

/// Reset the foreign-API-key sink at scan start. Re-exported here so
/// `core/engine` can drive it without importing `util` directly — the same
/// architecture-rule shim used for the per-module budget resets (the
/// dependency direction is `core → modules → util`, never `core → util`).
pub fn reset_found_keys() {
    crate::util::found_keys::reset();
}

/// Drain the foreign-API-key sink into first-class `ApiKey` entities for
/// `scan_id`. Lives at the module layer (which may use both `util` and
/// `core::entity`) so the engine's finalisation stays free of any `util`
/// import. Every entry is a recognised vendor key (the sink uses the
/// vendor-only identifier), so all are high-confidence.
pub fn drain_found_key_entities(scan_id: &str) -> Vec<Entity> {
    crate::util::found_keys::drain()
        .into_iter()
        .map(|fk| {
            // A crypto wallet address is identified alongside keys (both are
            // high-entropy tokens) but is a distinct artifact — emit it as a
            // chain-tagged CryptoAddress, never a foreign API key.
            if let Some(chain) = fk.service.strip_prefix("crypto_") {
                let mut e = Entity::new(EntityKind::CryptoAddress, &fk.key, 0.80, scan_id);
                e.tag("crypto-address");
                e.tag("retrieved");
                e.tag(format!("chain:{chain}"));
                e.add_evidence(
                    Evidence::new(
                        "found_keys",
                        format!("{chain} wallet address retrieved from {} data", fk.provider),
                    )
                    .with_attr("chain", chain)
                    .with_attr("source_provider", &fk.provider)
                    .with_attr("source_query", &fk.query)
                    .with_attr("occurrences", fk.count.to_string()),
                );
                return e;
            }
            let mut e = Entity::new(EntityKind::ApiKey, &fk.key, 0.80, scan_id);
            e.tag("api-key");
            e.tag("foreign-key");
            e.tag("retrieved");
            e.tag(format!("service:{}", fk.service));
            e.add_evidence(
                Evidence::new(
                    "found_keys",
                    format!(
                        "Foreign {} API key retrieved from {} data",
                        fk.service, fk.provider
                    ),
                )
                .with_attr("service", &fk.service)
                .with_attr("source_provider", &fk.provider)
                .with_attr("source_query", &fk.query)
                .with_attr("occurrences", fk.count.to_string()),
            );
            e
        })
        .collect()
}

/// Built-in module set. The engine sorts by priority — order here is irrelevant.
pub fn registry() -> Vec<Arc<dyn Module>> {
    vec![
        Arc::new(hibp::Hibp),
        Arc::new(hudsonrock::HudsonRock),
        Arc::new(xposed_or_not::XposedOrNot),
        Arc::new(osintcat::OsintCat),
        Arc::new(niamonx::NiamonX),
        Arc::new(pwned_passwords::PwnedPasswords),
        Arc::new(ip_reputation::IpReputation),
        Arc::new(oathnet_pro::OathnetPro),
        Arc::new(see_know::SeekNow),
        Arc::new(exa_search::ExaSearch),
        Arc::new(urlhaus::UrlHaus),
        Arc::new(shodan::Shodan),
        Arc::new(censys::Censys),
        Arc::new(greynoise::GreyNoise),
        Arc::new(dehashed::DeHashed),
        Arc::new(intelx::IntelX),
        Arc::new(securitytrails::SecurityTrails),
        Arc::new(leakix::LeakIx),
        Arc::new(criminal_ip::CriminalIp),
        Arc::new(ipqs::IpQs),
        Arc::new(contact_enrich::ContactEnrich),
        Arc::new(hunter_io::HunterIo),
        Arc::new(disposable_check::DisposableCheck),
        Arc::new(wigle::Wigle),
        Arc::new(cert_intel::CertIntel),
        Arc::new(crtsh::CrtSh),
        Arc::new(dns_intel::DnsIntel),
        Arc::new(dns_axfr::DnsAxfr),
        Arc::new(smtp_vrfy::SmtpVrfy),
        Arc::new(doh_resolver::DohResolver),
        Arc::new(whois::Whois),
        Arc::new(whoisxml::WhoisXml),
        Arc::new(ip_registry::IpRegistry),
        Arc::new(ip2location::Ip2Location),
        Arc::new(ip_geo::IpGeo),
        Arc::new(ipinfo::IpInfo),
        Arc::new(domainsdb::DomainsDb),
        Arc::new(ipapi::IpApi),
        Arc::new(ipquery::IpQuery),
        Arc::new(ip_whois_geo::IpWhois),
        Arc::new(geo_intel::GeoIntel),
        Arc::new(geocode::Geocode),
        Arc::new(hackertarget::HackerTarget),
        Arc::new(threatfox::ThreatFox),
        Arc::new(rdap_domain::RdapDomain),
        Arc::new(ripestat::RipeStat),
        Arc::new(search_engines::SearchEngines),
        Arc::new(webserver_banner::WebserverBanner),
        Arc::new(web_crawler::WebCrawler),
        Arc::new(urlscan::UrlScan),
        Arc::new(email_parse::EmailParse),
        Arc::new(email_canonical::EmailCanonical),
        Arc::new(employer_pivot::EmployerPivot),
        Arc::new(social_probe::SocialProbe),
        Arc::new(username_search::UsernameSearch),
        Arc::new(username_variants::UsernameVariants),
        Arc::new(github_user::GithubUser),
        Arc::new(hacker_news::HackerNews),
        Arc::new(npm_author::NpmAuthor),
        Arc::new(crates_io::CratesIo),
        Arc::new(reddit_user::RedditUser),
        Arc::new(gravatar::Gravatar),
        Arc::new(pgp::Pgp),
        Arc::new(psbdmp::Psbdmp),
        Arc::new(phone_intl::PhoneIntl),
        Arc::new(wayback::Wayback),
        Arc::new(device_sensors::DeviceSensors),
        Arc::new(cell_intel::CellIntel),
        Arc::new(wifi_intel::WifiIntel),
        Arc::new(local_net::LocalNet),
        Arc::new(abn_lookup::AbnLookup),
        Arc::new(api_key_probe::ApiKeyProbe),
        Arc::new(chain_intel::ChainIntel),
        // OSINT orchestration API modules
        Arc::new(seon::Seon),
        Arc::new(keybase::Keybase),
        Arc::new(emailrep::EmailRep),
        Arc::new(epieos::Epieos),
        Arc::new(proxycurl::Proxycurl),
        Arc::new(fullcontact::FullContact),
        Arc::new(numverify::NumVerify),
        Arc::new(photon::Photon),
        Arc::new(mylnikov::Mylnikov),
        Arc::new(mls::Mls),
        Arc::new(exif_geo::ExifGeo),
        Arc::new(overpass::Overpass),
        Arc::new(sunrise_sunset::SunriseSunset),
        // Geolocation enrichment (passive, zero-API)
        Arc::new(geo_domain_classifier::GeoDomainClassifier),
        Arc::new(email_header_geo::EmailHeaderGeo),
        Arc::new(phone_area_geo::PhoneAreaGeo),
        Arc::new(phone_carrier_geo::PhoneCarrierGeo),
        Arc::new(email_locale::EmailLocale),
        Arc::new(breach_timezone::BreachTimezone),
        // Threat intel & infrastructure
        Arc::new(virustotal::VirusTotal),
        Arc::new(abuseipdb::AbuseIpDb),
        Arc::new(subdomain_takeover::SubdomainTakeover),
        Arc::new(waf_detect::WafDetect),
        Arc::new(cloud_storage::CloudStorage),
        Arc::new(bgpview::BgpView),
        Arc::new(netblock::Netblock),
        Arc::new(portscan::PortScan),
        Arc::new(typosquat::Typosquat),
        // People-centric enrichment
        Arc::new(name_intel::NameIntel),
        Arc::new(social_location::SocialLocation),
        Arc::new(wikidata::Wikidata),
        // Australian + global public-records / corporate registries
        Arc::new(opencorporates::OpenCorporates),
        Arc::new(qld_unclaimed::QldUnclaimed),
        Arc::new(acnc_charities::AcncCharities),
        Arc::new(gleif_lei::GleifLei),
    ]
}

/// The MITRE ATT&CK Reconnaissance (TA0043) techniques *exercised* by a set of
/// evidence-source names — i.e. the collection coverage of an actual scan,
/// resolved from the modules that produced its findings. Sources that are not
/// registered module names (`seed`, `geo_normalize`, `import:dossier`, …)
/// contribute nothing. Deduped and sorted via [`crate::core::attack::coverage`],
/// so the per-scan view and the catalogue view (`hse modules`) agree.
///
/// Lives here, not in `core::attack`, because resolving a source name to its
/// techniques needs the module registry — and `core` may not depend on
/// `modules`. `core::attack` owns the pure technique data; this owns the
/// registry-backed lookup.
#[must_use]
pub fn reconnaissance_coverage<'a>(
    sources: impl IntoIterator<Item = &'a str>,
) -> Vec<&'static crate::core::attack::Technique> {
    use std::collections::HashMap;
    let reg = registry();
    let by_name: HashMap<&str, &'static [&'static str]> = reg
        .iter()
        .map(|m| (m.name(), m.attack_techniques()))
        .collect();
    let ids: Vec<&'static str> = sources
        .into_iter()
        .filter_map(|s| by_name.get(s).copied())
        .flat_map(|slice| slice.iter().copied())
        .collect();
    crate::core::attack::coverage(ids)
}

#[cfg(test)]
mod registry_invariants {
    use super::{reconnaissance_coverage, registry};
    use crate::core::dependency::{ALL_TARGET_KINDS, PROBE_VALUE};
    use crate::core::scan::Target;

    #[test]
    fn reconnaissance_coverage_resolves_real_sources_and_ignores_the_rest() {
        // A scan whose findings came from search_engines + crtsh + a non-module
        // source (`seed`) covers exactly the union of the two real modules'
        // techniques; `seed` contributes nothing.
        let cov = reconnaissance_coverage(["search_engines", "crtsh", "seed"]);
        let ids: Vec<&str> = cov.iter().map(|t| t.id).collect();
        // search_engines (Search) → T1593.002; crtsh (DnsRecon) → cert/DNS/WHOIS.
        assert!(
            ids.contains(&"T1593.002"),
            "search engines technique present"
        );
        assert!(
            ids.contains(&"T1596.003"),
            "crt.sh is digital-certificate recon: {ids:?}"
        );
        // Sorted + deduped, and no phantom entries from the unknown `seed` source.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids, sorted, "coverage must be sorted and deduped");
        // An all-unknown source set yields nothing.
        assert!(reconnaissance_coverage(["seed", "geo_normalize"]).is_empty());
    }

    /// Every registered module's `consumes()` must cover every `TargetKind`
    /// its `accepts()` matches against the canonical probe value.
    ///
    /// Why this is load-bearing: the engine builds its O(1) dispatch index
    /// from `consumes()` (see `core::dependency::ModuleGraph`). A module that
    /// hand-rolls `consumes()` and declares FEWER kinds than `accepts()`
    /// actually matches is silently never indexed for the missing kind — so
    /// it never dispatches there, and the engine's belt-and-braces `accepts()`
    /// recheck never even runs (the module isn't in the candidate list). This
    /// test turns that class of mis-declaration into a CI failure instead of a
    /// silent loss of coverage.
    ///
    /// The default `consumes()` derives itself by probing `accepts()`, so
    /// non-overriding modules satisfy this by construction; the test guards
    /// the modules that override `consumes()` by hand. A `consumes()` that is
    /// a strict *superset* of the probed-accepts set is fine (value-shape
    /// gates legitimately declare kinds the generic probe value can't match).
    #[test]
    fn module_consumes_covers_probed_accepts() {
        let mut violations = Vec::new();
        for m in registry() {
            let declared = m.consumes();
            for &kind in ALL_TARGET_KINDS {
                if m.accepts(&Target::new(kind, PROBE_VALUE)) && !declared.contains(&kind) {
                    violations.push(format!(
                        "  {}: accepts() matches {:?} (probe) but consumes() omits it \
                         → dispatch index would never serve it for that kind",
                        m.name(),
                        kind
                    ));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "consumes()/accepts() divergence detected:\n{}",
            violations.join("\n")
        );
    }
}
