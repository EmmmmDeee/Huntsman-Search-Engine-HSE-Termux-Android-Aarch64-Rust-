//! Module registry. Adding a new module is a one-file change:
//!   1. Create `src/modules/foo.rs` implementing `Module`.
//!   2. `pub mod foo;` here.
//!   3. Push `Arc::new(foo::Foo)` into `registry()`.
//!
//! Nothing else in the codebase needs to know about the new module.

pub mod abn_lookup;
pub mod abuseipdb;
pub mod acma_rrl;
pub mod acnc_charities;
pub mod ahpra;
pub mod api_key_probe;
pub mod asic_director;
pub mod au_electoral;
pub mod au_people;
pub mod au_property;
pub mod au_unclaimed;
pub mod austlii;
pub mod bgpview;
pub mod bitbucket_user;
pub mod bluesky_user;
pub mod breach_timezone;
pub mod cell_intel;
pub mod cell_local;
pub mod censys;
pub mod cert_intel;
pub mod chain_intel;
pub mod cloud_storage;
pub mod codeberg_user;
pub mod codewars_user;
pub mod contact_enrich;
pub mod cpan_user;
pub mod crates_io;
pub mod criminal_ip;
pub mod crtsh;
pub mod dehashed;
pub mod device_sensors;
pub mod devto;
pub mod disposable_check;
pub mod dns_axfr;
pub mod dns_intel;
pub mod dockerhub_user;
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
pub mod gitea_user;
pub mod github_code_search;
pub mod github_user;
pub mod gitlab_user;
pub mod gleif_lei;
pub mod gravatar;
pub mod greynoise;
pub mod hacker_news;
pub mod hackertarget;
pub mod hexpm_user;
pub mod hibp;
pub mod hlr_cnam;
pub mod hudsonrock;
pub mod huggingface_user;
pub mod hunter_io;
pub mod intelx;
pub mod ip2location;
pub mod ip_geo;
pub mod ip_registry;
pub mod ip_reputation;
pub mod ip_whois_geo;
pub mod ipinfo;
pub mod ipqs;
pub mod ipquery;
pub mod keybase;
pub mod launchpad_user;
pub mod leakix;
pub mod lobsters;
pub mod local_net;
pub mod mastodon_user;
pub mod mls;
pub mod mylnikov;
pub mod name_intel;
pub mod netblock;
pub mod netlas;
pub mod niamonx;
pub mod npm_author;
pub mod numverify;
pub mod oathnet_pro;
pub mod onyphe;
pub mod opencellid;
pub mod opencorporates;
pub mod osintcat;
pub mod overpass;
pub mod payid;
pub mod pgp;
pub mod phone_geo;
pub mod phone_intl;
pub mod photon;
pub mod portscan;
// Shared entity-construction toolkit for developer-profile modules — a helper,
// not a registered `Module`, so it is `pub(crate)` (the registry guard only
// inspects `pub mod` declarations).
pub(crate) mod profile_kit;
pub mod proxycurl;
pub mod psbdmp;
pub mod pwned_passwords;
pub mod qld_cadastre;
pub mod rdap_domain;
pub mod reddit_user;
pub mod ripestat;
pub mod search_engines;
pub mod securitytrails;
pub mod see_know;
pub mod seon;
pub mod shodan;
pub mod signal_radar;
pub mod smtp_vrfy;
pub mod social_location;
pub mod social_probe;
pub mod sourceforge_user;
pub mod stackoverflow_user;
pub mod streaming_probe;
pub mod subdomain_takeover;
pub mod sunrise_sunset;
pub mod threatfox;
pub mod trove_au;
pub mod typosquat;
pub mod url_extract;
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
pub mod zoomeye;

use std::sync::Arc;

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::core::module::Module;

/// Reset the foreign-API-key sink at scan start. Re-exported here so
/// `core/engine` can drive it without importing `util` directly — the same
/// architecture-rule shim used for the per-module budget resets (the
/// dependency direction is `core → modules → util`, never `core → util`).
pub fn reset_found_keys(scan_id: &str) {
    crate::util::found_keys::reset(scan_id);
}

/// Drain the foreign-API-key sink into first-class `ApiKey` entities for
/// `scan_id`. Lives at the module layer (which may use both `util` and
/// `core::entity`) so the engine's finalisation stays free of any `util`
/// import. Every entry is a recognised vendor key (the sink uses the
/// vendor-only identifier), so all are high-confidence.
pub fn drain_found_key_entities(scan_id: &str) -> Vec<Entity> {
    let found = crate::util::found_keys::drain(scan_id);
    // Persist every discovered key to the cross-scan permanent vault BEFORE
    // mapping to entities, so a vault write failure (disk full, permissions)
    // never prevents entities from being emitted. Crypto wallet addresses are
    // included — the vault stores everything with full provenance.
    crate::util::key_vault::persist_batch(&found, scan_id);
    found
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
            // Rank by operational value (blast radius if live) so the harvested
            // key set is a value-ordered database: a leaked cloud secret /
            // private key / DB URI ranks above a publishable token or webhook.
            let tier = oathnet_pro::key_harvest::key_value_tier(&fk.service);
            let mut e = Entity::new(EntityKind::ApiKey, &fk.key, tier.confidence(), scan_id);
            e.tag("api-key");
            e.tag("foreign-key");
            e.tag("retrieved");
            e.tag(format!("service:{}", fk.service));
            e.tag(format!("value:{}", tier.as_str()));
            if tier.is_high_value() {
                e.tag("high-value");
            }
            e.add_evidence(
                Evidence::new(
                    "found_keys",
                    format!(
                        "Foreign {} API key ({} value) retrieved from {} data",
                        fk.service,
                        tier.as_str(),
                        fk.provider
                    ),
                )
                .with_attr("service", &fk.service)
                .with_attr("value_tier", tier.as_str())
                .with_attr("source_provider", &fk.provider)
                .with_attr("source_query", &fk.query)
                .with_attr("occurrences", fk.count.to_string()),
            );
            e
        })
        .collect()
}

/// Built-in module set. The engine sorts by priority — order here is irrelevant.
/// Install the cross-cutting module hooks into `core` (per-scan budget resets,
/// the regional-search flag, the found-key sink, and the vendor-key matcher).
/// Idempotent; called from [`registry`] so the engine — always built from
/// `registry()` — has the hooks before it runs. This is the single place the
/// `modules → core` hook edge is wired; `core` never imports `modules`.
fn install_core_hooks() {
    crate::core::hooks::install(crate::core::hooks::ModuleHooks {
        reset_per_scan: |scan_id| {
            oathnet_pro::reset_budget();
            see_know::reset_budget();
            wigle::reset_budget();
            reset_found_keys(scan_id);
        },
        set_regional: search_engines::set_regional,
        refresh_round_budget: see_know::refresh_round_budget,
        identify_api_key: oathnet_pro::key_harvest::identify_api_key,
        drain_found_keys: drain_found_key_entities,
    });
}

pub fn registry() -> Vec<Arc<dyn Module>> {
    install_core_hooks();
    vec![
        // Priority 200 — runs first: types any value and extracts embedded entities from
        // unstructured text so every output (including the system's own) is re-injectable
        // as a seed. Pure/offline; lives in `core` (implements the core Module trait).
        Arc::new(crate::core::classify_module::ClassifyModule),
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
        Arc::new(onyphe::Onyphe),
        Arc::new(zoomeye::ZoomEye),
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
        Arc::new(url_extract::UrlExtract),
        Arc::new(urlscan::UrlScan),
        Arc::new(email_parse::EmailParse),
        Arc::new(email_canonical::EmailCanonical),
        Arc::new(employer_pivot::EmployerPivot),
        Arc::new(social_probe::SocialProbe),
        Arc::new(username_search::UsernameSearch),
        Arc::new(streaming_probe::StreamingProbe),
        Arc::new(username_variants::UsernameVariants),
        Arc::new(github_user::GithubUser),
        Arc::new(github_code_search::GithubCodeSearch),
        Arc::new(hacker_news::HackerNews),
        Arc::new(lobsters::Lobsters),
        Arc::new(devto::DevTo),
        Arc::new(stackoverflow_user::StackoverflowUser),
        Arc::new(bluesky_user::BlueskyUser),
        Arc::new(mastodon_user::MastodonUser),
        Arc::new(gitlab_user::GitlabUser),
        Arc::new(gitea_user::GiteaUser),
        Arc::new(sourceforge_user::SourceforgeUser),
        Arc::new(bitbucket_user::BitbucketUser),
        Arc::new(codeberg_user::CodebergUser),
        Arc::new(codewars_user::CodewarsUser),
        Arc::new(huggingface_user::HuggingfaceUser),
        Arc::new(dockerhub_user::DockerhubUser),
        Arc::new(hexpm_user::HexpmUser),
        Arc::new(launchpad_user::LaunchpadUser),
        Arc::new(cpan_user::CpanUser),
        Arc::new(npm_author::NpmAuthor),
        Arc::new(crates_io::CratesIo),
        Arc::new(reddit_user::RedditUser),
        Arc::new(gravatar::Gravatar),
        Arc::new(payid::PayId),
        Arc::new(pgp::Pgp),
        Arc::new(psbdmp::Psbdmp),
        Arc::new(phone_intl::PhoneIntl),
        Arc::new(wayback::Wayback),
        Arc::new(device_sensors::DeviceSensors),
        Arc::new(cell_intel::CellIntel),
        Arc::new(cell_local::CellLocal),
        Arc::new(opencellid::OpenCellId),
        Arc::new(wifi_intel::WifiIntel),
        Arc::new(local_net::LocalNet),
        Arc::new(signal_radar::SignalRadar),
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
        Arc::new(qld_cadastre::QldCadastre),
        Arc::new(sunrise_sunset::SunriseSunset),
        // Geolocation enrichment (passive, zero-API)
        Arc::new(geo_domain_classifier::GeoDomainClassifier),
        Arc::new(email_header_geo::EmailHeaderGeo),
        Arc::new(phone_geo::PhoneGeo),
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
        Arc::new(au_unclaimed::AuUnclaimed),
        Arc::new(au_people::AuPeople),
        Arc::new(asic_director::AsicDirector),
        Arc::new(au_electoral::AuElectoral),
        Arc::new(au_property::AuProperty),
        Arc::new(acnc_charities::AcncCharities),
        Arc::new(gleif_lei::GleifLei),
        Arc::new(acma_rrl::AcmaRrl),
        Arc::new(ahpra::Ahpra),
        Arc::new(hlr_cnam::HlrCnam),
        Arc::new(netlas::Netlas),
        Arc::new(trove_au::TroveAu),
        Arc::new(austlii::AustLii),
    ]
}

/// Module name → its ATT&CK technique IDs. The mapping is constant (the registry
/// and each module's `attack_techniques()` are `'static`), so it is built once
/// and reused — every per-request technique lookup avoids reconstructing the
/// whole 130-module registry. Backs the reverse [`technique_module_index`].
static MODULE_TECHNIQUES: std::sync::LazyLock<
    std::collections::HashMap<&'static str, &'static [&'static str]>,
> = std::sync::LazyLock::new(|| {
    registry()
        .iter()
        .map(|m| (m.name(), m.attack_techniques()))
        .collect()
});

/// Reverse of [`MODULE_TECHNIQUES`]: ATT&CK technique ID → the module names that
/// implement it. Catalogued IDs only; module lists sorted + deduplicated. Also
/// constant, so it is built once.
static TECHNIQUE_MODULES: std::sync::LazyLock<
    std::collections::BTreeMap<&'static str, Vec<&'static str>>,
> = std::sync::LazyLock::new(|| {
    let mut index: std::collections::BTreeMap<&'static str, Vec<&'static str>> =
        std::collections::BTreeMap::new();
    for (name, techniques) in MODULE_TECHNIQUES.iter() {
        for &id in *techniques {
            if crate::core::attack::technique(id).is_some() {
                index.entry(id).or_default().push(name);
            }
        }
    }
    for names in index.values_mut() {
        names.sort_unstable();
        names.dedup();
    }
    index
});

/// Reverse index of the module ⇆ technique map: each ATT&CK Reconnaissance
/// technique ID → the registered module names that implement it. Only
/// catalogued technique IDs are keyed (unknown IDs are dropped), and the module
/// lists are sorted + deduplicated, so the output is deterministic.
///
/// One structure answers two questions: which modules implement a given
/// technique, and (intersected with a scan's evidence sources) which of them a
/// scan actually exercised. Returns the process-wide cached index
/// ([`TECHNIQUE_MODULES`]) — built once, not per call.
#[must_use]
pub fn technique_module_index()
-> &'static std::collections::BTreeMap<&'static str, Vec<&'static str>> {
    &TECHNIQUE_MODULES
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
