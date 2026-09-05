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
pub mod ahmia;
pub mod ahpra;
pub mod anubis;
pub mod api_key_probe;
pub mod app_links;
pub mod asic_banned_orgs;
pub mod asic_business_names;
pub mod asic_director;
pub mod asic_persons;
pub mod au_business_id;
pub mod au_electoral;
pub mod au_geo;
pub mod au_people;
pub mod au_property;
pub mod au_rdap;
pub mod au_unclaimed;
pub mod auspost;
pub mod austlii;
pub mod beacondb;
pub mod bgpview;
pub mod binaryedge;
pub mod bitbucket_user;
pub mod bitcoin;
pub mod bluesky_user;
pub mod builtwith;
// Shared "maximum raw data" breach/stealer extractor — a `pub(crate)` HELPER
// (no `Module` impl), consumed by see_know / oathnet_pro / dehashed via
// `crate::modules::breach_rich::extract_rich_detail`, not a registered module.
// `pub(crate)` (like `profile_kit`) keeps it crate-internal and out of the
// `every_declared_module_is_registered` guard, which flags an unregistered
// `pub mod` as dead-at-runtime.
pub(crate) mod breach_rich;
pub mod breach_timezone;
pub mod breachdirectory;
pub mod c99;
pub mod cell_intel;
pub mod cell_local;
pub mod censys;
pub mod cert_intel;
pub mod certspotter;
pub mod chain_intel;
pub mod chess_profile;
pub mod cloud_storage;
pub mod codeberg_user;
pub mod codewars_user;
pub mod comb_search;
pub mod commoncrawl;
pub mod contact_enrich;
pub mod cpan_user;
pub mod crates_io;
pub mod criminal_ip;
pub mod crossref_search;
pub mod crtsh;
pub mod data_gov_au;
pub mod dehashed;
pub mod device_sensors;
// Shared Termux `termux-location` fix primitives (the `Fix` shape +
// confidence ladder) — a `pub(crate)` HELPER (no `Module` impl), consumed by
// device_sensors and signal_radar so the on-device fix logic lives once.
// `pub(crate)` (like `breach_rich`) keeps it out of the
// `every_declared_module_is_registered` guard.
pub(crate) mod device_fix;
pub mod devto;
pub mod discord_snowflake;
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
pub mod europepmc_search;
pub mod exa_search;
pub mod exif_geo;
pub mod fediverse;
pub mod fofa;
pub mod fullcontact;
pub mod fullhunt;
pub mod gaming_profile;
pub mod geo_domain_classifier;
pub mod geo_intel;
pub mod geocode;
pub mod gitea_user;
// Shared GitHub REST API binding (the pinned API version) — a `pub(crate)`
// HELPER (no `Module` impl), consumed by the three github_* modules so a
// version bump is one edit, not seven. `pub(crate)` (like `breach_rich`) keeps
// it out of the `every_declared_module_is_registered` guard.
pub(crate) mod github_api;
pub mod github_code_search;
pub mod github_commits;
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
pub mod leakcheck_public;
pub mod leakix;
pub mod libravatar;
pub mod lobsters;
pub mod local_net;
pub mod mastodon_user;
pub mod mnemonic_pdns;
pub mod mylnikov;
pub mod name_intel;
pub mod netblock;
pub mod netlas;
pub mod niamonx;
pub mod nostr;
pub mod npm_author;
pub mod numverify;
pub mod oathnet_pro;
pub mod onyphe;
pub mod open_meteo_geo;
pub mod opencellid;
pub mod opencorporates;
pub mod opensanctions;
pub mod osintcat;
pub mod overpass;
pub mod passivetotal;
pub mod payid;
pub mod pgp;
pub mod phone_au;
pub mod phone_geo;
pub mod phone_intl;
pub mod photon;
pub mod plc_directory;
pub mod portscan;
pub mod wiki_geosearch;
pub mod wikidata_geo;
// Shared entity-construction toolkit for developer-profile modules — a helper,
// not a registered `Module`, so it is `pub(crate)` (the registry guard only
// inspects `pub mod` declarations).
pub(crate) mod profile_kit;
pub mod proxycurl;
pub mod psbdmp;
pub mod pulsedive;
pub mod pwned_passwords;
pub mod pypi_user;
pub mod qld_cadastre;
pub mod ransomlook;
pub mod ransomware_live;
pub mod rdap_domain;
pub mod reddit_user;
pub mod ripestat;
pub mod rubygems_user;
pub mod sanctions_ofac;
pub mod search_engines;
pub mod securitytrails;
pub mod see_know;
pub mod seon;
pub mod shodan;
pub mod signal_radar;
pub mod sitemap;
pub mod smtp_vrfy;
pub mod social_location;
pub mod social_probe;
pub mod sourceforge_user;
pub mod stackoverflow_user;
pub mod steam_profile;
pub mod stolen_tax;
pub mod streaming_probe;
pub mod structured_id;
pub mod subdomain_center;
pub mod subdomain_takeover;
pub mod sunrise_sunset;
// Shared Termux sensor-tool output contract (blank vs unparseable) — a
// `pub(crate)` HELPER (no `Module` impl), consumed by signal_radar,
// device_sensors, wifi_intel and cell_intel so the rule distinguishing "the
// tool answered with nothing" from "the tool is broken" lives once.
// `pub(crate)` (like `breach_rich`) keeps it out of the
// `every_declared_module_is_registered` guard.
pub(crate) mod termux_sensor;
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
pub mod wifidb;
pub mod wigle;
pub mod wikidata;
pub mod xposed_or_not;
pub mod zoomeye;

use std::sync::Arc;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::Module,
};

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
                let mut e = Entity::new(
                    EntityKind::CryptoAddress,
                    &fk.key,
                    confidence::HIGH_PLUSPLUS,
                    scan_id,
                );
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
            let tier = crate::util::key_harvest::key_value_tier(&fk.service);
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

/// Built-in implementation of the engine's module-layer runtime contract.
struct BuiltinModuleRuntime;

impl crate::core::module_runtime::ModuleRuntime for BuiltinModuleRuntime {
    fn reset_per_scan(&self, scan_id: &str) {
        crate::util::oathnet::reset_budget();
        crate::util::see_know::reset_budget();
        wigle::reset_budget();
        typosquat::reset_seen(scan_id);
        search_engines::reset_session_liveness(scan_id);
        reset_found_keys(scan_id);
    }

    fn refresh_round_budget(&self) {
        see_know::refresh_round_budget();
    }

    fn identify_api_key<'a>(&self, value: &'a str) -> Option<(&'static str, &'a str)> {
        crate::util::key_harvest::identify_api_key(value)
    }

    fn drain_found_keys(&self, scan_id: &str) -> Vec<crate::core::entity::Entity> {
        drain_found_key_entities(scan_id)
    }

    fn cleanup_scan_budgets(&self, scan_id: &str) {
        crate::util::oathnet::cleanup_scan(scan_id);
        crate::util::see_know::cleanup_scan(scan_id);
        wigle::cleanup_scan(scan_id);
    }

    fn set_seeknow_scan_cap(&self, cap: u32) {
        crate::util::see_know::set_scan_cap_override(cap);
    }
}

/// Runtime effects paired with the built-in module registry.
pub fn module_runtime() -> std::sync::Arc<dyn crate::core::module_runtime::ModuleRuntime> {
    std::sync::Arc::new(BuiltinModuleRuntime)
}

/// The built-in module list, built exactly once. `registry()` is called from
/// several long-lived paths (e.g. the server's per-request scan handlers), and
/// re-running ~150 `Arc::new(ZST)` heap allocations on every call is pure
/// repeated work over `const` data. Cloning a `Vec<Arc<dyn Module>>` instead
/// costs one Vec allocation plus ~150 refcount bumps (no per-module heap
/// allocation), so `registry()` stays returning an owned, independently
/// droppable `Vec` — its documented contract — while the underlying modules
/// are built once per process.
static MODULE_REGISTRY: std::sync::LazyLock<Vec<Arc<dyn Module>>> =
    std::sync::LazyLock::new(|| {
        vec![
            // Priority 200 — runs first: types any value and extracts embedded entities from
            // unstructured text so every output (including the system's own) is re-injectable
            // as a seed. Pure/offline; lives in `core` (implements the core Module trait).
            Arc::new(crate::core::classify_module::ClassifyModule),
            Arc::new(hibp::Hibp),
            Arc::new(hudsonrock::HudsonRock),
            Arc::new(comb_search::CombSearch),
            Arc::new(xposed_or_not::XposedOrNot),
            Arc::new(stolen_tax::StolenTax),
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
            Arc::new(breachdirectory::BreachDirectory),
            // Keyless public breach index (email → named breaches + exposed data
            // classes), an independent corpus beside hudsonrock/xposed_or_not
            // that feeds the AU-001 multi-source-breach correlator.
            Arc::new(leakcheck_public::LeakCheckPublic),
            Arc::new(intelx::IntelX),
            // Dark-web exposure over Ahmia's clearnet index (keyless), beside the
            // other exposure sources — reports where a target is mentioned on a
            // Tor hidden service; never fetches one.
            Arc::new(ahmia::Ahmia),
            Arc::new(securitytrails::SecurityTrails),
            Arc::new(leakix::LeakIx),
            Arc::new(criminal_ip::CriminalIp),
            Arc::new(onyphe::Onyphe),
            Arc::new(zoomeye::ZoomEye),
            Arc::new(fofa::Fofa),
            Arc::new(builtwith::BuiltWith),
            Arc::new(binaryedge::BinaryEdge),
            Arc::new(c99::C99),
            Arc::new(fullhunt::FullHunt),
            Arc::new(pulsedive::Pulsedive),
            Arc::new(passivetotal::PassiveTotal),
            Arc::new(ipqs::IpQs),
            Arc::new(contact_enrich::ContactEnrich),
            Arc::new(hunter_io::HunterIo),
            Arc::new(proxycurl::Proxycurl),
            Arc::new(disposable_check::DisposableCheck),
            Arc::new(discord_snowflake::DiscordSnowflake),
            Arc::new(wigle::Wigle),
            Arc::new(cert_intel::CertIntel),
            Arc::new(crtsh::CrtSh),
            Arc::new(certspotter::CertSpotter),
            Arc::new(anubis::Anubis),
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
            // Keyless historical passive DNS (domain↔IP over time) — the reverse
            // and historical view the live resolvers above can't give.
            Arc::new(mnemonic_pdns::MnemonicPdns),
            // Keyless subdomain enumeration from an aggregated CT/passive corpus,
            // distinct from crtsh/certspotter/anubis — more independent coverage.
            Arc::new(subdomain_center::SubdomainCenter),
            Arc::new(threatfox::ThreatFox),
            Arc::new(rdap_domain::RdapDomain),
            // AU-specific RDAP (auDA) sibling of the generic `rdap_domain`
            // above — discloses registrant identity a generic RDAP client
            // can't reach for a .au domain, so it dispatches right after it.
            Arc::new(au_rdap::AuRdap),
            Arc::new(ripestat::RipeStat),
            Arc::new(search_engines::SearchEngines),
            Arc::new(webserver_banner::WebserverBanner),
            Arc::new(web_crawler::WebCrawler),
            Arc::new(app_links::AppLinks),
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
            Arc::new(github_commits::GithubCommits),
            Arc::new(chess_profile::ChessProfile),
            Arc::new(gaming_profile::GamingProfile),
            Arc::new(steam_profile::SteamProfile),
            Arc::new(structured_id::StructuredId),
            Arc::new(hacker_news::HackerNews),
            Arc::new(lobsters::Lobsters),
            Arc::new(devto::DevTo),
            Arc::new(stackoverflow_user::StackoverflowUser),
            Arc::new(bluesky_user::BlueskyUser),
            Arc::new(plc_directory::PlcDirectory),
            Arc::new(mastodon_user::MastodonUser),
            Arc::new(bitcoin::Bitcoin),
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
            Arc::new(rubygems_user::RubygemsUser),
            Arc::new(pypi_user::PypiUser),
            Arc::new(npm_author::NpmAuthor),
            Arc::new(crates_io::CratesIo),
            Arc::new(reddit_user::RedditUser),
            Arc::new(gravatar::Gravatar),
            // Federated open-source Gravatar alternative — an independent avatar
            // corpus beside `gravatar`, keyless email → public avatar presence.
            Arc::new(libravatar::Libravatar),
            Arc::new(fediverse::Fediverse),
            Arc::new(nostr::Nostr),
            Arc::new(payid::PayId),
            Arc::new(pgp::Pgp),
            Arc::new(psbdmp::Psbdmp),
            Arc::new(phone_intl::PhoneIntl),
            Arc::new(phone_au::PhoneAu),
            Arc::new(wayback::Wayback),
            // Common Crawl's own independent web-crawl index for a domain's
            // URLs — a separate corpus from the Wayback CDX lookup above.
            Arc::new(commoncrawl::CommonCrawl),
            Arc::new(sitemap::Sitemap),
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
            Arc::new(opensanctions::OpenSanctions),
            Arc::new(keybase::Keybase),
            Arc::new(emailrep::EmailRep),
            Arc::new(epieos::Epieos),
            Arc::new(fullcontact::FullContact),
            Arc::new(numverify::NumVerify),
            Arc::new(photon::Photon),
            // Third keyless forward geocoder alongside `geocode` (Nominatim) and
            // `photon` (Komoot): resolves self-reported place-names to coordinates
            // and adds timezone/population/place-class the others don't return.
            Arc::new(open_meteo_geo::OpenMeteoGeo),
            Arc::new(mylnikov::Mylnikov),
            // Keyless BSSID geolocation alongside `mylnikov`: two independent
            // free corpora answering the same question, so an outage or a miss
            // in one still leaves the radar a way to locate an observed AP.
            Arc::new(beacondb::BeaconDb),
            // The first keyless wardriving corpus — a free WiGLE alternative
            // (BSSID → coordinates) beside keyed `wigle` and the other free
            // corpora above, so a WiGLE-quota miss still leaves a way to locate.
            Arc::new(wifidb::WifiDb),
            Arc::new(exif_geo::ExifGeo),
            Arc::new(overpass::Overpass),
            Arc::new(wiki_geosearch::WikiGeoSearch),
            Arc::new(wikidata_geo::WikidataGeo),
            Arc::new(qld_cadastre::QldCadastre),
            // Coordinates -> Address reverse lookup against Australia Post,
            // alongside the other AU-specific geo sources above.
            Arc::new(auspost::AusPost),
            Arc::new(sunrise_sunset::SunriseSunset),
            // Geolocation enrichment (passive, zero-API)
            Arc::new(geo_domain_classifier::GeoDomainClassifier),
            Arc::new(email_header_geo::EmailHeaderGeo),
            Arc::new(phone_geo::PhoneGeo),
            Arc::new(email_locale::EmailLocale),
            Arc::new(breach_timezone::BreachTimezone),
            // Threat intel & infrastructure
            Arc::new(virustotal::VirusTotal),
            // Keyless ransomware/extortion victim index (domain/org → claiming
            // group, dates, reference) — a net-new org-exposure threat signal.
            Arc::new(ransomware_live::RansomwareLive),
            // Independent second ransomware/market leak-site corpus beside
            // `ransomware_live` — additive: it also indexes markets/forums.
            Arc::new(ransomlook::RansomLook),
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
            // Academic-literature search by name, two independent corpora
            // (kept adjacent: same target kinds, same search shape).
            Arc::new(crossref_search::CrossrefSearch),
            Arc::new(europepmc_search::EuropePmcSearch),
            // Australian + global public-records / corporate registries
            Arc::new(opencorporates::OpenCorporates),
            Arc::new(data_gov_au::DataGovAu),
            Arc::new(au_unclaimed::AuUnclaimed),
            Arc::new(au_people::AuPeople),
            Arc::new(asic_director::AsicDirector),
            Arc::new(asic_persons::AsicPersons),
            Arc::new(asic_business_names::AsicBusinessNames),
            Arc::new(asic_banned_orgs::AsicBannedOrgs),
            Arc::new(au_business_id::AuBusinessId),
            Arc::new(au_electoral::AuElectoral),
            Arc::new(au_property::AuProperty),
            Arc::new(au_geo::AuGeo),
            Arc::new(acnc_charities::AcncCharities),
            Arc::new(gleif_lei::GleifLei),
            Arc::new(sanctions_ofac::SanctionsOfac),
            Arc::new(acma_rrl::AcmaRrl),
            Arc::new(ahpra::Ahpra),
            Arc::new(hlr_cnam::HlrCnam),
            Arc::new(netlas::Netlas),
            Arc::new(trove_au::TroveAu),
            Arc::new(austlii::AustLii),
        ]
    });

pub fn registry() -> Vec<Arc<dyn Module>> {
    MODULE_REGISTRY.clone()
}

/// True if `key` names a capability toggle that actually exists: a registered
/// `feature.*` switch (`util::settings::FEATURE_TOGGLES`), a search engine
/// (`engine.<name>`, from [`search_engines::engine_toggles`]) or a module
/// (`module.<name>`) present in `modules` — the caller's live registry view
/// (`ScanEngine::modules()` for the API handler, [`registry`] for the CLI).
///
/// The ONE validator behind both write paths, `PUT /api/v1/settings/toggles`
/// and `hse config <key> on|off`. The CLI used to skip validation entirely and
/// persist whatever key it was given, so a typo'd `hse config module.shodann
/// off` printed "○ off", changed nothing, and left the operator believing the
/// module was disabled. Lives in this layer (not `util::settings`) because it
/// needs the engine catalogue and the registry, which `util` must not import.
/// The requested / excluded module names that are not registered modules
/// (deduplicated, sorted), checked against the live registry. A typo, or a
/// name removed in an upgrade (`ipapi`, folded into `ip_whois_geo`), used to
/// be dropped silently — and a non-empty allowlist matching no module makes
/// the engine skip EVERY module as "not in allowlist", a scan that completes
/// with nothing and reads as a legitimate narrowed sweep. Lives here, beside
/// [`is_known_toggle_key`], so `hse scan` and `POST /api/v1/scans` validate
/// against the same catalogue.
pub fn unknown_module_names(requested: &Option<Vec<String>>, excluded: &[String]) -> Vec<String> {
    let known: std::collections::HashSet<&str> = registry().iter().map(|m| m.name()).collect();
    requested
        .iter()
        .flatten()
        .chain(excluded.iter())
        .filter(|m| !known.contains(m.as_str()))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The registered module that OWNS a corpus other modules also read, by the
/// host they read it from. Evidence minted from such a read carries the
/// owner's source name, not the reader's: SOURCE COUNT ≠ SOURCE INDEPENDENCE,
/// and one record fetched by two modules must not merge into an entity
/// carrying two "independent" sources. `cell_intel`/`wifi_intel`/`ip_registry`
/// (Pass 17), `contact_enrich` and `wikidata_geo` attribute directly to the
/// owner's `SRC`; the probe modules (`username_search`, `social_probe`) run
/// hundreds of sites through one evidence path and look the site up here.
const CORPUS_OWNERS: &[(&str, &str)] = &[
    ("gravatar.com", gravatar::SRC),
    ("keybase.io", keybase::SRC),
    ("wikidata.org", wikidata::SRC),
];

/// The source name evidence derived from `url` must carry: the owning
/// module's when the host is (or is under) a corpus another module owns,
/// else `own`.
#[must_use]
pub fn corpus_source(url: &str, own: &'static str) -> &'static str {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    CORPUS_OWNERS
        .iter()
        .find(|(h, _)| host == *h || host.ends_with(&format!(".{h}")))
        .map_or(own, |(_, src)| *src)
}

pub fn is_known_toggle_key(key: &str, modules: &[Arc<dyn Module>]) -> bool {
    if let Some(name) = key.strip_prefix("module.") {
        return modules.iter().any(|m| m.name() == name);
    }
    if key.starts_with("engine.") {
        return search_engines::engine_toggles()
            .iter()
            .any(|(k, _)| k == key);
    }
    crate::util::settings::is_feature_key(key)
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

/// HSE's registry-wide MITRE ATT&CK **Reconnaissance** (TA0043) coverage — the
/// single authority for HSE's *static* ATT&CK posture, independent of any one
/// scan.
///
/// It composes every registered module's [`Module::attack_techniques`] with
/// [`crate::core::attack::static_reconnaissance_coverage`] (which folds in the
/// entity- and relation-kind mappings too), so the covered set, the honest gaps
/// and the coverage fraction are all **derived from real collection capability**,
/// never asserted. `hse attack {status,coverage,gaps,navigator}` render views of
/// exactly this value, and [`technique_module_index`] resolves each covered
/// technique to the modules that are its evidence.
#[must_use]
pub fn reconnaissance_coverage() -> crate::core::attack::Coverage {
    let ids = MODULE_TECHNIQUES
        .values()
        .flat_map(|techniques| techniques.iter().copied());
    crate::core::attack::static_reconnaissance_coverage(ids)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}

#[cfg(test)]
mod keyed_tests;
