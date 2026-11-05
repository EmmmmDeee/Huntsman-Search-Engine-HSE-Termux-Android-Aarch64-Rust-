//! One row per provenance source ID: the class the correlator counts it under and, where it
//! differs, the finer acquisition modality the orthogonal-coverage report names.
//!
//! `correlator::source_family` and the orthogonal-coverage modality each read this table, so a
//! source is classified in one place. The two columns stay distinct on purpose. The correlator's
//! class is strict: an account leg or a community-curated source stays `other`, so it never counts
//! as an independent family in a correlation rule. The modality is an acquisition hint, never
//! evidence that anything is true or independent.
//!
//! [`PROFILES`] holds every source ID the engine writes; [`LEGACY`] holds IDs no current code
//! writes, which a saved scan from an older build can still carry. An ID in neither is classified
//! by its name ([`by_name`]), as before the table existed. `tests/source_profile.rs` holds the
//! tables to the code: every collector constant and registry row has a `PROFILES` row, and no
//! `LEGACY` ID is written anywhere.

/// A source's class. The correlator uses the first eleven; the modality adds the last three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceClass {
    Breach,
    Code,
    Rf,
    Forum,
    Social,
    Presence,
    Search,
    EmailIntel,
    IdentityRegistry,
    Infra,
    Other,
    KnowledgeGraph,
    Geoint,
    Transport,
}

impl SourceClass {
    /// The label every report and rule has always used for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Breach => "breach",
            Self::Code => "code",
            Self::Rf => "rf",
            Self::Forum => "forum",
            Self::Social => "social",
            Self::Presence => "presence",
            Self::Search => "search",
            Self::EmailIntel => "email_intel",
            Self::IdentityRegistry => "identity_registry",
            Self::Infra => "infra",
            Self::Other => "other",
            Self::KnowledgeGraph => "knowledge_graph",
            Self::Geoint => "geoint",
            Self::Transport => "transport",
        }
    }
}

/// One source ID and how it is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceProfile {
    /// The `provenance.source` the source writes, lowercase.
    pub id: &'static str,
    /// The class the correlator counts the source under.
    pub family: SourceClass,
    /// The acquisition modality, where it is finer than `family`.
    pub modality: Option<SourceClass>,
}

impl SourceProfile {
    /// The acquisition modality: the finer class where one is set, else the family.
    #[must_use]
    pub const fn modality(&self) -> SourceClass {
        match self.modality {
            Some(modality) => modality,
            None => self.family,
        }
    }
}

use SourceClass as C;

/// A table row: `id`, its correlator class, and its acquisition modality where finer.
const fn row(
    id: &'static str,
    family: SourceClass,
    modality: Option<SourceClass>,
) -> SourceProfile {
    SourceProfile {
        id,
        family,
        modality,
    }
}

/// Every source ID the engine writes, sorted by ID.
pub const PROFILES: &[SourceProfile] = &[
    row("abn_lookup", C::IdentityRegistry, None),
    row("abusech", C::Other, None),
    row("abuseipdb", C::Infra, None),
    // Official registers and regulatory filing clients: an acquisition modality only; their
    // lineage is NOT authenticated by it.
    row("acnc", C::IdentityRegistry, None),
    row("adguard_dns", C::Infra, None),
    row("alienvaultiprep", C::Infra, None),
    row("apk_intel", C::Other, None),
    row("apk_set", C::Other, None),
    row("apple_itunes", C::Other, None),
    row("archived_page", C::Other, Some(C::Search)),
    row("asic_director", C::IdentityRegistry, None),
    row("asic_orgs", C::IdentityRegistry, None),
    row("asic_persons", C::Other, Some(C::IdentityRegistry)),
    row("asn_cli", C::Other, None),
    row("base_rpc", C::Other, None),
    row("bing", C::Other, Some(C::Search)),
    row("blockchain", C::Other, None),
    row("blocklistde", C::Other, None),
    row("bluesky_user", C::Other, Some(C::Social)),
    row("botvrij", C::Other, None),
    row("brave", C::Other, Some(C::Search)),
    row("breach_consensus", C::Other, None),
    row("cell_radar", C::Other, Some(C::Rf)),
    row("censys", C::Other, None),
    row("certspotter", C::Other, Some(C::Infra)),
    row("chess_com", C::Social, None),
    row("cinsscore", C::Other, None),
    row("classify_module", C::Other, None),
    row("cleanbrowsing", C::Other, None),
    row("cleantalk", C::Other, None),
    row("cloudflaredns", C::Infra, None),
    row("codeberg_user", C::Code, None),
    row("codewars_user", C::Code, None),
    row("common_crawl", C::Other, Some(C::Search)),
    row("comodo", C::Other, None),
    row("crates_io", C::Code, None),
    row("cross_scan_corroboration", C::Other, None),
    row("cross_scan_history", C::Other, None),
    row("crtsh", C::Other, Some(C::Infra)),
    row("cybercrimetracker", C::Other, None),
    row("dehashed", C::Breach, None),
    row("devto_user", C::Forum, None),
    row("dns", C::Infra, None),
    row("dns_for_family", C::Infra, None),
    row("dnsbl", C::Infra, None),
    row("dnsresolve", C::Infra, None),
    row("docker_hub_user", C::Other, Some(C::Code)),
    row("docmeta", C::Other, None),
    row("domain_cli", C::Other, None),
    row("domain_lifecycle", C::Other, None),
    row("dronebl", C::Other, None),
    row("duolingo", C::Social, None),
    row("email_parse", C::EmailIntel, None),
    row("emergingthreats", C::Other, None),
    row("eth_rpc", C::Other, None),
    row("exa", C::Search, None),
    row("exif", C::Other, None),
    row("fixture", C::Other, None),
    row("geo_corroboration", C::Infra, None),
    row("geocode", C::Infra, None),
    row("github_repos", C::Code, None),
    row("github_user", C::Code, None),
    row("gitlab_user", C::Other, Some(C::Code)),
    row("gleif", C::Other, Some(C::IdentityRegistry)),
    row("gleif_lei", C::IdentityRegistry, None),
    row("google", C::Search, None),
    row("gravatar", C::Social, None),
    row("greensnow", C::Other, None),
    row("greynoise", C::Infra, None),
    row("hacker_news", C::Forum, None),
    row("hackertarget", C::Infra, None),
    row("hibp", C::Breach, None),
    row("hibp_account", C::Breach, None),
    row("hudsonrock", C::Breach, None),
    row("huggingface_user", C::Code, None),
    row("hunter", C::EmailIntel, None),
    row("internetdb", C::Infra, None),
    row("ip_cli", C::Infra, None),
    row("ipinfo", C::Infra, None),
    row("ipinfo_lite", C::Infra, None),
    row("ipqs", C::Infra, None),
    row("isc", C::Infra, None),
    row("keybase", C::Other, Some(C::Social)),
    row("kickbox", C::EmailIntel, None),
    row("leakix", C::Breach, None),
    row("lichess", C::Social, None),
    row("lobsters", C::Forum, None),
    row("local_search", C::Search, None),
    row("maltiverse", C::Infra, None),
    row("mastodon_user", C::Other, Some(C::Social)),
    row("mitm_guard", C::Other, None),
    row("mnemonic", C::Other, None),
    row("mojeek", C::Other, Some(C::Search)),
    row("multipath_corroboration", C::Infra, None),
    row("name_intel", C::IdentityRegistry, None),
    row("netblock", C::Infra, None),
    row("netblock_cli", C::Other, None),
    row("netlas", C::Infra, None),
    // GEOINT and transport classes are acquisition hints, never evidence of identity,
    // co-presence or an operator's location.
    row("nominatim", C::Other, Some(C::Geoint)),
    row("npm_author", C::Code, None),
    row("numverify", C::Other, None),
    row("oathnet", C::Breach, None),
    row("official_x_recent_search", C::Search, None),
    row("opencellid", C::Other, Some(C::Rf)),
    row("opendns", C::Infra, None),
    row("openpgp_keys", C::EmailIntel, None),
    row("openphish", C::Other, None),
    row("opensky", C::Other, Some(C::Transport)),
    row("osintcat", C::Breach, None),
    row("otx", C::Infra, None),
    row("oui", C::Rf, None),
    row("peeringdb", C::Other, Some(C::Infra)),
    row("phishstats", C::Infra, None),
    row("phishtank", C::Other, None),
    row("phone_au", C::Other, None),
    row("phone_intl", C::Other, None),
    row("phone_nanp", C::Other, None),
    row("public_osint", C::Other, Some(C::Search)),
    row("public_web_indexes", C::Other, None),
    row("pulsedive", C::Infra, None),
    row("qld_state_road_camera_gis", C::Other, Some(C::Transport)),
    row("qld_traffic_cameras", C::Other, Some(C::Transport)),
    row("quad9", C::Other, None),
    row("rdap", C::Other, Some(C::Infra)),
    row("recall", C::Other, None),
    row("registry_policy", C::Other, None),
    row("ripestat", C::Infra, None),
    row("robtex", C::Infra, None),
    row("sec_edgar", C::Other, Some(C::IdentityRegistry)),
    row("securitytrails", C::Infra, None),
    row("seeknow", C::Breach, None),
    row("sf_compat", C::Other, None),
    row("shodan", C::Infra, None),
    row("solana_rpc", C::Other, None),
    row("sorbs", C::Other, None),
    row("source_registry", C::Other, None),
    row("spamcop", C::Other, None),
    row("spamhaus", C::Other, None),
    row("stac", C::Other, Some(C::Geoint)),
    row("stevenblack_hosts", C::Other, None),
    row("stolen_tax", C::Breach, None),
    row("stopforumspam", C::Infra, None),
    row("submd", C::Other, None),
    row("surbl", C::Other, None),
    row("threatfox", C::Infra, None),
    row("tiktok_public_contact", C::Other, Some(C::Social)),
    row("torexits", C::Other, None),
    row("uceprotect", C::Other, None),
    row(
        "unverified_network_survey_bluetooth_csv_file",
        C::Other,
        None,
    ),
    row("unverified_network_survey_csv_file", C::Other, None),
    row("unverified_network_survey_nr_csv_file", C::Other, None),
    row("unverified_network_survey_wifi_csv_file", C::Other, None),
    row("urlhaus", C::Infra, None),
    row("urlscan", C::Infra, None),
    row("username_variants", C::Other, None),
    row("virustotal", C::Infra, None),
    row("voipbl", C::Infra, None),
    row("vxvault", C::Other, None),
    row("wayback_cdx", C::Other, Some(C::Search)),
    row("web_query", C::Other, Some(C::Search)),
    row("web_server", C::Other, None),
    row("whoxy", C::Infra, None),
    row("wifi_radar", C::Other, Some(C::Rf)),
    row("wigle", C::Rf, None),
    row("wigle_bluetooth", C::Rf, None),
    // Community-curated: never an official identity registry or an independent identity proof.
    row("wikidata", C::Other, Some(C::KnowledgeGraph)),
    row("wikipedia", C::Other, None),
    row("xposed_or_not", C::Breach, None),
    row("yandexdns", C::Infra, None),
];

/// Source IDs no current code writes, sorted by ID: the correlator and modality arms of collectors
/// that were removed, renamed or never added. A saved scan from an older build can still carry one,
/// so each keeps the class it always had.
pub const LEGACY: &[SourceProfile] = &[
    row("acnc_charities", C::IdentityRegistry, None),
    row("ahpra", C::IdentityRegistry, None),
    row("atproto", C::Other, Some(C::Social)),
    row("au_electoral", C::IdentityRegistry, None),
    row("au_people", C::IdentityRegistry, None),
    row("bgpview", C::Infra, None),
    row("comb_search", C::Breach, None),
    row("contact_enrich", C::IdentityRegistry, None),
    row("criminal_ip", C::Infra, None),
    row("dns_intel", C::Infra, None),
    row("domainsdb", C::Infra, None),
    row("emailrep", C::EmailIntel, None),
    row("epieos", C::Presence, None),
    row("exa_search", C::Search, None),
    row("fullcontact", C::IdentityRegistry, None),
    row("intelx", C::Breach, None),
    row("ip2location", C::Infra, None),
    row("ip_geo", C::Infra, None),
    row("ip_whois_geo", C::Infra, None),
    row("leakcheck_public", C::Breach, None),
    row("mylnikov", C::Infra, None),
    row("niamonx", C::Breach, None),
    row("oathnet_pro", C::Breach, None),
    row("onyphe", C::Infra, None),
    row("portscan", C::Infra, None),
    row("proxycurl", C::IdentityRegistry, None),
    row("psbdmp", C::Breach, None),
    row("pwned_passwords", C::Breach, None),
    row("rdap_legs", C::Other, Some(C::Infra)),
    row("reddit_user", C::Forum, None),
    row("search_engines", C::Search, None),
    // The ID the legacy 7dca720 build wrote for SeekNow; its consensus fixture still uses it.
    row("see_know", C::Breach, None),
    row("smtp_vrfy", C::EmailIntel, None),
    row("social_probe", C::Social, None),
    row("username_search", C::Presence, None),
    row("xposedornot", C::Other, Some(C::Breach)),
    row("zoomeye", C::Infra, None),
];

/// The profile of `source`, matched as the classifiers always matched it: trimmed and lowercased.
#[must_use]
pub fn profile(source: &str) -> Option<&'static SourceProfile> {
    let id = source.trim().to_ascii_lowercase();
    [PROFILES, LEGACY].into_iter().find_map(|table| {
        table
            .binary_search_by(|row| row.id.cmp(id.as_str()))
            .ok()
            .map(|at| &table[at])
    })
}

/// The class the correlator counts `source` under.
#[must_use]
pub fn family(source: &str) -> SourceClass {
    profile(source).map_or_else(|| by_name(source), |row| row.family)
}

/// The acquisition modality of `source`: its profile's, else its family.
#[must_use]
pub fn modality(source: &str) -> SourceClass {
    profile(source).map_or_else(|| by_name(source), SourceProfile::modality)
}

/// The class of an ID neither table holds, from words in its name, as before the table existed.
#[must_use]
pub fn by_name(source: &str) -> SourceClass {
    let source = source.trim().to_ascii_lowercase();
    if source.contains("github") || source.contains("npm") {
        SourceClass::Code
    } else if source.contains("forum") || source.contains("reddit") {
        SourceClass::Forum
    } else if source.contains("search") {
        SourceClass::Search
    } else if source.contains("mail") || source.contains("smtp") {
        SourceClass::EmailIntel
    } else if source.contains("dns") || source.contains("geo") || source.contains("ip") {
        SourceClass::Infra
    } else {
        SourceClass::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_table_is_sorted_unique_and_lowercase() {
        for table in [PROFILES, LEGACY] {
            for pair in table.windows(2) {
                assert!(pair[0].id < pair[1].id, "{} is out of order", pair[1].id);
            }
            for row in table {
                assert_eq!(row.id, row.id.trim().to_ascii_lowercase(), "{}", row.id);
            }
        }
        for row in LEGACY {
            assert!(
                PROFILES
                    .binary_search_by(|live| live.id.cmp(row.id))
                    .is_err(),
                "{} is in both tables",
                row.id
            );
        }
    }

    #[test]
    fn the_correlator_family_never_takes_a_modality_only_class() {
        for row in PROFILES.iter().chain(LEGACY) {
            assert!(
                !matches!(
                    row.family,
                    SourceClass::KnowledgeGraph | SourceClass::Geoint | SourceClass::Transport
                ),
                "{}",
                row.id
            );
            assert_ne!(
                row.modality,
                Some(row.family),
                "{} repeats its family",
                row.id
            );
        }
    }

    /// B1 and B2. The correlator's arms named `acnc_charities` and `exa_search`, which no collector
    /// writes, so ACNC and Exa evidence counted as `other`; `wikipedia` matched the `ip` in its
    /// name and counted as infrastructure. Each is now classed as what it is.
    #[test]
    fn acnc_exa_and_wikipedia_are_classed_as_what_they_are() {
        assert_eq!(family("acnc"), SourceClass::IdentityRegistry);
        assert_eq!(modality("acnc"), SourceClass::IdentityRegistry);
        assert_eq!(family("exa"), SourceClass::Search);
        assert_eq!(modality("exa"), SourceClass::Search);
        assert_eq!(family("wikipedia"), SourceClass::Other);
        assert_eq!(modality("wikipedia"), SourceClass::Other);
    }

    #[test]
    fn an_id_is_matched_trimmed_and_lowercased_and_an_unknown_one_by_its_name() {
        assert_eq!(family("  HIBP "), SourceClass::Breach);
        assert_eq!(modality("Gitlab_User"), SourceClass::Code);
        assert_eq!(family("Gitlab_User"), SourceClass::Other);
        assert_eq!(family("zz_unknown_mailer"), SourceClass::EmailIntel);
        assert_eq!(modality("zz_unknown_mailer"), SourceClass::EmailIntel);
        assert_eq!(family("zz_unknown"), SourceClass::Other);
    }
}
