//! Catalogue of OSINT / recon / breach / threat-intel API providers, by category.
//!
//! A harvested API key is not just a credential — *which provider* it belongs to
//! is itself intelligence. A key for Shodan, Dehashed, IntelX, Maltego or Hunter
//! found in a victim's stealer log says its owner **runs OSINT** — they are a
//! fellow practitioner, an investigator, a researcher, or an adversary doing
//! reconnaissance. That makes such a key a first-class OSINT *pivot*: from the
//! key's provider you learn the holder's tradecraft, tooling and likely intent.
//!
//! This module is the single source of truth for "is service X an OSINT
//! provider, and in which category?". It deliberately classifies only the
//! recon/intelligence services — generic infra (AWS, Stripe, GitHub, MongoDB)
//! returns `None` and is never flagged as practitioner tooling.
//!
//! Retention-only: classifying a key never authenticates with it. The category
//! drives tags + the OSINT-practitioner correlation, not any reuse.

/// The functional category an OSINT provider falls under. Drives the
/// `osint-category:<slug>` tag and lets the correlator describe a holder's
/// tradecraft (breach-hunting vs attack-surface mapping vs people-search …).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OsintCategory {
    /// Breach / leak / stealer-credential databases.
    BreachLeak,
    /// Internet-wide host / port / attack-surface scanners.
    AttackSurface,
    /// Malware / abuse / reputation threat-intelligence.
    ThreatIntel,
    /// Email, identity and people-search enrichment.
    EmailPeople,
    /// Phone-number intelligence / validation.
    Phone,
    /// IP geolocation / ASN / network context.
    IpGeo,
    /// Search-result / SERP / scraping APIs used for recon.
    Search,
    /// Domain, WHOIS, DNS and certificate intelligence.
    DomainCert,
    /// Corporate / company-registry intelligence.
    Corporate,
    /// Geolocation of wireless / cell / wifi infrastructure.
    WirelessGeo,
    /// Social-media / username link-analysis platforms & toolkits.
    SocialLinkAnalysis,
}

impl OsintCategory {
    /// Stable slug for the `osint-category:<slug>` tag.
    pub fn slug(self) -> &'static str {
        match self {
            Self::BreachLeak => "breach-leak",
            Self::AttackSurface => "attack-surface",
            Self::ThreatIntel => "threat-intel",
            Self::EmailPeople => "email-people",
            Self::Phone => "phone-intel",
            Self::IpGeo => "ip-geo",
            Self::Search => "search-recon",
            Self::DomainCert => "domain-cert",
            Self::Corporate => "corporate",
            Self::WirelessGeo => "wireless-geo",
            Self::SocialLinkAnalysis => "social-link-analysis",
        }
    }
}

use OsintCategory::*;

/// The authoritative OSINT-provider catalogue: `(service_tag, category)`.
///
/// Service tags match the vocabulary the harvester emits (the `service_domains`
/// / `osint_keys` / `patterns` tables in `key_harvest`) and the `service` field
/// the `key_vault` stores, so a key attributed by *any* path (prefix,
/// context+shape, or URL domain) is classified consistently. Sorted within each
/// category for readability; the order is not load-bearing (lookup is by tag).
pub const OSINT_SERVICES: &[(&str, OsintCategory)] = &[
    // ── Breach / leak / stealer-credential databases ────────────────────────
    ("oathnet", BreachLeak),
    ("see_know", BreachLeak),
    ("dehashed", BreachLeak),
    ("snusbase", BreachLeak),
    ("intelx", BreachLeak),
    ("leakcheck", BreachLeak),
    ("leakpeek", BreachLeak),
    ("leak_lookup", BreachLeak),
    ("leakbase", BreachLeak),
    ("hashes", BreachLeak),
    ("psbdmp", BreachLeak),
    ("ghostproject", BreachLeak),
    ("scylla", BreachLeak),
    ("weleakinfo", BreachLeak),
    ("hackcheck", BreachLeak),
    ("scrubd", BreachLeak),
    ("nuclearleaks", BreachLeak),
    ("breachdirectory", BreachLeak),
    ("breachforums", BreachLeak),
    ("hibp", BreachLeak),
    ("hudsonrock", BreachLeak),
    ("proxynova", BreachLeak),
    ("scatteredsecrets", BreachLeak),
    ("xposedornot", BreachLeak),
    ("leakradar", BreachLeak),
    ("inteltechniques", BreachLeak),
    // ── Internet-wide attack-surface scanners ───────────────────────────────
    ("shodan", AttackSurface),
    ("censys", AttackSurface),
    ("binaryedge", AttackSurface),
    ("zoomeye", AttackSurface),
    ("fofa", AttackSurface),
    ("netlas", AttackSurface),
    ("onyphe", AttackSurface),
    ("fullhunt", AttackSurface),
    ("criminal_ip", AttackSurface),
    ("leakix", AttackSurface),
    ("spyse", AttackSurface),
    ("quake", AttackSurface),
    ("hunter_how", AttackSurface),
    ("odin", AttackSurface),
    // ── Threat intelligence ─────────────────────────────────────────────────
    ("virustotal", ThreatIntel),
    ("abuseipdb", ThreatIntel),
    ("greynoise", ThreatIntel),
    ("pulsedive", ThreatIntel),
    ("threatfox", ThreatIntel),
    ("urlscan", ThreatIntel),
    ("alienvault_otx", ThreatIntel),
    ("hybrid_analysis", ThreatIntel),
    ("malwarebazaar", ThreatIntel),
    ("anyrun", ThreatIntel),
    ("maltiverse", ThreatIntel),
    ("xforce", ThreatIntel),
    ("polyswarm", ThreatIntel),
    ("threatminer", ThreatIntel),
    ("passivetotal", ThreatIntel),
    ("riskiq", ThreatIntel),
    // ── Email / identity / people search ────────────────────────────────────
    ("hunter", EmailPeople),
    ("snov", EmailPeople),
    ("clearbit", EmailPeople),
    ("fullcontact", EmailPeople),
    ("apollo", EmailPeople),
    ("rocketreach", EmailPeople),
    ("pipl", EmailPeople),
    ("emailrep", EmailPeople),
    ("tomba", EmailPeople),
    ("anymailfinder", EmailPeople),
    ("voilanorbert", EmailPeople),
    ("dropcontact", EmailPeople),
    ("peopledatalabs", EmailPeople),
    ("seon", EmailPeople),
    ("epieos", EmailPeople),
    ("proxycurl", EmailPeople),
    ("predictasearch", EmailPeople),
    ("osint_industries", EmailPeople),
    ("castrick", EmailPeople),
    ("skymem", EmailPeople),
    // ── Phone intelligence ──────────────────────────────────────────────────
    ("numverify", Phone),
    ("numlookup", Phone),
    ("veriphone", Phone),
    ("ipqs", Phone),
    ("hlr_lookups", Phone),
    ("abstractapi_phone", Phone),
    // ── IP geolocation / ASN ────────────────────────────────────────────────
    ("ipinfo", IpGeo),
    ("ip2location", IpGeo),
    ("ipgeolocation", IpGeo),
    ("ipstack", IpGeo),
    ("ipdata", IpGeo),
    ("ipregistry", IpGeo),
    ("maxmind", IpGeo),
    ("ipquery", IpGeo),
    // ── Search / SERP / scraping for recon ──────────────────────────────────
    ("serpapi", Search),
    ("serper", Search),
    ("zenserp", Search),
    ("exa", Search),
    ("brave_search", Search),
    ("google_cse", Search),
    ("bing_search", Search),
    ("dataforseo", Search),
    ("scraperapi", Search),
    ("scrapingbee", Search),
    // ── Domain / WHOIS / DNS / cert ─────────────────────────────────────────
    ("securitytrails", DomainCert),
    ("whoisxml", DomainCert),
    ("whoxy", DomainCert),
    ("domaintools", DomainCert),
    ("ip2whois", DomainCert),
    ("viewdns", DomainCert),
    ("builtwith", DomainCert),
    ("c99", DomainCert),
    ("dnsdumpster", DomainCert),
    // ── Corporate registries ────────────────────────────────────────────────
    ("opencorporates", Corporate),
    // ── Wireless / cell geolocation ─────────────────────────────────────────
    ("wigle", WirelessGeo),
    ("opencellid", WirelessGeo),
    // ── Social / username link-analysis platforms & toolkits ────────────────
    ("sociallinks", SocialLinkAnalysis),
    ("maltego", SocialLinkAnalysis),
    ("lampyre", SocialLinkAnalysis),
    ("spiderfoot", SocialLinkAnalysis),
];

/// The OSINT category of `service`, or `None` when it is not an OSINT/recon
/// provider (generic infra, AI, payment, dev tooling). Exact-tag match — the
/// service tags are a fixed, snake-case vocabulary. Pure.
pub fn osint_category(service: &str) -> Option<OsintCategory> {
    OSINT_SERVICES
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn no_duplicate_service_tags() {
        let mut seen = BTreeSet::new();
        for (svc, _) in OSINT_SERVICES {
            assert!(seen.insert(*svc), "duplicate OSINT service tag: {svc}");
        }
    }

    #[test]
    fn service_tags_are_snake_case_nonempty() {
        for (svc, _) in OSINT_SERVICES {
            assert!(!svc.is_empty(), "empty service tag");
            assert!(
                svc.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "service tag not snake_case: {svc}"
            );
        }
    }

    #[test]
    fn classifies_known_osint_and_rejects_infra() {
        assert_eq!(osint_category("shodan"), Some(OsintCategory::AttackSurface));
        assert_eq!(osint_category("dehashed"), Some(OsintCategory::BreachLeak));
        assert_eq!(osint_category("hunter"), Some(OsintCategory::EmailPeople));
        assert_eq!(
            osint_category("maltego"),
            Some(OsintCategory::SocialLinkAnalysis)
        );
        assert!(osint_category("intelx").is_some());
        // Generic infra / AI / payment must NOT be flagged as OSINT tooling.
        for infra in [
            "openai",
            "aws",
            "stripe",
            "github",
            "twilio",
            "mongodb_atlas",
        ] {
            assert!(
                osint_category(infra).is_none(),
                "{infra} wrongly flagged OSINT"
            );
        }
    }

    #[test]
    fn every_category_has_at_least_one_provider() {
        use OsintCategory::*;
        for cat in [
            BreachLeak,
            AttackSurface,
            ThreatIntel,
            EmailPeople,
            Phone,
            IpGeo,
            Search,
            DomainCert,
            Corporate,
            WirelessGeo,
            SocialLinkAnalysis,
        ] {
            assert!(
                OSINT_SERVICES.iter().any(|(_, c)| *c == cat),
                "category {cat:?} has no providers"
            );
        }
    }
}
