//! Canonical API-provider category for a `HUNTSMAN_*` credential key.
//!
//! Single-sourced so `hse credentials list` (`cli::credentials`) and the
//! `hse doctor` embedded-credentials report (`app::doctor::embedded_validation`)
//! always agree on which bucket a key falls into, instead of each keeping its
//! own drifting copy of the same `contains(...)` chain.

/// The provider category for a `HUNTSMAN_*` key name, by substring match on
/// the key itself (e.g. `HUNTSMAN_SHODAN_KEY` contains `SHODAN`).
///
/// Order matters where a key could match more than one arm (e.g. GitHub is
/// excluded from `HUNTSMAN_GITHUB_COMMITS_*` style keys some day) — first
/// match wins.
#[must_use]
pub fn category_for(key: &str) -> &'static str {
    match key {
        // Threat Intelligence & Malware
        k if k.contains("VIRUSTOTAL") => "Threat Intelligence",
        k if k.contains("GREYNOISE") => "Threat Intelligence",
        k if k.contains("URLSCAN") => "Threat Intelligence",
        k if k.contains("ABUSEIPDB") => "Threat Intelligence",
        k if k.contains("THREATFOX") => "Threat Intelligence",
        k if k.contains("ABUSECH") => "Threat Intelligence",

        // Breach & Intelligence
        k if k.contains("SEEKNOW") => "Breach Intelligence",
        k if k.contains("HIBP") => "Breach Intelligence",
        k if k.contains("INTELLIGENCE_X") || k.contains("INTELX") => "Breach Intelligence",
        k if k.contains("OATHNET") => "Breach Intelligence",
        k if k.contains("STOLEN") => "Breach Intelligence",
        k if k.contains("DEHASHED") => "Breach Intelligence",

        // Infrastructure/IP/Domain
        k if k.contains("SHODAN") => "Infrastructure Intelligence",
        k if k.contains("SECURITYTRAILS") || k.contains("SECTRAILS") => {
            "Infrastructure Intelligence"
        }
        k if k.contains("LEAKIX") => "Infrastructure Intelligence",
        k if k.contains("CRIMINALIP") => "Infrastructure Intelligence",
        k if k.contains("IPQUALITYSCORE") || k.contains("IPQS") => "Infrastructure Intelligence",
        k if k.contains("CENSYS") => "Infrastructure Intelligence",
        k if k.contains("FOFA") => "Infrastructure Intelligence",
        k if k.contains("NETLAS") => "Infrastructure Intelligence",
        k if k.contains("ONYPHE") => "Infrastructure Intelligence",
        k if k.contains("WHOISXML") => "Infrastructure Intelligence",
        k if k.contains("DOMAINSDB") => "Infrastructure Intelligence",
        k if k.contains("OSINTCAT") => "Infrastructure Intelligence",

        // Identity/Person
        k if k.contains("PROXYCURL") => "Identity Intelligence",
        k if k.contains("HUNTER") => "Identity Intelligence",
        k if k.contains("EMAILREP") => "Identity Intelligence",
        k if k.contains("GITHUB") && !k.contains("COMMITS") => "Identity Intelligence",
        k if k.contains("FULLCONTACT") => "Identity Intelligence",
        k if k.contains("SEON") => "Identity Intelligence",
        k if k.contains("TROVE") => "Identity Intelligence",

        // Telecommunications
        k if k.contains("NUMVERIFY") => "Telecommunications",
        k if k.contains("OPENCNAM") => "Telecommunications",
        k if k.contains("EPIEOS") => "Telecommunications",
        k if k.contains("NIAMONX") => "Telecommunications",
        k if k.contains("HLR") => "Telecommunications",

        // Geolocation
        k if k.contains("WIGLE") => "Geolocation",
        k if k.contains("OPENCELLID") => "Geolocation",

        // Business Intelligence
        k if k.contains("OPENCORPORATES") || k.contains("OPENCORP") => "Business Intelligence",
        k if k.contains("OPENSANCTIONS") => "Business Intelligence",
        k if k.contains("BUILTWITH") => "Business Intelligence",

        // Search & AI
        k if k.contains("EXA") => "Search & AI",
        k if k.contains("ALIENVAULT") => "Search & AI",
        k if k.contains("ZOOMEYE") => "Search & AI",

        _ => "Other Services",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_resolve_to_the_expected_category() {
        assert_eq!(
            category_for("HUNTSMAN_SHODAN_KEY"),
            "Infrastructure Intelligence"
        );
        assert_eq!(
            category_for("HUNTSMAN_VIRUSTOTAL_KEY"),
            "Threat Intelligence"
        );
        assert_eq!(category_for("HUNTSMAN_HIBP_KEY"), "Breach Intelligence");
        assert_eq!(
            category_for("HUNTSMAN_GITHUB_TOKEN"),
            "Identity Intelligence"
        );
        assert_eq!(category_for("HUNTSMAN_WIGLE_TOKEN"), "Geolocation");
    }

    #[test]
    fn unknown_key_falls_back_to_other_services() {
        assert_eq!(
            category_for("HUNTSMAN_NOT_A_REAL_PROVIDER_KEY"),
            "Other Services"
        );
    }
}
