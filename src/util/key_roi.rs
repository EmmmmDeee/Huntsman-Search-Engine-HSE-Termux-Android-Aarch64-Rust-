//! Key ROI tiers — strategic prioritization for force multiplication.
//!
//! Principle: a discovered API key's value is proportional to how many
//! NEW entities (and ultimately NEW keys) it unlocks downstream. Keys
//! that lead to discovering more keys have exponential ROI compared to
//! keys that yield terminal data.
//!
//! Tiers:
//!
//! - `Multiplier` — discovers infrastructure or identities that feed
//!   back into key extraction. Shodan/Censys/SecurityTrails return
//!   hostnames + cert SANs that web_crawler can scan for leaked keys.
//!   Hunter.io enumerates company emails — each new email is a new
//!   OathNet target with its own breach/stealer credential exposure.
//!   Proxycurl returns work + personal emails from LinkedIn profiles.
//!   These keys CASCADE.
//!
//! - `Expansion` — discovers many entities but does not chain back to
//!   key discovery. HIBP returns breach names + dates. Dehashed returns
//!   more breach rows. These add depth but don't multiply.
//!
//! - `Terminal` — produces single-shot data per target with no chain.
//!   AbuseIPDB returns an abuse score. GreyNoise returns a noise tag.
//!   IP2Location returns coordinates. Valuable but one-and-done.
//!
//! Operational impact: when api_key_probe identifies a discovered key,
//! its tier informs:
//! - Reporting order (Multipliers first in the summary)
//! - Tag application ("force-multiplier" on the entity)
//! - Operator log prominence

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyRoi {
    /// Single-shot data, no chain to more keys.
    Terminal,
    /// Multi-entity output but doesn't lead to more keys.
    Expansion,
    /// Discovers infrastructure/identities that lead to more keys.
    /// THESE are the highest-ROI keys.
    Multiplier,
}

impl KeyRoi {
    pub fn label(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Expansion => "expansion",
            Self::Multiplier => "multiplier",
        }
    }
}

/// Classify a service by its key-discovery ROI tier.
///
/// MULTIPLIER tier produces Domain/Url/Email entities that feed
/// web_crawler, search_engines, or another OathNet round — each
/// producing more keys.
pub fn classify(service: &str) -> KeyRoi {
    match service {
        // ── MULTIPLIER ──────────────────────────────────────────────
        // Self-discovery: finding more OathNet keys directly scales our
        // OathNet quota. Each discovered key is a parallel daily-lookup
        // pool that costs us nothing.
        "oathnet"
        // OathNet competitors — same breach/stealer surface, separate
        // quota pools. Finding a see-know.eu or snusbase key means we
        // get their daily quota for free.
        | "see_know" | "snusbase" | "leakcheck" | "leakpeek" | "leak_lookup"
        | "hashes" | "psbdmp" | "ghostproject" | "scylla" | "weleakinfo"
        | "hackcheck" | "scrubd" | "nuclearleaks" | "breachforums"
        | "inteltechniques" | "breachdirectory"
        // Infrastructure → hostnames → web_crawler → leaked keys
        | "shodan" | "censys" | "securitytrails" | "fullhunt" | "binaryedge"
        | "passivetotal" | "onyphe" | "zoomeye" | "netlas" | "fofa"
        | "spyse" | "leakix" | "urlscan"
        // Domain/URL intelligence → more domains → more crawl surface
        | "virustotal" | "criminal_ip" | "whoisxml" | "builtwith"
        // Identity enumeration → more emails → new OathNet targets
        | "hunter" | "proxycurl" | "epieos" | "emailrep" | "seon"
        // Source-code key leaks
        | "github" | "gitlab"
        // Breach-with-credentials services (these directly contain creds
        // for OTHER services, leading to more keys)
        | "hibp" | "dehashed" | "intelx" | "hudsonrock" | "xposed_or_not"
        => KeyRoi::Multiplier,

        // ── EXPANSION ───────────────────────────────────────────────
        // Many entities per target but no chain back to keys.
        // (HIBP/Dehashed/IntelX/HudsonRock/XposedOrNot were promoted
        // to Multiplier — breach data contains credentials for OTHER
        // services, which yields more keys via key_harvest.)
        "opencorporates" | "abn" | "wigle" | "opencellid"
        | "mailchimp" | "twilio"
        => KeyRoi::Expansion,

        // ── TERMINAL ────────────────────────────────────────────────
        // Single-shot scoring or geolocation
        "abuseipdb" | "greynoise" | "ipqs" | "ipinfo" | "ipapi"
        | "ip2location" | "ipregistry" | "ipquery" | "numverify"
        | "pulsedive" | "threatfox" | "sunrise_sunset" | "c99"
        => KeyRoi::Terminal,

        // Unknown services default to Expansion (assume moderate value)
        _ => KeyRoi::Expansion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipliers_include_infrastructure_services() {
        assert_eq!(classify("shodan"), KeyRoi::Multiplier);
        assert_eq!(classify("censys"), KeyRoi::Multiplier);
        assert_eq!(classify("securitytrails"), KeyRoi::Multiplier);
        assert_eq!(classify("hunter"), KeyRoi::Multiplier);
        assert_eq!(classify("proxycurl"), KeyRoi::Multiplier);
    }

    #[test]
    fn multipliers_include_self_and_competitors() {
        // OathNet self-discovery — finding more OathNet keys scales
        // our own quota.
        assert_eq!(classify("oathnet"), KeyRoi::Multiplier);
        // Competitors — same data surface, parallel quota pools.
        assert_eq!(classify("see_know"), KeyRoi::Multiplier);
        assert_eq!(classify("snusbase"), KeyRoi::Multiplier);
        assert_eq!(classify("leakcheck"), KeyRoi::Multiplier);
        assert_eq!(classify("dehashed"), KeyRoi::Multiplier);
        assert_eq!(classify("hibp"), KeyRoi::Multiplier);
        assert_eq!(classify("intelx"), KeyRoi::Multiplier);
    }

    #[test]
    fn expansion_includes_non_key_services() {
        assert_eq!(classify("opencorporates"), KeyRoi::Expansion);
        assert_eq!(classify("wigle"), KeyRoi::Expansion);
    }

    #[test]
    fn terminal_includes_scoring_services() {
        assert_eq!(classify("abuseipdb"), KeyRoi::Terminal);
        assert_eq!(classify("greynoise"), KeyRoi::Terminal);
        assert_eq!(classify("ip2location"), KeyRoi::Terminal);
    }

    #[test]
    fn unknown_defaults_to_expansion() {
        assert_eq!(classify("some_unknown_service"), KeyRoi::Expansion);
    }

    #[test]
    fn ord_prioritises_multiplier() {
        assert!(KeyRoi::Multiplier > KeyRoi::Expansion);
        assert!(KeyRoi::Expansion > KeyRoi::Terminal);
    }
}
