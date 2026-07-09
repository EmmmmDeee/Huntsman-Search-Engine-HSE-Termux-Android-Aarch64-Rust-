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

/// Explicit ROI classification for known services.
///
/// Kept as an inspectable `const` table (rather than `match` arms) so a
/// drift-guard can enumerate every classified service and assert each is a real
/// service name the key-harvester can actually emit — the check that would have
/// caught the `xposed_or_not` → `xposedornot` spelling drift, where a
/// misspelled arm silently classified nothing. Each service names the value the
/// harvester writes to `FoundKey.service` (NOT the HSE module id); a harvested
/// XposedOrNot key is tagged `xposedornot`, so the underscored module id
/// `xposed_or_not` (an evidence source elsewhere) must never appear here.
///
/// A service absent from this table falls through to `KeyRoi::Expansion` in
/// [`classify`]. The `Expansion` rows below are therefore behaviourally
/// identical to the default; they are listed explicitly to record intent (and so
/// the guard treats them as known, deliberate classifications).
const ROI_TABLE: &[(&str, KeyRoi)] = &[
    // ── MULTIPLIER ──────────────────────────────────────────────
    // Self-discovery: finding more OathNet keys directly scales our OathNet
    // quota — each discovered key is a parallel daily-lookup pool.
    ("oathnet", KeyRoi::Multiplier),
    // OathNet competitors — same breach/stealer surface, separate quota pools.
    ("see_know", KeyRoi::Multiplier),
    ("snusbase", KeyRoi::Multiplier),
    ("leakcheck", KeyRoi::Multiplier),
    ("leakpeek", KeyRoi::Multiplier),
    ("leak_lookup", KeyRoi::Multiplier),
    ("hashes", KeyRoi::Multiplier),
    ("psbdmp", KeyRoi::Multiplier),
    ("ghostproject", KeyRoi::Multiplier),
    ("scylla", KeyRoi::Multiplier),
    ("weleakinfo", KeyRoi::Multiplier),
    ("hackcheck", KeyRoi::Multiplier),
    ("scrubd", KeyRoi::Multiplier),
    ("nuclearleaks", KeyRoi::Multiplier),
    ("breachforums", KeyRoi::Multiplier),
    ("inteltechniques", KeyRoi::Multiplier),
    ("breachdirectory", KeyRoi::Multiplier),
    // Infrastructure → hostnames → web_crawler → leaked keys.
    ("shodan", KeyRoi::Multiplier),
    ("censys", KeyRoi::Multiplier),
    ("securitytrails", KeyRoi::Multiplier),
    ("fullhunt", KeyRoi::Multiplier),
    ("binaryedge", KeyRoi::Multiplier),
    ("passivetotal", KeyRoi::Multiplier),
    ("onyphe", KeyRoi::Multiplier),
    ("zoomeye", KeyRoi::Multiplier),
    ("netlas", KeyRoi::Multiplier),
    ("fofa", KeyRoi::Multiplier),
    ("spyse", KeyRoi::Multiplier),
    ("leakix", KeyRoi::Multiplier),
    ("urlscan", KeyRoi::Multiplier),
    // Domain/URL intelligence → more domains → more crawl surface.
    ("virustotal", KeyRoi::Multiplier),
    ("criminal_ip", KeyRoi::Multiplier),
    ("whoisxml", KeyRoi::Multiplier),
    ("builtwith", KeyRoi::Multiplier),
    // Identity enumeration → more emails → new OathNet targets.
    ("hunter", KeyRoi::Multiplier),
    ("proxycurl", KeyRoi::Multiplier),
    ("epieos", KeyRoi::Multiplier),
    ("emailrep", KeyRoi::Multiplier),
    ("seon", KeyRoi::Multiplier),
    // Source-code key leaks.
    ("github", KeyRoi::Multiplier),
    ("gitlab", KeyRoi::Multiplier),
    // Semantic search → URLs → web_crawler → leaked keys.
    ("exa", KeyRoi::Multiplier),
    // Breach-with-credentials services — directly contain creds for OTHER
    // services, leading to more keys via key_harvest.
    ("hibp", KeyRoi::Multiplier),
    ("dehashed", KeyRoi::Multiplier),
    ("intelx", KeyRoi::Multiplier),
    ("hudsonrock", KeyRoi::Multiplier),
    ("xposedornot", KeyRoi::Multiplier),

    // ── EXPANSION (explicit; same as the default, recorded for intent) ──
    // Many entities per target but no chain back to keys.
    ("opencorporates", KeyRoi::Expansion),
    ("abn", KeyRoi::Expansion),
    ("wigle", KeyRoi::Expansion),
    ("opencellid", KeyRoi::Expansion),
    ("mailchimp", KeyRoi::Expansion),
    ("twilio", KeyRoi::Expansion),

    // ── TERMINAL ────────────────────────────────────────────────
    // Single-shot scoring or geolocation.
    ("abuseipdb", KeyRoi::Terminal),
    ("greynoise", KeyRoi::Terminal),
    ("ipqs", KeyRoi::Terminal),
    ("ipinfo", KeyRoi::Terminal),
    ("ip2location", KeyRoi::Terminal),
    ("ipregistry", KeyRoi::Terminal),
    ("ipquery", KeyRoi::Terminal),
    ("numverify", KeyRoi::Terminal),
    ("pulsedive", KeyRoi::Terminal),
    ("threatfox", KeyRoi::Terminal),
    ("sunrise_sunset", KeyRoi::Terminal),
    ("c99", KeyRoi::Terminal),
];

/// The full explicit ROI classification table — every `(service, tier)` HSE
/// deliberately assigns. Exposed so a cross-registry drift-guard (in
/// `oathnet_pro::key_harvest`, which can reach both this and the harvester's
/// emit vocabulary — a layering the reverse would violate) can assert every
/// non-`Expansion` service here is really emittable.
#[must_use]
pub fn roi_table() -> &'static [(&'static str, KeyRoi)] {
    ROI_TABLE
}

/// Classify a service by its key-discovery ROI tier.
///
/// MULTIPLIER tier produces Domain/Url/Email entities that feed
/// web_crawler, search_engines, or another OathNet round — each
/// producing more keys. A service not in [`ROI_TABLE`] is assumed
/// moderate value (`Expansion`).
#[must_use]
pub fn classify(service: &str) -> KeyRoi {
    ROI_TABLE
        .iter()
        .find(|(name, _)| *name == service)
        .map_or(KeyRoi::Expansion, |(_, roi)| *roi)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
