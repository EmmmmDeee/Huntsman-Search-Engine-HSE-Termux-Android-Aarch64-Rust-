//! MITRE ATT&CK® **Reconnaissance** tactic (TA0043) alignment.
//!
//! ATT&CK's Reconnaissance tactic is the framework's taxonomy of adversary
//! OSINT *collection* — gathering victim identity / network / org / host
//! information, and searching open websites, victim-owned sites and open
//! technical databases. HSE performs exactly this class of collection (for
//! authorised, defensive purposes), so mapping each module to the technique it
//! implements lets the tool speak the standard vocabulary: a finding can be
//! traced to the ATT&CK technique that produced it, and operators can report
//! Reconnaissance *coverage* and gaps the way they would any ATT&CK assessment.
//!
//! This catalogues the **complete** Reconnaissance tactic (TA0043): all ten
//! techniques and every sub-technique, so the tool holds the whole tactic rather
//! than only the slice its own modules exercise. That completeness is what makes
//! a *coverage* report honest — a technique HSE performs no collection for (e.g.
//! `T1598` Phishing for Information) shows as a real, named gap instead of being
//! silently absent from the vocabulary. It is deliberately scoped to TA0043: the
//! other Enterprise tactics describe post-compromise adversary behaviour a
//! passive OSINT collector does not perform, so claiming them would be a false
//! coverage assertion — the one thing this evidentiary tool must never make.
//! Pure data + lookups; no I/O (no ~mb STIX bundle is vendored). A drift-guard
//! test pins that every technique the module map references exists here, and a
//! completeness test pins that every real TA0043 id is present, so neither the
//! catalogue nor the module map can silently drift.

use crate::core::module::ModuleCategory;
use serde::Serialize;

/// The MITRE ATT&CK Enterprise tactic this catalogue represents in full.
pub const TACTIC_ID: &str = "TA0043";
/// Human-readable name of [`TACTIC_ID`].
pub const TACTIC_NAME: &str = "Reconnaissance";

/// One ATT&CK Reconnaissance technique (or sub-technique) HSE's collection maps
/// to. `id` is the canonical ATT&CK identifier (`T1596.002`); sub-techniques
/// use the dotted form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    /// Canonical ATT&CK ID, e.g. `T1589.002`.
    pub id: &'static str,
    /// ATT&CK technique name, e.g. "Email Addresses".
    pub name: &'static str,
}

/// The curated Reconnaissance technique catalogue, kept sorted by `id` for
/// stable output and easy review. Every ID referenced by
/// [`techniques_for_category`] (and any module override) must appear here — the
/// `every_module_maps_to_valid_attack_reconnaissance_techniques` architecture
/// guard (and the in-module `every_category_maps_only_to_catalogued_ids` test)
/// enforce it.
pub const RECONNAISSANCE: &[Technique] = &[
    Technique {
        id: "T1589",
        name: "Gather Victim Identity Information",
    },
    Technique {
        id: "T1589.001",
        name: "Credentials",
    },
    Technique {
        id: "T1589.002",
        name: "Email Addresses",
    },
    Technique {
        id: "T1589.003",
        name: "Employee Names",
    },
    Technique {
        id: "T1590",
        name: "Gather Victim Network Information",
    },
    Technique {
        id: "T1590.001",
        name: "Domain Properties",
    },
    Technique {
        id: "T1590.002",
        name: "DNS",
    },
    Technique {
        id: "T1590.003",
        name: "Network Trust Dependencies",
    },
    Technique {
        id: "T1590.004",
        name: "Network Topology",
    },
    Technique {
        id: "T1590.005",
        name: "IP Addresses",
    },
    Technique {
        id: "T1590.006",
        name: "Network Security Appliances",
    },
    Technique {
        id: "T1591",
        name: "Gather Victim Org Information",
    },
    Technique {
        id: "T1591.001",
        name: "Determine Physical Locations",
    },
    Technique {
        id: "T1591.002",
        name: "Business Relationships",
    },
    Technique {
        id: "T1591.003",
        name: "Identify Business Tempo",
    },
    Technique {
        id: "T1591.004",
        name: "Identify Roles",
    },
    Technique {
        id: "T1592",
        name: "Gather Victim Host Information",
    },
    Technique {
        id: "T1592.001",
        name: "Hardware",
    },
    Technique {
        id: "T1592.002",
        name: "Software",
    },
    Technique {
        id: "T1592.003",
        name: "Firmware",
    },
    Technique {
        id: "T1592.004",
        name: "Client Configurations",
    },
    Technique {
        id: "T1593",
        name: "Search Open Websites/Domains",
    },
    Technique {
        id: "T1593.001",
        name: "Social Media",
    },
    Technique {
        id: "T1593.002",
        name: "Search Engines",
    },
    Technique {
        id: "T1593.003",
        name: "Code Repositories",
    },
    Technique {
        id: "T1594",
        name: "Search Victim-Owned Websites",
    },
    Technique {
        id: "T1595",
        name: "Active Scanning",
    },
    Technique {
        id: "T1595.001",
        name: "Scanning IP Blocks",
    },
    Technique {
        id: "T1595.002",
        name: "Vulnerability Scanning",
    },
    Technique {
        id: "T1595.003",
        name: "Wordlist Scanning",
    },
    Technique {
        id: "T1596",
        name: "Search Open Technical Databases",
    },
    Technique {
        id: "T1596.001",
        name: "DNS/Passive DNS",
    },
    Technique {
        id: "T1596.002",
        name: "WHOIS",
    },
    Technique {
        id: "T1596.003",
        name: "Digital Certificates",
    },
    Technique {
        id: "T1596.004",
        name: "CDNs",
    },
    Technique {
        id: "T1596.005",
        name: "Scan Databases",
    },
    Technique {
        id: "T1597",
        name: "Search Closed Sources",
    },
    Technique {
        id: "T1597.001",
        name: "Threat Intel Vendors",
    },
    Technique {
        id: "T1597.002",
        name: "Purchase Technical Data",
    },
    Technique {
        id: "T1598",
        name: "Phishing for Information",
    },
    Technique {
        id: "T1598.001",
        name: "Spearphishing Service",
    },
    Technique {
        id: "T1598.002",
        name: "Spearphishing Attachment",
    },
    Technique {
        id: "T1598.003",
        name: "Spearphishing Link",
    },
    Technique {
        id: "T1598.004",
        name: "Spearphishing Voice",
    },
];

/// The catalogued technique with this ID, if any.
#[must_use]
pub fn technique(id: &str) -> Option<&'static Technique> {
    RECONNAISSANCE.iter().find(|t| t.id == id)
}

/// The complete-tactic techniques for which `is_covered` returns `false` — the
/// honest Reconnaissance *gaps* for a coverage set (typically the union of every
/// module's [`crate::core::module::Module::attack_techniques`]). Returned in the
/// catalogue's sorted order. Because the catalogue is the full TA0043 tactic, a
/// gap report built on this names exactly which techniques HSE performs no
/// collection for, instead of quietly implying total coverage.
#[must_use]
pub fn uncovered(is_covered: impl Fn(&str) -> bool) -> Vec<&'static Technique> {
    RECONNAISSANCE
        .iter()
        .filter(|t| !is_covered(t.id))
        .collect()
}

/// The ATT&CK Reconnaissance technique IDs a module's functional
/// [`ModuleCategory`] implements — the **default** mapping every module inherits
/// (a module whose category is too coarse, e.g. an active scanner sitting in
/// `Infrastructure`, overrides [`crate::core::module::Module::attack_techniques`]
/// directly). Category-level is the right granularity for the default because
/// the category already encodes what kind of collection the module performs.
#[must_use]
pub fn techniques_for_category(cat: ModuleCategory) -> &'static [&'static str] {
    match cat {
        // DNS / cert / WHOIS recon is the canonical "search open technical
        // databases" + "gather network information" cluster.
        ModuleCategory::DnsRecon => &[
            "T1590.001",
            "T1590.002",
            "T1596.001",
            "T1596.002",
            "T1596.003",
        ],
        // Breach corpora expose leaked credentials and email addresses.
        ModuleCategory::Breach => &["T1589.001", "T1589.002"],
        // IP/ASN/Shodan-style infra intel: network IPs via open scan databases.
        ModuleCategory::Infrastructure => &["T1590.005", "T1596.005"],
        // Search-engine scraping.
        ModuleCategory::Search => &["T1593.002"],
        // Social profiles + the employee/handle names they reveal.
        ModuleCategory::Social => &["T1593.001", "T1589.003"],
        ModuleCategory::Email => &["T1589.002"],
        // No phone sub-technique exists; phone metadata is victim identity info.
        ModuleCategory::Phone => &["T1589"],
        // Company registry / directorship / role intel.
        ModuleCategory::Corporate => &["T1591.002", "T1591.004"],
        // Malware/C2/abuse lists are bought-or-free threat-intel vendor data.
        ModuleCategory::Threat => &["T1597.001"],
        // Local device sensors gather host information.
        ModuleCategory::Sensor => &["T1592"],
        // People-centric enrichment: employee names + their organisational role.
        ModuleCategory::People => &["T1589.003", "T1591.004"],
        // Site crawling / fingerprinting victim-owned sites and their software.
        ModuleCategory::Web => &["T1594", "T1592.002"],
        // Geolocation / address resolution → physical locations.
        ModuleCategory::Geo => &["T1591.001"],
        // Uncategorised — no claimed ATT&CK mapping.
        ModuleCategory::Other => &[],
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
