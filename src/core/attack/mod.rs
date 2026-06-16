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
//! This is a curated subset of TA0043 — only the techniques HSE's keyless,
//! Termux-viable collection actually performs. It is **not** the full ATT&CK
//! corpus (a ~mb STIX bundle the project deliberately avoids vendoring). Pure
//! data + lookups; no I/O. A drift-guard test pins that every technique the
//! module map references exists in the catalogue here, so the two can't diverge.

use crate::core::module::ModuleCategory;
use serde::Serialize;

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

/// The ATT&CK tactic these techniques belong to — Reconnaissance.
pub const TACTIC_ID: &str = "TA0043";
/// Human name of [`TACTIC_ID`].
pub const TACTIC_NAME: &str = "Reconnaissance";

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
];

/// The catalogued technique with this ID, if any.
#[must_use]
pub fn technique(id: &str) -> Option<&'static Technique> {
    RECONNAISSANCE.iter().find(|t| t.id == id)
}

/// An ATT&CK Reconnaissance **coverage assessment** for one scan: the
/// catalogued techniques partitioned into those the scan's collection
/// `covered` and the `gaps` it did not exercise. Together they always equal the
/// full [`RECONNAISSANCE`] catalogue, so the pair is a complete assessment —
/// the "coverage *and gaps*" view any ATT&CK review produces.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    /// Techniques the scan exercised (sorted, deduplicated).
    pub covered: Vec<&'static Technique>,
    /// Catalogued techniques the scan did **not** exercise — the collection gaps.
    pub gaps: Vec<&'static Technique>,
}

impl Assessment {
    /// Partition the [`RECONNAISSANCE`] catalogue against a covered set (typically
    /// [`coverage`]'s output). Unknown IDs in `covered` are ignored — every entry
    /// is a catalogue technique — so `covered` and `gaps` always partition the
    /// catalogue exactly. **Pure.**
    #[must_use]
    pub fn from_covered(covered: Vec<&'static Technique>) -> Self {
        let ids: std::collections::HashSet<&str> = covered.iter().map(|t| t.id).collect();
        let gaps: Vec<&'static Technique> = RECONNAISSANCE
            .iter()
            .filter(|t| !ids.contains(t.id))
            .collect();
        Self { covered, gaps }
    }

    /// Share of the catalogue exercised, as a percentage in `[0, 100]`.
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        let total = self.covered.len() + self.gaps.len();
        if total == 0 {
            return 0.0;
        }
        (self.covered.len() as f64 / total as f64) * 100.0
    }
}

/// Build a MITRE ATT&CK **Navigator layer** (schema 4.5) marking each supplied
/// Reconnaissance technique as exercised (score 1). The JSON imports directly
/// into the ATT&CK Navigator (`https://mitre-attack.github.io/attack-navigator/`),
/// so an HSE scan's collection footprint is reviewable in the framework's own
/// visual surface — the same vocabulary a blue/red team already speaks.
///
/// **Pure.** `name` / `description` identify the source (e.g. a scan id);
/// `techniques` is typically [`coverage`]'s output. Output is deterministic
/// (techniques are emitted in the given order — pass a sorted slice for stable
/// diffs).
#[must_use]
pub fn navigator_layer(name: &str, description: &str, techniques: &[&Technique]) -> String {
    use serde_json::json;

    let techs: Vec<serde_json::Value> = techniques
        .iter()
        .map(|t| {
            json!({
                "techniqueID": t.id,
                "tactic": "reconnaissance",
                "score": 1,
                "enabled": true,
                "comment": t.name,
            })
        })
        .collect();

    let layer = json!({
        "name": name,
        "description": description,
        "domain": "enterprise-attack",
        "versions": { "attack": "15", "navigator": "4.9.5", "layer": "4.5" },
        "sorting": 0,
        "hideDisabled": true,
        "techniques": techs,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#096dd9"],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            { "label": "Exercised by this HSE scan", "color": "#096dd9" }
        ],
        "metadata": [
            { "name": "tactic", "value": TACTIC_NAME },
            { "name": "tactic_id", "value": TACTIC_ID },
            { "name": "generator", "value": "Huntsman Search Engine" }
        ]
    });

    // A `json!`-built value over string keys and finite numbers is always
    // serialisable; the pretty form is the canonical Navigator file shape.
    serde_json::to_string_pretty(&layer).expect("navigator layer is serialisable")
}

/// Resolve a set of technique IDs into their catalogue entries, deduplicated
/// and sorted by ID; unknown IDs are dropped. The shared reducer behind every
/// "which Reconnaissance techniques did this exercise" report — the module
/// catalogue view (`hse modules`) and the per-scan coverage view both funnel
/// through here, so a covered-technique list is computed one way everywhere.
#[must_use]
pub fn coverage<'a>(ids: impl IntoIterator<Item = &'a str>) -> Vec<&'static Technique> {
    let mut out: Vec<&'static Technique> = ids.into_iter().filter_map(technique).collect();
    out.sort_unstable_by_key(|t| t.id);
    out.dedup_by_key(|t| t.id);
    out
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
