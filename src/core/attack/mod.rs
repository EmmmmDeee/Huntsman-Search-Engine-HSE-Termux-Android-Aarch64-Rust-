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
];

/// The catalogued technique with this ID, if any.
#[must_use]
pub fn technique(id: &str) -> Option<&'static Technique> {
    RECONNAISSANCE.iter().find(|t| t.id == id)
}

/// The parent technique ID of a sub-technique (`T1596.002` → `T1596`), or `None`
/// for a top-level technique. Pure string split on the ATT&CK dotted form.
#[must_use]
pub fn parent_id(id: &str) -> Option<&str> {
    id.split_once('.').map(|(base, _)| base)
}

/// True when `id` is an ATT&CK sub-technique (dotted form, e.g. `T1590.005`).
#[must_use]
pub fn is_subtechnique(id: &str) -> bool {
    id.contains('.')
}

/// The catalogued sub-techniques of a parent technique ID (`T1596` →
/// `T1596.001..005`), sorted by ID for stable output. Empty for an unknown or
/// leaf ID. The `RECONNAISSANCE` catalogue is already ID-sorted, so the filtered
/// result inherits that order.
#[must_use]
pub fn subtechniques(base: &str) -> Vec<&'static Technique> {
    RECONNAISSANCE
        .iter()
        .filter(|t| parent_id(t.id) == Some(base))
        .collect()
}

/// Per-technique coverage within one scan: whether any finding was collected via
/// this Reconnaissance technique, how many, and the strongest such finding.
/// Sub-technique hits roll UP into their parent (a parent counts as exercised
/// when any of its sub-techniques was), so coverage reads hierarchically.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TechniqueCoverage {
    /// Canonical ATT&CK ID (`T1589.002`).
    pub id: &'static str,
    /// ATT&CK technique name.
    pub name: &'static str,
    /// True for a dotted sub-technique ID.
    pub is_subtechnique: bool,
    /// Whether the scan collected any finding via this technique (rolled up from
    /// sub-techniques for a parent).
    pub exercised: bool,
    /// Distinct findings collected via this technique (rolled up).
    pub finding_count: u32,
    /// Strongest `c_effective` among those findings (`0.0` when unexercised).
    pub max_c_eff: f64,
}

/// Scan-level MITRE ATT&CK **Reconnaissance** (TA0043) coverage — the
/// Navigator-style "which techniques did this collection exercise vs stay dark"
/// layer, computed purely from the inline `attack:<ID>` provenance every finding
/// already carries. Deterministic: `techniques` is the full catalogue in ID order,
/// so identical input yields byte-identical output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CoverageReport {
    /// `TA0043`.
    pub tactic_id: &'static str,
    /// `Reconnaissance`.
    pub tactic_name: &'static str,
    /// Every catalogued technique with its per-scan coverage, sorted by ID.
    pub techniques: Vec<TechniqueCoverage>,
    /// Number of catalogued techniques exercised (parents + sub-techniques).
    pub exercised_count: usize,
    /// Total catalogued techniques ([`RECONNAISSANCE`]`.len()`).
    pub total_count: usize,
}

impl CoverageReport {
    /// The catalogued techniques the scan did NOT exercise — the collection gaps,
    /// in ID order. Sub-techniques whose parent was exercised still appear if the
    /// specific sub-technique itself was dark.
    #[must_use]
    pub fn gaps(&self) -> Vec<&TechniqueCoverage> {
        self.techniques.iter().filter(|t| !t.exercised).collect()
    }

    /// The exercised techniques, in ID order.
    #[must_use]
    pub fn exercised(&self) -> Vec<&TechniqueCoverage> {
        self.techniques.iter().filter(|t| t.exercised).collect()
    }
}

/// Compute the [`CoverageReport`] for a scan's entity set. **Pure** — reads each
/// entity's `attack:<ID>` tags (stamped at admission by the dispatcher) and its
/// `c_effective`, folds them onto the catalogue, and rolls sub-technique hits up
/// to their parents. An entity counts once per distinct technique it carries;
/// an `attack:<ID>` tag whose ID is not catalogued (a stale/typo'd stamp) is
/// ignored, so the report can't invent a technique. Deterministic regardless of
/// entity order (the output is the ID-sorted catalogue).
#[must_use]
pub fn coverage(entities: &[crate::core::entity::Entity]) -> CoverageReport {
    use std::collections::{BTreeMap, BTreeSet};

    // Direct hits per EXACT catalogued technique ID: (finding_count, max_c_eff).
    let mut direct: BTreeMap<&'static str, (u32, f64)> = BTreeMap::new();
    for e in entities {
        let c = e.c_effective();
        // Dedup techniques within one entity so a finding carrying the same
        // technique twice still counts once.
        let mut on_this: BTreeSet<&'static str> = BTreeSet::new();
        for tag in &e.tags {
            if let Some(id) = tag.strip_prefix("attack:")
                && let Some(t) = technique(id)
            {
                on_this.insert(t.id);
            }
        }
        for id in on_this {
            let slot = direct.entry(id).or_insert((0, 0.0));
            slot.0 += 1;
            if c > slot.1 {
                slot.1 = c;
            }
        }
    }

    // Roll each sub-technique's hits up into its (catalogued) parent.
    let mut rolled = direct.clone();
    for (&id, &(count, ceff)) in &direct {
        if let Some(parent) = parent_id(id)
            && let Some(pt) = technique(parent)
        {
            let slot = rolled.entry(pt.id).or_insert((0, 0.0));
            slot.0 += count;
            if ceff > slot.1 {
                slot.1 = ceff;
            }
        }
    }

    let techniques: Vec<TechniqueCoverage> = RECONNAISSANCE
        .iter()
        .map(|t| {
            let (finding_count, max_c_eff) = rolled.get(t.id).copied().unwrap_or((0, 0.0));
            TechniqueCoverage {
                id: t.id,
                name: t.name,
                is_subtechnique: is_subtechnique(t.id),
                exercised: finding_count > 0,
                finding_count,
                max_c_eff,
            }
        })
        .collect();

    let exercised_count = techniques.iter().filter(|t| t.exercised).count();
    let total_count = techniques.len();
    CoverageReport {
        tactic_id: TACTIC_ID,
        tactic_name: TACTIC_NAME,
        techniques,
        exercised_count,
        total_count,
    }
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
