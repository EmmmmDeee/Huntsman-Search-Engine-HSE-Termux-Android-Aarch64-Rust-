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
    use super::*;

    #[test]
    fn catalogue_is_well_formed_and_sorted() {
        for t in RECONNAISSANCE {
            assert!(
                t.id.starts_with('T') && t.id.len() >= 5,
                "bad technique id {:?}",
                t.id
            );
            // IDs are `Tdddd` or `Tdddd.ddd`.
            let core = t.id.trim_start_matches('T');
            let (base, sub) = core
                .split_once('.')
                .map_or((core, None), |(b, s)| (b, Some(s)));
            assert!(base.len() == 4 && base.bytes().all(|b| b.is_ascii_digit()));
            if let Some(sub) = sub {
                assert!(
                    sub.bytes().all(|b| b.is_ascii_digit()),
                    "bad sub {:?}",
                    t.id
                );
            }
            assert!(!t.name.is_empty());
        }
        let mut sorted = RECONNAISSANCE.to_vec();
        sorted.sort_by_key(|t| t.id);
        assert_eq!(
            RECONNAISSANCE.iter().map(|t| t.id).collect::<Vec<_>>(),
            sorted.iter().map(|t| t.id).collect::<Vec<_>>(),
            "RECONNAISSANCE must stay sorted by id"
        );
        // No duplicate IDs.
        let mut ids: Vec<&str> = RECONNAISSANCE.iter().map(|t| t.id).collect();
        ids.dedup();
        assert_eq!(ids.len(), RECONNAISSANCE.len(), "duplicate technique id");
    }

    #[test]
    fn technique_lookup_round_trips() {
        assert_eq!(technique("T1596.002").map(|t| t.name), Some("WHOIS"));
        assert_eq!(
            technique("T1593.002").map(|t| t.name),
            Some("Search Engines")
        );
        assert_eq!(technique("T9999"), None);
    }

    #[test]
    fn coverage_dedupes_sorts_and_drops_unknown() {
        let cov = coverage(["T1596.002", "T1589.002", "T1596.002", "T9999"]);
        let ids: Vec<&str> = cov.iter().map(|t| t.id).collect();
        assert_eq!(ids, vec!["T1589.002", "T1596.002"]);
        assert!(coverage(std::iter::empty::<&str>()).is_empty());
    }

    #[test]
    fn every_category_maps_only_to_catalogued_ids() {
        // Drift guard at the source: every ID the category map yields must be a
        // real catalogue entry, for every category (so a typo'd or removed
        // technique is caught without needing the module registry).
        let cats = [
            ModuleCategory::DnsRecon,
            ModuleCategory::Breach,
            ModuleCategory::Infrastructure,
            ModuleCategory::Search,
            ModuleCategory::Social,
            ModuleCategory::Email,
            ModuleCategory::Phone,
            ModuleCategory::Corporate,
            ModuleCategory::Threat,
            ModuleCategory::Sensor,
            ModuleCategory::People,
            ModuleCategory::Web,
            ModuleCategory::Geo,
            ModuleCategory::Other,
        ];
        for cat in cats {
            for id in techniques_for_category(cat) {
                assert!(
                    technique(id).is_some(),
                    "category {cat:?} maps to unknown technique {id}"
                );
            }
        }
    }
}
