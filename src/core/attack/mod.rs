//! MITRE ATT&CK® catalogue — the **complete Enterprise matrix** as reference
//! vocabulary, plus HSE's honest **Reconnaissance** coverage.
//!
//! Two distinct things live here, and keeping them distinct is the whole point:
//!
//! 1. **The framework** ([`TACTICS`] + [`ENTERPRISE`]): the entire MITRE ATT&CK
//!    Enterprise matrix — all 14 tactics and every current technique /
//!    sub-technique ([`ATTACK_VERSION`]) — as pure static data. This lets a finding, an
//!    evidence trail, or a correlation edge be labelled with *any* ATT&CK
//!    technique in the standard vocabulary, and lets an operator resolve any
//!    `Tnnnn[.nnn]` id the tool emits to its canonical name and owning tactic(s).
//!
//! 2. **HSE's coverage** ([`reconnaissance`] / [`uncovered`] /
//!    [`techniques_for_category`]): the slice HSE actually *performs* — the
//!    Reconnaissance tactic (TA0043). HSE is a passive-and-authorised OSINT
//!    *collector*; it gathers victim identity / network / org / host information
//!    and searches open sites and technical databases. Those are Reconnaissance
//!    techniques, so that is the only tactic HSE claims coverage of.
//!
//! Holding the *whole* framework while claiming coverage of *one* tactic is not a
//! contradiction — it is the invariant. Reference vocabulary is not a coverage
//! assertion: a module may tag a finding with a Collection or Resource-Development
//! technique when that is literally what the datum is, without HSE pretending to
//! perform those tactics end-to-end. The one thing this evidentiary tool must
//! never do is claim *coverage* it does not have, so [`uncovered`] and the
//! per-scan coverage report are computed against the Reconnaissance tactic alone —
//! a technique HSE performs no collection for (e.g. `T1598` Phishing for
//! Information) surfaces as a real, named gap rather than being silently absent.
//!
//! Pure data + lookups; no runtime I/O (the multi-MB STIX bundle is NOT vendored —
//! only the id/name/tactic triples are, regenerated from the pinned release).
//! Drift-guard tests pin that the Reconnaissance slice is exactly the full TA0043
//! tactic, that every id the module map references exists in the catalogue, and
//! that the catalogue stays sorted and duplicate-free.

use crate::core::entity::EntityKind;
use crate::core::module::ModuleCategory;
use serde::Serialize;

/// The ATT&CK release these triples were generated from. Bump alongside a
/// regeneration of [`TACTICS`] / [`ENTERPRISE`] from the pinned STIX bundle.
pub const ATTACK_VERSION: &str = "17.1";

/// The MITRE ATT&CK tactic HSE performs collection for — the one tactic whose
/// *coverage* the tool honestly claims. Retained as the canonical pair the
/// coverage report and dossier key on.
pub const TACTIC_ID: &str = "TA0043";
/// Human-readable name of [`TACTIC_ID`].
pub const TACTIC_NAME: &str = "Reconnaissance";

/// One MITRE ATT&CK Enterprise tactic (a column of the matrix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Tactic {
    /// Canonical ATT&CK tactic ID, e.g. `TA0043`.
    pub id: &'static str,
    /// STIX `x_mitre_shortname`, e.g. `reconnaissance` — the key a technique's
    /// [`Technique::tactics`] membership uses.
    pub shortname: &'static str,
    /// Tactic name, e.g. "Reconnaissance".
    pub name: &'static str,
}

/// One ATT&CK technique or sub-technique. `id` is the canonical ATT&CK
/// identifier; sub-techniques use the dotted form (`T1596.002`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Technique {
    /// Canonical ATT&CK ID, e.g. `T1589.002`.
    pub id: &'static str,
    /// ATT&CK technique name, e.g. "Email Addresses".
    pub name: &'static str,
    /// True for a sub-technique (dotted id) — a leaf under a parent technique.
    pub is_subtechnique: bool,
    /// The `shortname`s of every tactic this technique belongs to (a technique
    /// can sit in several matrix columns), sorted for stable output.
    pub tactics: &'static [&'static str],
}

mod catalogue;
mod coverage;

pub use catalogue::{ENTERPRISE, TACTICS};
pub use coverage::{
    Coverage, CoveredTechnique, TechniqueByEntityType, coverage, coverage_by_entity_type,
    navigator_layer, techniques_from_entities,
};

/// The catalogued technique with this ID, if any. Searches the entire Enterprise
/// catalogue, so any `Tnnnn[.nnn]` the tool emits resolves to its canonical name.
#[must_use]
pub fn technique(id: &str) -> Option<&'static Technique> {
    ENTERPRISE.iter().find(|t| t.id == id)
}

/// The catalogued tactic with this ID (`TA0043`) or `shortname` (`reconnaissance`).
#[must_use]
pub fn tactic(id_or_shortname: &str) -> Option<&'static Tactic> {
    TACTICS
        .iter()
        .find(|t| t.id == id_or_shortname || t.shortname == id_or_shortname)
}

/// Every technique belonging to the tactic named by `shortname` (e.g.
/// `reconnaissance`), in the catalogue's sorted order. Empty for an unknown
/// shortname.
#[must_use]
pub fn techniques_for_tactic(shortname: &str) -> Vec<&'static Technique> {
    ENTERPRISE
        .iter()
        .filter(|t| t.tactics.contains(&shortname))
        .collect()
}

/// The full Reconnaissance tactic (TA0043) — the slice HSE performs collection
/// for. Derived from the catalogue so it can never drift from the framework data.
/// A drift-guard test pins that this is exactly the complete TA0043 tactic.
#[must_use]
pub fn reconnaissance() -> Vec<&'static Technique> {
    techniques_for_tactic("reconnaissance")
}

/// The Reconnaissance techniques for which `is_covered` returns `false` — the
/// honest coverage *gaps* for a coverage set (typically the union of every
/// module's [`crate::core::module::Module::attack_techniques`]), in sorted order.
/// Computed against the Reconnaissance tactic alone: that is the tactic HSE
/// claims, so a gap here names exactly which collection HSE performs none of,
/// instead of implying total coverage of a tactic — or of the framework.
#[must_use]
pub fn uncovered(is_covered: impl Fn(&str) -> bool) -> Vec<&'static Technique> {
    reconnaissance()
        .into_iter()
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

/// The ATT&CK Reconnaissance technique IDs an entity type commonly carries.
/// Entity-type mapping refines module category mapping: an entity is tagged with
/// both its module's category-level techniques (what the module collects) AND
/// the entity-type-specific techniques (what kind of data the entity represents).
/// This dual-layer tagging enables both broad coverage (per module) and precise
/// technique attribution (per entity).
///
/// For example, a Username entity from a Social module gets tagged with both:
/// - Category techniques: `T1593.001` (Social Media), `T1589.003` (Employee Names)
/// - Entity techniques: `T1593.001` (Social Media), `T1589.003` (Employee Names)
///
/// The technique deduplication happens at tagging time (entity.tag is idempotent).
#[must_use]
pub fn techniques_for_entity_kind(kind: &EntityKind) -> &'static [&'static str] {
    match kind {
        // People and identifiers
        EntityKind::Person => &[
            "T1589",     // Gather Victim Identity Information
            "T1589.003", // Employee Names
            "T1591",     // Gather Victim Org Information
        ],
        EntityKind::Email => &["T1589.002"], // Email Addresses
        EntityKind::Phone => &["T1589"],     // Gather Victim Identity Information
        EntityKind::Username => &[
            "T1593.001", // Social Media
            "T1589.003", // Employee Names
        ],

        // Credentials
        EntityKind::Credential | EntityKind::ApiKey | EntityKind::Password => {
            &["T1589.001"] // Credentials
        }

        // Network infrastructure
        EntityKind::IpAddress => &["T1590.005"], // IP Addresses
        EntityKind::Domain => &[
            "T1590.001", // Domain Properties
            "T1596.002", // WHOIS
            "T1593.002", // Search Engines
            "T1594",     // Search Victim-Owned Websites
        ],
        EntityKind::Url => &["T1594"], // Search Victim-Owned Websites
        EntityKind::Asn => &["T1590.004"], // Network Topology
        EntityKind::Cidr => &[
            "T1590.001", // Domain Properties
            "T1590.004", // Network Topology
        ],

        // Physical / Geospatial
        EntityKind::Address | EntityKind::Coordinates => &["T1591.001"], // Determine Physical Locations

        // Organisation
        EntityKind::Organisation => &["T1591"], // Gather Victim Org Information
        EntityKind::AbnAcn => &[
            "T1591.002", // Business Relationships
            "T1591.004", // Identify Roles
        ],

        // Host / Device information
        EntityKind::MacAddress | EntityKind::DeviceId | EntityKind::Ssid => {
            &["T1592"] // Gather Victim Host Information
        }

        // Web analytics and tracking
        EntityKind::TrackingId => &[
            "T1593.002", // Search Engines
            "T1591",     // Gather Victim Org Information
        ],

        // Cryptocurrency
        EntityKind::CryptoAddress => &["T1589"], // Gather Victim Identity Information

        // Uncategorised or no direct mapping
        EntityKind::Other(_) => &[],
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
