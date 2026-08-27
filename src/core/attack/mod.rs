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
use crate::core::relation::RelationKind;
use serde::Serialize;

/// The ATT&CK release these triples were generated from. Bump alongside a
/// regeneration of [`TACTICS`] / [`ENTERPRISE`] from the pinned STIX bundle.
pub const ATTACK_VERSION: &str = "17.1";

/// The ATT&CK **content major** version, derived from [`ATTACK_VERSION`].
///
/// The ATT&CK Navigator's `versions.attack` field carries the content *major*
/// (MITRE tags a `17.1` catalogue as attack version `"17"`), so
/// [`navigator_layer`] reads this instead of a hand-typed literal that silently
/// drifts behind a catalogue bump. Single-sourcing it against `ATTACK_VERSION`
/// means one edit (the `const` above) moves the whole surface, and the
/// `navigator_layer_is_a_valid_honest_layer` guard pins the emitted value to it.
#[must_use]
pub fn attack_spec_major() -> &'static str {
    match ATTACK_VERSION.split_once('.') {
        Some((major, _)) => major,
        None => ATTACK_VERSION,
    }
}

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

mod data;
pub use data::{ENTERPRISE, TACTICS};

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

/// The ATT&CK Reconnaissance technique IDs a **relation** exercises — the third
/// and final layer of the mapping, beside [`techniques_for_category`] (what a
/// module collects) and [`techniques_for_entity_kind`] (what a finding is).
///
/// A relation is a collection *result*, not merely a rendering of one: an
/// adversary who establishes that a person is a filed director of a company has
/// performed T1591.004 (Identify Roles) whether or not any single entity in the
/// scan carries that tag. Without this layer a scan's coverage under-reported
/// exactly the collection the graph layer contributes — an officership, a
/// corporate parent, a named network operator — because the technique lived in
/// the EDGE and the rollup only ever read entity tags.
///
/// Two kinds return no technique, and both are deliberate rather than an
/// omission:
/// * [`DerivedFrom`](RelationKind::DerivedFrom) is provenance — it records which
///   entity's expansion surfaced another, which is bookkeeping about HSE's own
///   traversal, not collection against the target.
/// * [`SameAs`](RelationKind::SameAs) asserts that two entities already
///   collected are one identity in two spellings; the collection was done by
///   whatever produced them, and counting it again would inflate coverage with a
///   normalisation step.
#[must_use]
pub fn techniques_for_relation_kind(kind: RelationKind) -> &'static [&'static str] {
    match kind {
        // ── Infrastructure ───────────────────────────────────────────────
        // Domain structure and hierarchy.
        RelationKind::SubdomainOf | RelationKind::BelongsToDomain => &["T1590.001"],
        // A URL bound to the site that serves it.
        RelationKind::HostedOn => &["T1594"],
        // The DNS answer itself.
        RelationKind::ResolvesTo => &["T1590.002"],
        // Registrant attribution comes out of WHOIS.
        RelationKind::RegisteredBy => &["T1596.002"],
        // Two assets proven to share an operator — a second/third-party
        // relationship established from domain properties.
        RelationKind::SameOperator => &["T1591.002", "T1590.001"],

        // ── Place ────────────────────────────────────────────────────────
        RelationKind::CoLocatedWith | RelationKind::LocatedAt => &["T1591.001"],

        // ── Identity ─────────────────────────────────────────────────────
        RelationKind::IdentifiedBy => &["T1589"],
        // A handle reused across platforms is social-media collection resolving
        // to a person's name.
        RelationKind::AliasOf => &["T1589.003", "T1593.001"],
        // The authenticated identity behind a profile page.
        RelationKind::SameIdentity => &["T1593.001"],
        // A reused, individuating secret is credential collection.
        RelationKind::SharesSecretWith => &["T1589.001"],
        // Family, household and declared associates — identity information about
        // the people around the subject.
        RelationKind::AssociatedWith => &["T1589"],

        // ── Affiliation ──────────────────────────────────────────────────
        // A register naming an officeholder IS Identify Roles.
        RelationKind::OfficerOf => &["T1591.004"],
        // Employment names both the role and the employee.
        RelationKind::EmployedBy => &["T1591.004", "T1589.003"],
        // A membership is organisation information without being a role at the
        // target, so it maps to the parent technique rather than to .004.
        RelationKind::MemberOf => &["T1591"],
        // The corporate hierarchy is the textbook Business Relationships case.
        RelationKind::ControlledBy | RelationKind::OperatedBy => &["T1591.002"],

        // ── Not collection (see the doc comment) ─────────────────────────
        RelationKind::DerivedFrom | RelationKind::SameAs => &[],
    }
}

/// Count the Reconnaissance techniques a scan's RELATIONS exercised, folded into
/// an existing per-technique tally (typically the entity-tag counts) so
/// [`coverage`] sees one combined picture.
///
/// The count added per technique is the number of EDGES that exercised it, which
/// is the same "how much collection of this kind did the scan actually do"
/// quantity the entity counts carry — a scan establishing forty officerships and
/// one is not equally covered.
pub fn fold_relation_techniques(
    exercised: &mut std::collections::BTreeMap<String, usize>,
    relations: &[crate::core::relation::Relation],
) {
    for r in relations {
        for id in techniques_for_relation_kind(r.kind) {
            *exercised.entry((*id).to_string()).or_insert(0) += 1;
        }
    }
}

/// One exercised technique in a [`Coverage`] rollup: the catalogued technique
/// plus the number of scan entities collected via it.
#[derive(Debug, Clone, Serialize)]
pub struct CoveredTechnique {
    /// The catalogued technique (`id` + `name`), flattened into the object.
    #[serde(flatten)]
    pub technique: Technique,
    /// How many of the scan's entities carry this technique's `attack:<id>` tag.
    pub entity_count: usize,
}

/// One exercised technique broken down by entity type: how many entities of
/// each kind contributed to coverage of a single technique.
#[derive(Debug, Clone, Serialize)]
pub struct TechniqueByEntityType {
    /// The technique id + name.
    #[serde(flatten)]
    pub technique: Technique,
    /// Entity count per kind (e.g., `{ "Email": 5, "Username": 3 }`).
    pub by_entity_type: std::collections::BTreeMap<String, usize>,
}

/// A scan's MITRE ATT&CK **Reconnaissance** (TA0043) coverage: the techniques it
/// exercised (with entity counts) and the honest uncovered gaps, both in the
/// catalogue's sorted order. Built by [`coverage`] from the `attack:<id>` tags
/// the engine stamps on every admitted entity, and serialised straight to the
/// `/scans/{id}/attack` API surface.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// Always [`TACTIC_ID`] — the one Enterprise tactic HSE honestly performs.
    pub tactic_id: &'static str,
    /// Always [`TACTIC_NAME`].
    pub tactic_name: &'static str,
    /// Techniques the scan actually exercised, catalogue-sorted.
    pub covered: Vec<CoveredTechnique>,
    /// Catalogued TA0043 techniques the scan performed no collection for — the
    /// honest gaps, straight from [`uncovered`].
    pub uncovered: Vec<&'static Technique>,
    /// `covered.len() / reconnaissance().len()`, in `0.0..=1.0`.
    pub coverage_fraction: f64,
}

/// Roll a scan's exercised technique IDs (with per-technique entity counts —
/// typically the `attack:<id>` tags counted across the scan's entities) up into
/// a [`Coverage`]. Unknown IDs are ignored (the drift guard keeps them from ever
/// being emitted). Covered techniques and gaps come back catalogue-sorted, so
/// the rollup is deterministic regardless of entity iteration order.
#[must_use]
pub fn coverage(exercised: &std::collections::BTreeMap<String, usize>) -> Coverage {
    let recon = reconnaissance();
    let covered: Vec<CoveredTechnique> = recon
        .iter()
        .filter_map(|t| {
            exercised.get(t.id).map(|&entity_count| CoveredTechnique {
                technique: **t,
                entity_count,
            })
        })
        .collect();
    let gaps = uncovered(|id| exercised.contains_key(id));
    #[allow(clippy::cast_precision_loss)]
    let coverage_fraction = if recon.is_empty() {
        0.0
    } else {
        covered.len() as f64 / recon.len() as f64
    };
    Coverage {
        tactic_id: TACTIC_ID,
        tactic_name: TACTIC_NAME,
        covered,
        uncovered: gaps,
        coverage_fraction,
    }
}

/// Every [`EntityKind`] that carries an ATT&CK mapping — the entity surface of
/// the static coverage union in [`static_reconnaissance_coverage`]. The catch-all
/// [`EntityKind::Other`] is deliberately excluded: it has no claimed mapping
/// ([`techniques_for_entity_kind`] returns `&[]` for it). The
/// `static_reconnaissance_coverage_is_the_platform_envelope` guard holds an
/// arm-less match, so a new `EntityKind` fails the build until it is triaged into
/// this list — the union can never silently stop counting a new surface.
const MAPPED_ENTITY_KINDS: &[EntityKind] = &[
    EntityKind::Person,
    EntityKind::Email,
    EntityKind::Phone,
    EntityKind::Username,
    EntityKind::Credential,
    EntityKind::ApiKey,
    EntityKind::Password,
    EntityKind::IpAddress,
    EntityKind::Domain,
    EntityKind::Url,
    EntityKind::Asn,
    EntityKind::Cidr,
    EntityKind::Address,
    EntityKind::Coordinates,
    EntityKind::Organisation,
    EntityKind::AbnAcn,
    EntityKind::MacAddress,
    EntityKind::DeviceId,
    EntityKind::Ssid,
    EntityKind::TrackingId,
    EntityKind::CryptoAddress,
];

/// Every [`RelationKind`] — the graph surface of the static coverage union. All
/// unit variants; the same arm-less-match guard keeps this list exhaustive.
const ALL_RELATION_KINDS: &[RelationKind] = &[
    RelationKind::SubdomainOf,
    RelationKind::BelongsToDomain,
    RelationKind::HostedOn,
    RelationKind::ResolvesTo,
    RelationKind::RegisteredBy,
    RelationKind::CoLocatedWith,
    RelationKind::DerivedFrom,
    RelationKind::IdentifiedBy,
    RelationKind::AliasOf,
    RelationKind::LocatedAt,
    RelationKind::AssociatedWith,
    RelationKind::SameAs,
    RelationKind::SameOperator,
    RelationKind::SameIdentity,
    RelationKind::SharesSecretWith,
    RelationKind::EmployedBy,
    RelationKind::OfficerOf,
    RelationKind::MemberOf,
    RelationKind::ControlledBy,
    RelationKind::OperatedBy,
];

/// HSE's **structural** Reconnaissance coverage — the platform's capability
/// envelope, not a single scan's result.
///
/// Where [`coverage`] rolls up one scan's runtime `exercised` counts, this unions
/// the three *static* ATT&CK surfaces the platform maps — the module registry
/// (each module's [`attack_techniques`](crate::core::module::Module::attack_techniques)),
/// every mapped [`EntityKind`]'s [`techniques_for_entity_kind`], and every
/// [`RelationKind`]'s [`techniques_for_relation_kind`] — to answer which TA0043
/// techniques HSE can *ever* exercise, and which it structurally never reaches
/// (e.g. the phishing family `T1598`, which a passive collector performs none of).
/// This is the "recursive" view: coverage computed across the whole
/// module→entity→relation chain rather than one scan's tags.
///
/// Each covered technique's `entity_count` here is the number of static surfaces
/// that name it (a coarse structural-reachability weight), *not* a live entity
/// tally — read it as "how many independent surfaces would exercise this".
///
/// `module_technique_ids` is **injected**, not read from the registry: `core`
/// must not depend on `crate::modules` (the `core_does_not_import_modules`
/// architecture guard). A caller in a layer that can see the registry — e.g.
/// `hse selftest` — passes
/// `registry().iter().flat_map(|m| m.attack_techniques().iter().copied())`.
#[must_use]
pub fn static_reconnaissance_coverage<'a>(
    module_technique_ids: impl IntoIterator<Item = &'a str>,
) -> Coverage {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for id in module_technique_ids {
        *counts.entry(id.to_string()).or_default() += 1;
    }
    for kind in MAPPED_ENTITY_KINDS {
        for id in techniques_for_entity_kind(kind) {
            *counts.entry((*id).to_string()).or_default() += 1;
        }
    }
    for &kind in ALL_RELATION_KINDS {
        for id in techniques_for_relation_kind(kind) {
            *counts.entry((*id).to_string()).or_default() += 1;
        }
    }
    coverage(&counts)
}

/// Compute Reconnaissance technique coverage broken down by entity type.
/// This shows what kinds of entities carry each technique, enabling analysis
/// of collection depth across entity dimensions. For example, if a scan's
/// `T1589.002` (Email Addresses) technique is carried only by Breach entities
/// (not Search/Social collection), the gap is visible — operators can prioritize
/// module expansion accordingly.
///
/// Takes a list of (entity_kind, technique_id) pairs from the scan's entities
/// (each entity may contribute multiple technique IDs). Returns techniques in
/// catalogue order with per-type breakdowns (type-sorted within each technique).
#[must_use]
pub fn coverage_by_entity_type(
    entity_techniques: &[(String, String)],
) -> Vec<TechniqueByEntityType> {
    use std::collections::BTreeMap;

    // Aggregate: technique_id → kind → count
    let mut by_technique: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for (kind, tech_id) in entity_techniques {
        by_technique
            .entry(tech_id.clone())
            .or_default()
            .entry(kind.clone())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    // Build result in catalogue order
    reconnaissance()
        .iter()
        .filter_map(|t| {
            by_technique
                .remove(t.id)
                .map(|by_entity_type| TechniqueByEntityType {
                    technique: **t,
                    by_entity_type,
                })
        })
        .collect()
}

/// Extract Reconnaissance technique IDs from a list of entities (typically the
/// correlated entities from a Correlation finding). Returns a sorted, deduplicated
/// set of technique IDs carried by the entities' `attack:<id>` tags.
///
/// This enables attribution tracing: "these entities were linked together by AU-123,
/// and they were discovered via these Reconnaissance techniques" — the full chain
/// from module → technique → entity → correlation.
#[must_use]
pub fn techniques_from_entities(entities: &[&crate::core::entity::Entity]) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut techniques: BTreeSet<String> = BTreeSet::new();
    for e in entities {
        for tag in &e.tags {
            if let Some(tech_id) = tag.strip_prefix("attack:") {
                techniques.insert(tech_id.to_string());
            }
        }
    }
    techniques.into_iter().collect()
}

/// Serialise a [`Coverage`] as a MITRE ATT&CK **Navigator layer** — the standard
/// JSON the official [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
/// renders — so a scan's Reconnaissance coverage drops straight into MITRE's own
/// visualisation instead of living only in HSE's tags. Each exercised technique
/// carries a `score` equal to its entity count (the Navigator heat-map then shows
/// collection *intensity*); every uncovered TA0043 technique is emitted disabled
/// with `score: 0`, so the layer is an honest picture of exactly what HSE
/// collected and what it did not. `scan_label` names the source scan.
#[must_use]
pub fn navigator_layer(coverage: &Coverage, scan_label: &str) -> serde_json::Value {
    let max_score = coverage
        .covered
        .iter()
        .map(|c| c.entity_count)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut techniques: Vec<serde_json::Value> = coverage
        .covered
        .iter()
        .map(|c| {
            serde_json::json!({
                "techniqueID": c.technique.id,
                "tactic": "reconnaissance",
                "score": c.entity_count,
                "enabled": true,
                "comment": c.technique.name,
            })
        })
        .collect();
    for t in &coverage.uncovered {
        techniques.push(serde_json::json!({
            "techniqueID": t.id,
            "tactic": "reconnaissance",
            "score": 0,
            "enabled": false,
            "comment": t.name,
        }));
    }
    serde_json::json!({
        "name": format!("HSE — {scan_label} (Reconnaissance coverage)"),
        "versions": { "attack": attack_spec_major(), "navigator": "5.1.0", "layer": "4.5" },
        "domain": "enterprise-attack",
        "description": "MITRE ATT&CK Reconnaissance (TA0043) coverage produced by \
                        Huntsman Search Engine. score = entities collected via each \
                        technique; disabled techniques are honest gaps (no collection \
                        performed). Scoped to TA0043 — a passive OSINT collector \
                        performs no post-compromise tactic.",
        "sorting": 3,
        "hideDisabled": false,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
            "minValue": 0,
            "maxValue": max_score
        },
        "legendItems": [],
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
