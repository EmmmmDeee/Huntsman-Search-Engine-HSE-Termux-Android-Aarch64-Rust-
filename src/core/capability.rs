//! Frontier self-verifying ATT&CK *capability claims* ledger for HSE.
//!
//! This module records **claims** that the product can defensively observe,
//! collect (OSINT / Termux sensing), or otherwise evidence — keyed by MITRE
//! ATT&CK technique IDs. It is **not** an attack toolkit: it does not
//! implement offensive techniques, payloads, exploits, or phishing / host-
//! intrusion / C2 product capabilities.
//!
//! # Mandate chain
//!
//! `OBJECTIVE → CAPABILITY → METHOD → RUST COMPONENT → SOURCE → EXECUTION →
//! OUTPUT → PROVENANCE → CORROBORATION → TEST → BENCHMARK → REGRESSION →
//! VERIFIED STATUS`
//!
//! # Status derivation (mandatory)
//!
//! [`CapabilityStatus::Verified`] **requires a full evidence chain** and is
//! **never** accepted from static seed data alone. Status is always computed
//! by [`derive_status`] from [`ClaimScope`] + [`CapabilityEvidenceLinks`].
//! There is **no API** to manually set a row to `Verified`.
//!
//! **NO EVIDENCE = NO VERIFIED.**
//!
//! Hard failures that force [`CapabilityStatus::Unverified`] (auto-downgrade
//! from a prior Verified derivation):
//! - any `failed_test_ids`
//! - `!regression_ok` when any evidence activity is present
//! - `!freshness_ok`
//! - `!reproducibility_ok`
//!
//! # Applicable scope
//!
//! A claim is InScope only when it can be **executed, tested, and reproduced**
//! under present constraints. Otherwise it stays Unverified or is marked
//! NotApplicable. Default product surface: **OSINT in Rust**. First-class
//! themes (future evidence, not auto-Verified): people-centric identity,
//! GEOINT, public harvest + provenance, STIX interop. Hashed evidence /
//! provenance binding for links is available via
//! [`evidence_links_content_hash`] / [`evidence_links_provenance_binding`].
//! Capability Navigator export comes **only** from this ledger's
//! `derive_status` — never from coverage heatmaps.
//!
//! Closed sources, active scanning, and credential collection are
//! [`ClaimScope::NotApplicable`] unless a lawful, testable in-tree method exists.
//!
//! # Evidence ladder (claim strength ceiling)
//!
//! `Assertion < Derived < Primary < IndependentCorroboration <
//! DirectObservation < Reproduction < EndToEndDemonstration`
//!
//! v0 Verified requires full mandatory links **and**
//! `evidence_level >= IndependentCorroboration`.
//!
//! # NEVER infer Verified from ATT&CK mapping alone
//!
//! **Catalog presence ≠ capability. Mapping ≠ Verified.**
//! The following are **explicitly not** evidence that a capability is Verified:
//! - `Module::attack_techniques()` / module→technique maps
//! - [`crate::core::attack::Coverage`] collection-reach / entity_count heat
//! - [`crate::core::attack::navigator_layer`] coverage heatmap export
//! - `docs/REQUIREMENTS_LEDGER.md` human `VERIFIED` rows
//! - [`crate::core::assurance`] maturity ladder (`Assured`, etc.)
//!
//! ATT&CK is the **canonical interoperability map**, not a methodological
//! ceiling. [`CapabilityRow::method_id`] is a v0 hook so later METHOD plugins
//! (D3FEND, STIX/TAXII, Bayesian, graph, geo, temporal, VOI, …) can compete;
//! status remains **derive-only** from evidence links regardless of method.
//!
//! # Navigator export
//!
//! [`CapabilityLedger::navigator_layer`] emits ATT&CK Navigator layer 4.x
//! compatible JSON that is **derived-only** from `derive_status`. It is a
//! **capability ledger layer**, not a coverage heatmap. Keep it **separate**
//! from [`crate::core::attack::navigator_layer`] — do not replace coverage
//! export. There is no manual promotion / status-override API for export.
//!
//! ## Color map (derived status → Navigator)
//!
//! | Status | Score | Color |
//! |---|---:|---|
//! | Verified | 100 | `#31a354` |
//! | Partial | 50 | `#fec44f` |
//! | Unverified | 10 | `#de2d26` |
//! | NotApplicable | 0 | `#bdbdbd` |

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Value as JsonValue, json};

/// Derived capability status for a defensive ATT&CK claim.
///
/// Order is for sorting/display only; **never** assign `Verified` from static
/// data or from ATT&CK coverage maps — use [`derive_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityStatus {
    /// Full mandatory evidence chain present and healthy.
    Verified,
    /// Some but not all mandatory evidence links are present.
    Partial,
    /// In-scope claim with no (or insufficient) evidence, or hard failure.
    Unverified,
    /// Curated out of product scope; never counted as verified.
    NotApplicable,
}

impl CapabilityStatus {
    /// Navigator layer score for this status.
    #[must_use]
    pub const fn navigator_score(self) -> u8 {
        match self {
            Self::Verified => 100,
            Self::Partial => 50,
            Self::Unverified => 10,
            Self::NotApplicable => 0,
        }
    }

    /// Navigator layer color (hex) for this status.
    #[must_use]
    pub const fn navigator_color(self) -> &'static str {
        match self {
            Self::Verified => "#31a354",
            Self::Partial => "#fec44f",
            Self::Unverified => "#de2d26",
            Self::NotApplicable => "#bdbdbd",
        }
    }

    /// Stable label for comments / Display.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "Verified",
            Self::Partial => "Partial",
            Self::Unverified => "Unverified",
            Self::NotApplicable => "NotApplicable",
        }
    }
}

impl fmt::Display for CapabilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a technique is in product scope for a future defensive claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimScope {
    /// Product may eventually evidence a defensive claim for this technique.
    ///
    /// Applicable only when the claim can be executed, tested, and reproduced
    /// under present constraints; otherwise leave Unverified or mark NotApplicable.
    InScope,
    /// Explicitly out of product scope (omission ≠ N/A).
    ///
    /// Closed sources, active scanning, and credential collection are N/A
    /// unless a lawful, testable in-tree method exists.
    NotApplicable,
}

/// Claim-strength ladder. Status strength **may not exceed** the declared level.
///
/// Order (weak → strong):
/// `Assertion < Derived < Primary < IndependentCorroboration < DirectObservation
/// < Reproduction < EndToEndDemonstration`
///
/// v0 [`CapabilityStatus::Verified`] requires
/// `evidence_level >= IndependentCorroboration` **and** full mandatory links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum EvidenceLevel {
    /// Unsubstantiated statement.
    #[default]
    Assertion = 0,
    /// Inferred from other claims / maps (still not Verified alone).
    Derived = 1,
    /// Direct primary-source artifact.
    Primary = 2,
    /// Independent corroboration channel satisfied.
    IndependentCorroboration = 3,
    /// Direct observation of the phenomenon.
    DirectObservation = 4,
    /// Reproduced under controlled conditions.
    Reproduction = 5,
    /// Full end-to-end demonstration with provenance.
    EndToEndDemonstration = 6,
}

impl EvidenceLevel {
    /// Minimum level required for v0 Verified (with full links).
    pub const MIN_FOR_VERIFIED: Self = Self::IndependentCorroboration;

    /// Stable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assertion => "Assertion",
            Self::Derived => "Derived",
            Self::Primary => "Primary",
            Self::IndependentCorroboration => "IndependentCorroboration",
            Self::DirectObservation => "DirectObservation",
            Self::Reproduction => "Reproduction",
            Self::EndToEndDemonstration => "EndToEndDemonstration",
        }
    }
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Links from a capability row into the defensive evidence chain.
///
/// Status is **not** stored here; callers always pass these links through
/// [`derive_status`]. Benchmarks are optional for v0 `Verified`.
///
/// `freshness_ok` and `reproducibility_ok` default to `true` on
/// [`CapabilityEvidenceLinks::empty`] / [`Default`] so empty InScope seeds
/// remain Unverified (not hard-failed). Setting either to `false` forces
/// auto-downgrade to Unverified (same class as failed tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityEvidenceLinks {
    /// Authoritative source identifiers for the claim.
    pub source_ids: Vec<String>,
    /// Declared inputs for the claim verification procedure.
    pub input_ids: Vec<String>,
    /// Record id of the executed verification procedure.
    pub execution_record_id: Option<String>,
    /// Structured outputs bound to the claim.
    pub output_ids: Vec<String>,
    /// Provenance claim id (e.g. entity / evidence provenance tag).
    pub provenance_claim_id: Option<String>,
    /// Independent corroboration channel ids.
    pub corroboration_ids: Vec<String>,
    /// Linked test ids that must Pass for Verified.
    pub test_ids: Vec<String>,
    /// Optional benchmark ids (not required for v0 Verified).
    pub benchmark_ids: Vec<String>,
    /// Regression lock ids tied to this claim.
    pub regression_lock_ids: Vec<String>,
    /// Linked tests that are currently known Passed (ids subset of `test_ids`).
    pub passed_test_ids: Vec<String>,
    /// Linked tests currently Failed — forces downgrade.
    pub failed_test_ids: Vec<String>,
    /// True when independent corroboration channel is satisfied.
    pub corroboration_ok: bool,
    /// True when regression locks are intact (no fail).
    pub regression_ok: bool,
    /// True when evidence is still considered fresh.
    ///
    /// Default `true` on empty links. `false` → hard Unverified (auto-downgrade).
    pub freshness_ok: bool,
    /// True when the verification procedure remains reproducible.
    ///
    /// Default `true` on empty links. `false` → hard Unverified (auto-downgrade).
    pub reproducibility_ok: bool,
    /// Highest claim-strength level supported by attached evidence.
    ///
    /// Defaults to [`EvidenceLevel::Assertion`] on empty links. Verified
    /// requires `>= IndependentCorroboration` in addition to full links.
    pub evidence_level: EvidenceLevel,
}

impl Default for CapabilityEvidenceLinks {
    fn default() -> Self {
        Self {
            source_ids: Vec::new(),
            input_ids: Vec::new(),
            execution_record_id: None,
            output_ids: Vec::new(),
            provenance_claim_id: None,
            corroboration_ids: Vec::new(),
            test_ids: Vec::new(),
            benchmark_ids: Vec::new(),
            regression_lock_ids: Vec::new(),
            passed_test_ids: Vec::new(),
            failed_test_ids: Vec::new(),
            corroboration_ok: false,
            regression_ok: false,
            freshness_ok: true,
            reproducibility_ok: true,
            evidence_level: EvidenceLevel::Assertion,
        }
    }
}

impl CapabilityEvidenceLinks {
    /// Empty links (InScope seed rows start here → Unverified).
    ///
    /// `freshness_ok` / `reproducibility_ok` default true so absence of
    /// evidence yields Unverified rather than a hard-fail path.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// True when every mandatory field for `Verified` is satisfied.
    ///
    /// Benchmarks are optional for v0. Requires:
    /// - non-empty `source_ids`, `input_ids`, `output_ids`, `corroboration_ids`
    /// - `execution_record_id` and `provenance_claim_id` present
    /// - non-empty `test_ids`
    /// - non-empty `regression_lock_ids` (REGRESSION is a mandatory chain link)
    /// - `corroboration_ok` and `regression_ok`
    /// - `freshness_ok` and `reproducibility_ok`
    /// - `evidence_level >= IndependentCorroboration` (v0 floor)
    /// - `failed_test_ids` empty
    /// - every `test_id` appears in `passed_test_ids`
    #[must_use]
    pub fn mandatory_complete(&self) -> bool {
        if self.source_ids.is_empty()
            || self.input_ids.is_empty()
            || self.output_ids.is_empty()
            || self.corroboration_ids.is_empty()
            || self.test_ids.is_empty()
            || self.regression_lock_ids.is_empty()
        {
            return false;
        }
        if self.execution_record_id.is_none() || self.provenance_claim_id.is_none() {
            return false;
        }
        if !self.corroboration_ok || !self.regression_ok {
            return false;
        }
        if !self.freshness_ok || !self.reproducibility_ok {
            return false;
        }
        if self.evidence_level < EvidenceLevel::MIN_FOR_VERIFIED {
            return false;
        }
        if !self.failed_test_ids.is_empty() {
            return false;
        }
        for tid in &self.test_ids {
            if !self.passed_test_ids.iter().any(|p| p == tid) {
                return false;
            }
        }
        true
    }

    /// True if any mandatory evidence field has at least one value present
    /// (used to distinguish Partial vs Unverified when incomplete).
    #[must_use]
    pub fn any_mandatory_partial(&self) -> bool {
        !self.source_ids.is_empty()
            || !self.input_ids.is_empty()
            || self.execution_record_id.is_some()
            || !self.output_ids.is_empty()
            || self.provenance_claim_id.is_some()
            || !self.corroboration_ids.is_empty()
            || !self.test_ids.is_empty()
            || self.corroboration_ok
            || self.regression_ok
            || !self.passed_test_ids.is_empty()
            || !self.failed_test_ids.is_empty()
            || !self.regression_lock_ids.is_empty()
            || !self.benchmark_ids.is_empty()
            // Explicit false on freshness/reproducibility counts as activity
            // so Partial-vs-Unverified hard-fail ordering stays consistent.
            || !self.freshness_ok
            || !self.reproducibility_ok
            || self.evidence_level != EvidenceLevel::Assertion
    }

    /// SHA-256 content hash (lowercase hex) of this links struct.
    ///
    /// Equivalent to [`evidence_links_content_hash`]. Not an input to
    /// [`derive_status`] — hashing alone never invents Verified.
    #[must_use]
    pub fn content_hash(&self) -> String {
        evidence_links_content_hash(self)
    }

    /// Provenance binding string: `{claim_id}|sha256:{hash}` (or `sha256:{hash}`
    /// when no claim id). See [`evidence_links_provenance_binding`].
    #[must_use]
    pub fn provenance_binding(&self) -> String {
        evidence_links_provenance_binding(self)
    }
}

/// Schema id embedded in every canonical evidence payload (v1).
///
/// Bump only when the canonical field set or encoding changes in a
/// digest-breaking way.
pub const EVIDENCE_CONTENT_HASH_SCHEMA: &str = "hse.capability.evidence_links.v1";

/// Deterministic canonical JSON for content-addressing [`CapabilityEvidenceLinks`].
///
/// - Keys appear in a **fixed schema order** (hand-built JSON; not `serde_json::Map`, which sorts keys).
/// - `Vec` fields preserve **stored order** (order is part of evidence identity).
/// - Booleans use JSON `true`/`false`; absent optionals use JSON `null`.
/// - `evidence_level` uses [`EvidenceLevel::as_str`].
///
/// **Not an input to [`derive_status`].** Content-addressing binds the evidence
/// store; it does not promote status.
#[must_use]
pub fn evidence_links_canonical_json(links: &CapabilityEvidenceLinks) -> String {
    // Hand-built JSON: serde_json::Map sorts keys alphabetically on serialize,
    // which would break the fixed schema order required for content-addressing.
    fn esc(s: &str) -> String {
        serde_json::to_string(s).expect("string JSON encode")
    }
    fn arr(xs: &[String]) -> String {
        let parts: Vec<String> = xs.iter().map(|s| esc(s)).collect();
        format!("[{}]", parts.join(","))
    }
    fn opt(v: &Option<String>) -> String {
        match v {
            Some(s) => esc(s),
            None => "null".to_string(),
        }
    }
    fn bool_json(b: bool) -> &'static str {
        if b { "true" } else { "false" }
    }

    format!(
        concat!(
            r#"{{"schema":{schema},"source_ids":{source_ids},"input_ids":{input_ids},"#,
            r#""execution_record_id":{execution_record_id},"output_ids":{output_ids},"#,
            r#""provenance_claim_id":{provenance_claim_id},"corroboration_ids":{corroboration_ids},"#,
            r#""test_ids":{test_ids},"benchmark_ids":{benchmark_ids},"#,
            r#""regression_lock_ids":{regression_lock_ids},"passed_test_ids":{passed_test_ids},"#,
            r#""failed_test_ids":{failed_test_ids},"corroboration_ok":{corroboration_ok},"#,
            r#""regression_ok":{regression_ok},"freshness_ok":{freshness_ok},"#,
            r#""reproducibility_ok":{reproducibility_ok},"evidence_level":{evidence_level}}}"#
        ),
        schema = esc(EVIDENCE_CONTENT_HASH_SCHEMA),
        source_ids = arr(&links.source_ids),
        input_ids = arr(&links.input_ids),
        execution_record_id = opt(&links.execution_record_id),
        output_ids = arr(&links.output_ids),
        provenance_claim_id = opt(&links.provenance_claim_id),
        corroboration_ids = arr(&links.corroboration_ids),
        test_ids = arr(&links.test_ids),
        benchmark_ids = arr(&links.benchmark_ids),
        regression_lock_ids = arr(&links.regression_lock_ids),
        passed_test_ids = arr(&links.passed_test_ids),
        failed_test_ids = arr(&links.failed_test_ids),
        corroboration_ok = bool_json(links.corroboration_ok),
        regression_ok = bool_json(links.regression_ok),
        freshness_ok = bool_json(links.freshness_ok),
        reproducibility_ok = bool_json(links.reproducibility_ok),
        evidence_level = esc(links.evidence_level.as_str()),
    )
}

/// SHA-256 (lowercase hex) of the UTF-8 bytes of [`evidence_links_canonical_json`].
///
/// Tampering with any hashed field changes the digest. Does **not** feed
/// [`derive_status`].
#[must_use]
pub fn evidence_links_content_hash(links: &CapabilityEvidenceLinks) -> String {
    use sha2::{Digest, Sha256};
    let canonical = evidence_links_canonical_json(links);
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// Bind `provenance_claim_id` to the content hash for the evidence-store axis.
///
/// Format:
/// - with claim id: `{provenance_claim_id}|sha256:{64-hex}`
/// - without: `sha256:{64-hex}`
///
/// This is a derived view — it does not rewrite `provenance_claim_id` on the
/// links struct and is not an input to [`derive_status`].
#[must_use]
pub fn evidence_links_provenance_binding(links: &CapabilityEvidenceLinks) -> String {
    let hash = evidence_links_content_hash(links);
    match links.provenance_claim_id.as_deref() {
        Some(id) if !id.is_empty() => format!("{id}|sha256:{hash}"),
        _ => format!("sha256:{hash}"),
    }
}

/// Static claim specification used when seeding the ledger.
///
/// Seed rows always start with **empty** links. Comments in
/// [`CapabilityLedger::seed_v0`] mark these as claim placeholders, not attack
/// implementations. Presence of a technique in [`crate::core::attack`] or a
/// module→technique map does **not** imply Verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityClaimSpec {
    /// ATT&CK technique id (`Txxxx` or `Txxxx.xxx`).
    pub technique_id: &'static str,
    /// Human-readable defensive claim label.
    pub name: &'static str,
    /// Rust component path owning the claim surface.
    pub rust_component: &'static str,
    /// Method plugin id for future frontier competition (v0: static tag only).
    ///
    /// Status is **never** derived from this field — evidence links only.
    pub method_id: &'static str,
    /// Optional short objective statement for the claim chain.
    pub objective: Option<&'static str>,
    /// In-scope vs explicit NotApplicable.
    pub scope: ClaimScope,
}

/// One ledger row: technique + method + component + evidence links.
///
/// **No stored status field** — status is always derived via
/// [`CapabilityLedger::status_of`] / [`derive_status`]. This makes manual
/// `Verified` promotion impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRow {
    /// ATT&CK technique id.
    pub technique_id: String,
    /// Human-readable defensive claim label.
    pub name: String,
    /// Rust component path owning the claim surface.
    pub rust_component: String,
    /// Method plugin id (v0 string tag; future competition attaches here).
    pub method_id: String,
    /// Optional short objective for the evidence chain.
    pub objective: Option<String>,
    /// In-scope vs explicit NotApplicable.
    pub scope: ClaimScope,
    /// Evidence links (status is never stored here).
    pub links: CapabilityEvidenceLinks,
}

impl CapabilityRow {
    /// Live content hash of [`Self::links`] (sha256 hex).
    ///
    /// Always recomputed from current links so mutators (`set_links`,
    /// `invalidate_*`) cannot leave a stale digest. Not stored separately and
    /// not an input to [`derive_status`].
    #[must_use]
    pub fn evidence_content_hash(&self) -> String {
        evidence_links_content_hash(&self.links)
    }

    /// Live provenance binding for [`Self::links`].
    #[must_use]
    pub fn evidence_provenance_binding(&self) -> String {
        evidence_links_provenance_binding(&self.links)
    }
}

/// Errors from ledger mutation APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// Technique id is not present in the ledger.
    UnknownTechnique(String),
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTechnique(id) => write!(f, "unknown technique id: {id}"),
        }
    }
}

impl std::error::Error for CapabilityError {}

/// Derive capability status from scope + evidence links.
///
/// Rules:
/// - `NotApplicable` scope → [`CapabilityStatus::NotApplicable`] (even if links present)
/// - any `failed_test_ids` → [`CapabilityStatus::Unverified`]
/// - `!freshness_ok` → [`CapabilityStatus::Unverified`]
/// - `!reproducibility_ok` → [`CapabilityStatus::Unverified`]
/// - `!regression_ok` with any evidence activity → [`CapabilityStatus::Unverified`]
/// - `mandatory_complete` (includes `evidence_level >= IndependentCorroboration`)
///   → [`CapabilityStatus::Verified`]
/// - any mandatory field partially filled → [`CapabilityStatus::Partial`]
/// - else [`CapabilityStatus::Unverified`]
///
/// ATT&CK catalogue membership, Coverage heatmaps, and module maps are
/// **not** inputs to this function. **Mapping ≠ capability. Catalog ≠ Verified.**
#[must_use]
pub fn derive_status(scope: ClaimScope, links: &CapabilityEvidenceLinks) -> CapabilityStatus {
    if scope == ClaimScope::NotApplicable {
        return CapabilityStatus::NotApplicable;
    }
    // Hard failures: prefer Unverified (even if some links exist).
    if !links.failed_test_ids.is_empty() {
        return CapabilityStatus::Unverified;
    }
    if !links.freshness_ok || !links.reproducibility_ok {
        return CapabilityStatus::Unverified;
    }
    // regression_ok=false with any evidence activity → Unverified (auto-downgrade).
    // Empty default (regression_ok=false, no links) falls through to Unverified below.
    if !links.regression_ok && links.any_mandatory_partial() {
        return CapabilityStatus::Unverified;
    }
    if links.mandatory_complete() {
        // mandatory_complete already requires corroboration_ok, regression_ok,
        // freshness_ok, reproducibility_ok, failed empty, and every test_id
        // in passed_test_ids.
        return CapabilityStatus::Verified;
    }
    if links.any_mandatory_partial() {
        return CapabilityStatus::Partial;
    }
    CapabilityStatus::Unverified
}

/// Self-verifying ATT&CK capability ledger (technique_id → row).
///
/// Internally a [`BTreeMap`] for stable techniqueID sort order in exports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapabilityLedger {
    rows: BTreeMap<String, CapabilityRow>,
}

impl CapabilityLedger {
    /// Empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
        }
    }

    /// Curated v0 seed: InScope claim placeholders (empty links → Unverified)
    /// plus explicit NotApplicable stubs for offensive / host-intrusion product
    /// capabilities HSE does not claim.
    ///
    /// These are **CLAIM PLACEHOLDERS for future defensive evidence**, not
    /// implementations of attacks. Technique IDs are chosen from the HSE
    /// ATT&CK catalogue for interoperability only — catalogue presence and
    /// module→technique maps do **not** make a row Verified.
    /// `verified_count()` on the seed is **0**.
    #[must_use]
    pub fn seed_v0() -> Self {
        // Claim placeholders only — no attack procedures / payloads / exploits.
        const SPECS: &[CapabilityClaimSpec] = &[
            // --- InScope OSINT / Termux / recon placeholders (empty → Unverified) ---
            CapabilityClaimSpec {
                technique_id: "T1590",
                name: "Gather Victim Network Information — passive recon claim",
                rust_component: "modules/dns_intel",
                method_id: "recon.passive",
                objective: Some("Defensive OSINT network-information collection claim"),
                scope: ClaimScope::InScope,
            },
            // Catalogue: T1596.003 Digital Certificates (crt.sh); parent T1596 =
            // Search Open Technical Databases. Prefer .003 over .002 (WHOIS).
            CapabilityClaimSpec {
                technique_id: "T1596.003",
                name: "Search open certificate databases (crt.sh) — collection claim",
                rust_component: "modules/crtsh",
                method_id: "recon.collection",
                objective: Some("Passive digital-certificate OSINT collection claim"),
                scope: ClaimScope::InScope,
            },
            CapabilityClaimSpec {
                technique_id: "T1040",
                name: "Network observation surface (defensive Wi-Fi sensing claim)",
                rust_component: "modules/wifi_intel",
                method_id: "sensing.wifi",
                objective: Some(
                    "Defensive local RF/Wi-Fi observation claim — not offensive sniffing toolkit",
                ),
                scope: ClaimScope::InScope,
            },
            CapabilityClaimSpec {
                technique_id: "T1016.002",
                name: "Wi-Fi Discovery — Termux device sensing claim",
                rust_component: "util/termux",
                method_id: "sensing.termux",
                objective: Some("Device Wi-Fi scan observation via Termux helpers"),
                scope: ClaimScope::InScope,
            },
            CapabilityClaimSpec {
                technique_id: "T1614",
                name: "System Location Discovery — offline GEOINT coord/geodesic claim",
                rust_component: "util/geo",
                method_id: "geoint.offline",
                objective: Some(
                    "Offline coordinate parse + geodesic distance (haversine) GEOINT claim",
                ),
                scope: ClaimScope::InScope,
            },
            CapabilityClaimSpec {
                technique_id: "T1589",
                name: "Gather Victim Identity Information — offline identity canonicalize claim",
                rust_component: "util/canonical",
                method_id: "identity.canonicalize",
                objective: Some(
                    "Offline email mailbox fold + name-token identity normaliser claim",
                ),
                scope: ClaimScope::InScope,
            },
            // --- Explicit NotApplicable: offensive / host-intrusion product caps ---
            CapabilityClaimSpec {
                technique_id: "T1566",
                name: "Phishing — n/a (not an HSE product offensive capability)",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1598",
                name: "Phishing for Information — n/a",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1003",
                name: "OS Credential Dumping — n/a (host intrusion)",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1059",
                name: "Command and Scripting Interpreter — n/a",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1021",
                name: "Remote Services — n/a",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1486",
                name: "Data Encrypted for Impact (ransomware) — n/a",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1071",
                name: "Application Layer Protocol (C2) — n/a",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1046",
                name: "Network Service Discovery — n/a (active scanning unless lawful in-tree method)",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
            CapabilityClaimSpec {
                technique_id: "T1555",
                name: "Credentials from Password Stores — n/a (credential collection)",
                rust_component: "n/a",
                method_id: "n/a",
                objective: None,
                scope: ClaimScope::NotApplicable,
            },
        ];

        let mut ledger = Self::new();
        for spec in SPECS {
            ledger.insert_row(CapabilityRow {
                technique_id: spec.technique_id.to_string(),
                name: spec.name.to_string(),
                rust_component: spec.rust_component.to_string(),
                method_id: spec.method_id.to_string(),
                objective: spec.objective.map(str::to_string),
                scope: spec.scope,
                links: CapabilityEvidenceLinks::empty(),
            });
        }
        ledger
    }

    /// Insert or replace a row. Status is never stored — always derived.
    pub fn insert_row(&mut self, row: CapabilityRow) {
        self.rows.insert(row.technique_id.clone(), row);
    }

    /// Borrow a row by technique id.
    #[must_use]
    pub fn get(&self, technique_id: &str) -> Option<&CapabilityRow> {
        self.rows.get(technique_id)
    }

    /// Iterate rows sorted by technique_id (BTreeMap order).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &CapabilityRow)> {
        self.rows.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Update evidence links only; status remains derived.
    pub fn set_links(
        &mut self,
        technique_id: &str,
        links: CapabilityEvidenceLinks,
    ) -> Result<(), CapabilityError> {
        let row = self
            .rows
            .get_mut(technique_id)
            .ok_or_else(|| CapabilityError::UnknownTechnique(technique_id.to_string()))?;
        row.links = links;
        Ok(())
    }

    /// Content hash of a row's evidence links, if the technique exists.
    ///
    /// See [`evidence_links_content_hash`]. Not an input to [`derive_status`].
    #[must_use]
    pub fn evidence_content_hash(&self, technique_id: &str) -> Option<String> {
        self.rows
            .get(technique_id)
            .map(|r| r.evidence_content_hash())
    }

    /// Provenance binding for a row's evidence links, if present.
    ///
    /// See [`evidence_links_provenance_binding`].
    #[must_use]
    pub fn evidence_provenance_binding(&self, technique_id: &str) -> Option<String> {
        self.rows
            .get(technique_id)
            .map(|r| r.evidence_provenance_binding())
    }

    /// Derived status for a technique, if present.
    #[must_use]
    pub fn status_of(&self, technique_id: &str) -> Option<CapabilityStatus> {
        self.rows
            .get(technique_id)
            .map(|r| derive_status(r.scope, &r.links))
    }

    /// Count of rows whose derived status is [`CapabilityStatus::Verified`].
    /// NotApplicable never contributes.
    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.rows
            .values()
            .filter(|r| derive_status(r.scope, &r.links) == CapabilityStatus::Verified)
            .count()
    }

    /// Counts per derived status.
    #[must_use]
    pub fn counts_by_status(&self) -> BTreeMap<CapabilityStatus, usize> {
        let mut counts = BTreeMap::new();
        for status in [
            CapabilityStatus::Verified,
            CapabilityStatus::Partial,
            CapabilityStatus::Unverified,
            CapabilityStatus::NotApplicable,
        ] {
            counts.insert(status, 0);
        }
        for row in self.rows.values() {
            let s = derive_status(row.scope, &row.links);
            *counts.entry(s).or_insert(0) += 1;
        }
        counts
    }

    /// Mark a linked test as failed: move/add to `failed_test_ids`, remove from
    /// `passed_test_ids`. Used to demonstrate auto-downgrade of derived status.
    pub fn invalidate_test(
        &mut self,
        technique_id: &str,
        test_id: &str,
    ) -> Result<(), CapabilityError> {
        let row = self
            .rows
            .get_mut(technique_id)
            .ok_or_else(|| CapabilityError::UnknownTechnique(technique_id.to_string()))?;
        row.links.passed_test_ids.retain(|id| id != test_id);
        if !row.links.failed_test_ids.iter().any(|id| id == test_id) {
            row.links.failed_test_ids.push(test_id.to_string());
        }
        Ok(())
    }

    /// Force freshness failure on a row (auto-downgrade path).
    pub fn invalidate_freshness(&mut self, technique_id: &str) -> Result<(), CapabilityError> {
        let row = self
            .rows
            .get_mut(technique_id)
            .ok_or_else(|| CapabilityError::UnknownTechnique(technique_id.to_string()))?;
        row.links.freshness_ok = false;
        Ok(())
    }

    /// Force reproducibility failure on a row (auto-downgrade path).
    pub fn invalidate_reproducibility(
        &mut self,
        technique_id: &str,
    ) -> Result<(), CapabilityError> {
        let row = self
            .rows
            .get_mut(technique_id)
            .ok_or_else(|| CapabilityError::UnknownTechnique(technique_id.to_string()))?;
        row.links.reproducibility_ok = false;
        Ok(())
    }

    /// ATT&CK Navigator layer 4.x compatible JSON (**capability ledger layer**).
    ///
    /// Scores/colors come **only** from [`derive_status`]. No manual status
    /// override parameter exists. This is **not** a coverage heatmap — keep
    /// separate from [`crate::core::attack::navigator_layer`].
    ///
    /// Uses `serde_json` for consistency with the coverage Navigator exporter.
    #[must_use]
    pub fn navigator_layer(&self, name: &str, domain: &str, version: &str) -> JsonValue {
        let techniques: Vec<JsonValue> = self
            .rows
            .iter()
            .map(|(tid, row)| {
                let status = derive_status(row.scope, &row.links);
                let comment = format!(
                    "{} | method={} | {} | status={} | capability-ledger (not coverage)",
                    row.name,
                    row.method_id,
                    row.rust_component,
                    status.as_str()
                );
                json!({
                    "techniqueID": tid,
                    "score": status.navigator_score(),
                    "color": status.navigator_color(),
                    "enabled": true,
                    "comment": comment,
                })
            })
            .collect();

        json!({
            "name": name,
            "versions": {
                "attack": version,
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": domain,
            "description": "Derived-only HSE capability ledger layer (NOT a coverage heatmap). \
                 Status colors reflect derive_status; Verified requires full evidence chain. \
                 Module→technique maps and attack::Coverage must never be treated as Verified. \
                 Defensive claims only — not an attack toolkit.",
            "techniques": techniques,
        })
    }

    /// Deterministic JSON string form of [`Self::navigator_layer`] (stable key order
    /// via serde_json Value Display is not guaranteed; use this helper when tests
    /// need round-trip equality on the same Value serialization path).
    #[must_use]
    pub fn navigator_layer_string(&self, name: &str, domain: &str, version: &str) -> String {
        self.navigator_layer(name, domain, version).to_string()
    }
}

/// Known-good offline GEOINT evidence fixture for [`CapabilityLedger`] technique
/// `T1614` (first OSINT capability claim).
///
/// # Competition (v0 first claim)
///
/// Evaluated two InScope candidates against host constraints (no live network,
/// leave dirty `stolen_tax` / `crtsh` alone):
///
/// | Candidate | Technique | In-tree surface | Offline tests | Dirty risk |
/// |---|---|---|---|---|
/// | A Identity | `T1589` / `T1589.002` | `util/canonical`, `util/identity` | email fold + name tokens | Medium — seed `T1589` still labels `modules/stolen_tax` |
/// | **B GEOINT (winner)** | `T1614` | `util/geo`, `util/geohash` | `parse_coords` + `haversine_km` | **None** |
///
/// GEOINT wins: two independent offline corroboration channels (coord-parse
/// validation vs spherical-geodesic known Sydney↔Melbourne distance), pure
/// numeric fixtures, zero touch of dirty WIP modules, highest reproducibility.
///
/// # Corroboration channels (IndependentCorroboration)
///
/// 1. **Coord parse / validity** — `util::geo::tests::parse_coords_*` /
///    `valid_coords_*` (string→(lat,lon) gate; Null Island / range / non-finite).
/// 2. **Geodesic distance** — `util::geo::tests::haversine_km_matches_known_distances`
///    and `util::geohash::tests::haversine_known_distance_sydney_to_melbourne`
///    (independent arithmetic surface; same known ~714 km Syd–Mel fixture).
///
/// # Honesty
///
/// Links record **existing** `#[test]` function paths as `test_ids`. They do
/// not invent network or device observation. Termux live location remains
/// Unverified without a device — this claim is the offline GEOINT method that
/// already ships and passes under `cargo test --lib`.
#[must_use]
pub fn geoint_t1614_evidence_links_v1() -> CapabilityEvidenceLinks {
    // Stable test_id strings = rustc test paths matching #[test] fn names.
    const T_PARSE: &str = "util::geo::tests::parse_coords_accepts_well_formed_pairs";
    const T_VALID: &str = "util::geo::tests::valid_coords_accepts_real_positions";
    const T_HAV_GEO: &str = "util::geo::tests::haversine_km_matches_known_distances";
    const T_HAV_HASH: &str = "util::geohash::tests::haversine_known_distance_sydney_to_melbourne";

    CapabilityEvidenceLinks {
        source_ids: vec!["src-util-geo".into(), "src-util-geohash-distance".into()],
        input_ids: vec![
            "in-brisbane-coord-string:-27.4766,153.0166".into(),
            "in-sydney-melbourne-pair:(-33.8688,151.2093)->(-37.8136,144.9631)".into(),
        ],
        execution_record_id: Some("exec-geoint-offline-unit-v1".into()),
        output_ids: vec![
            "out-parsed-brisbane:(-27.4766,153.0166)".into(),
            "out-haversine-syd-mel:~714km".into(),
        ],
        provenance_claim_id: Some("prov-geoint-offline-fixture-v1".into()),
        corroboration_ids: vec![
            "corr-geoint-coord-parse".into(),
            "corr-geoint-haversine-syd-mel".into(),
        ],
        test_ids: vec![
            T_PARSE.into(),
            T_VALID.into(),
            T_HAV_GEO.into(),
            T_HAV_HASH.into(),
        ],
        benchmark_ids: vec![],
        regression_lock_ids: vec![
            "lock-geoint-t1614-v1".into(),
            "lock-capability-derive-status".into(),
        ],
        passed_test_ids: vec![
            T_PARSE.into(),
            T_VALID.into(),
            T_HAV_GEO.into(),
            T_HAV_HASH.into(),
        ],
        failed_test_ids: vec![],
        corroboration_ok: true,
        regression_ok: true,
        freshness_ok: true,
        reproducibility_ok: true,
        evidence_level: EvidenceLevel::IndependentCorroboration,
    }
}

/// Attach the first honest OSINT capability evidence chain (GEOINT / `T1614`).
///
/// Seed rows stay empty (Unverified). Call this after [`CapabilityLedger::seed_v0`]
/// to wire `CapabilityEvidenceLinks` for the chosen technique. Identity
/// (`T1589` / email+name normalisers) was the first-claim runner-up — see
/// [`geoint_t1614_evidence_links_v1`] competition notes; second claim lands via
/// [`apply_identity_evidence_v1`].
///
/// Returns `Ok(())` when `T1614` is present; does not touch other rows.
pub fn apply_identity_geoint_evidence_v1(
    ledger: &mut CapabilityLedger,
) -> Result<(), CapabilityError> {
    ledger.set_links("T1614", geoint_t1614_evidence_links_v1())
}

/// Known-good offline identity evidence fixture for [`CapabilityLedger`] technique
/// `T1589` (second OSINT capability claim).
///
/// # Competition (v0 second claim)
///
/// Evaluated InScope candidates against host constraints (no live network,
/// leave dirty `stolen_tax` / `crtsh` alone; do not invent Verified on breach
/// recon). Seed `T1589` was rebound from `modules/stolen_tax` / `recon.breach`
/// to the clean util path (same pattern as GEOINT rebind of `T1614`).
///
/// | Candidate | Technique | In-tree surface | Offline tests | Dirty risk | Rank |
/// |---|---|---|---|---|---|
/// | **A Email+name canonicalize (winner)** | `T1589` | `util/canonical` | gmail fold + name tokens | **None** | 1 |
/// | B Demographic tags | `T1589` | `util/identity` | dob/gender/age fold | Low (breach-schema oriented) | 2 |
/// | C Breach recon (rejected) | `T1589` | `modules/stolen_tax` | N/A dirty WIP | **High** | 3 |
///
/// Winner A: two independent offline corroboration channels (email mailbox
/// canonicalization vs person-name tokenization), pure string fixtures, zero
/// touch of dirty WIP, highest reproducibility under Termux/offline constraints.
/// Method B remains available as a future demographic channel; C stays unbound
/// from Verified until a lawful clean evidence path exists.
///
/// # Corroboration channels (IndependentCorroboration)
///
/// 1. **Email mailbox fold** — `util::canonical::tests::gmail_dots_and_plus_tag_both_fold`
///    and `googlemail_alias_folds_to_gmail` (provider-aware local+domain fold).
/// 2. **Name word tokens** — `util::canonical::tests::hyphen_apostrophe_and_underscore_stay_inside_their_token`
///    and `edge_punctuation_is_stripped_not_split_on` (independent tokenizer surface).
///
/// # Honesty
///
/// Links record **existing** `#[test]` function paths as `test_ids`. They do
/// not invent network observation, breach harvest, or credential collection.
/// This claim is offline identity *normalization* — not live victim
/// enumeration.
#[must_use]
pub fn identity_t1589_evidence_links_v1() -> CapabilityEvidenceLinks {
    const T_GMAIL: &str = "util::canonical::tests::gmail_dots_and_plus_tag_both_fold";
    const T_GOOGLEMAIL: &str = "util::canonical::tests::googlemail_alias_folds_to_gmail";
    const T_HYPHEN: &str =
        "util::canonical::tests::hyphen_apostrophe_and_underscore_stay_inside_their_token";
    const T_EDGE: &str = "util::canonical::tests::edge_punctuation_is_stripped_not_split_on";

    CapabilityEvidenceLinks {
        source_ids: vec![
            "src-util-canonical-email".into(),
            "src-util-canonical-name".into(),
        ],
        input_ids: vec![
            "in-gmail-plus-dot:jo.hn+promo@gmail.com".into(),
            "in-name-compound:Anna Smith-Jones / Bamford, Haigen".into(),
        ],
        execution_record_id: Some("exec-identity-canonicalize-unit-v1".into()),
        output_ids: vec![
            "out-gmail-folded:john@gmail.com".into(),
            "out-name-tokens:[anna,smith-jones]/[bamford,haigen]".into(),
        ],
        provenance_claim_id: Some("prov-identity-canonicalize-fixture-v1".into()),
        corroboration_ids: vec![
            "corr-identity-email-fold".into(),
            "corr-identity-name-tokens".into(),
        ],
        test_ids: vec![
            T_GMAIL.into(),
            T_GOOGLEMAIL.into(),
            T_HYPHEN.into(),
            T_EDGE.into(),
        ],
        benchmark_ids: vec![],
        regression_lock_ids: vec![
            "lock-identity-t1589-v1".into(),
            "lock-capability-derive-status".into(),
        ],
        passed_test_ids: vec![
            T_GMAIL.into(),
            T_GOOGLEMAIL.into(),
            T_HYPHEN.into(),
            T_EDGE.into(),
        ],
        failed_test_ids: vec![],
        corroboration_ok: true,
        regression_ok: true,
        freshness_ok: true,
        reproducibility_ok: true,
        evidence_level: EvidenceLevel::IndependentCorroboration,
    }
}

/// Attach the second honest OSINT capability evidence chain (identity / `T1589`).
///
/// Seed rows stay empty (Unverified) until this is called. Does not touch GEOINT
/// `T1614` or other rows. Pair with [`apply_identity_geoint_evidence_v1`] when
/// both claims should be Verified (`verified_count == 2`).
///
/// Returns `Ok(())` when `T1589` is present.
pub fn apply_identity_evidence_v1(ledger: &mut CapabilityLedger) -> Result<(), CapabilityError> {
    ledger.set_links("T1589", identity_t1589_evidence_links_v1())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_links() -> CapabilityEvidenceLinks {
        CapabilityEvidenceLinks {
            source_ids: vec!["src-oracle-1".into()],
            input_ids: vec!["in-fixture-1".into()],
            execution_record_id: Some("exec-1".into()),
            output_ids: vec!["out-1".into()],
            provenance_claim_id: Some("claim-1".into()),
            corroboration_ids: vec!["corr-independent-1".into()],
            test_ids: vec!["test-capability-1".into()],
            benchmark_ids: vec![],
            regression_lock_ids: vec!["lock-1".into()],
            passed_test_ids: vec!["test-capability-1".into()],
            failed_test_ids: vec![],
            corroboration_ok: true,
            regression_ok: true,
            freshness_ok: true,
            reproducibility_ok: true,
            evidence_level: EvidenceLevel::IndependentCorroboration,
        }
    }

    #[test]
    fn empty_links_in_scope_are_unverified() {
        assert_eq!(
            derive_status(ClaimScope::InScope, &CapabilityEvidenceLinks::empty()),
            CapabilityStatus::Unverified
        );
    }

    #[test]
    fn na_scope_ignores_links() {
        let mut links = CapabilityEvidenceLinks::empty();
        links.source_ids.push("s1".into());
        assert_eq!(
            derive_status(ClaimScope::NotApplicable, &links),
            CapabilityStatus::NotApplicable
        );
    }

    #[test]
    fn seed_v0_has_zero_verified() {
        let ledger = CapabilityLedger::seed_v0();
        assert_eq!(ledger.verified_count(), 0);

        let in_scope = ["T1590", "T1596.003", "T1040", "T1016.002", "T1614", "T1589"];
        for tid in in_scope {
            assert_eq!(
                ledger.status_of(tid),
                Some(CapabilityStatus::Unverified),
                "{tid} should start Unverified"
            );
        }

        let na = [
            "T1566", "T1598", "T1003", "T1059", "T1021", "T1486", "T1071", "T1046", "T1555",
        ];
        for tid in na {
            assert_eq!(
                ledger.status_of(tid),
                Some(CapabilityStatus::NotApplicable),
                "{tid} should be NotApplicable"
            );
        }

        let counts = ledger.counts_by_status();
        assert_eq!(counts.get(&CapabilityStatus::Verified), Some(&0));
        assert_eq!(counts.get(&CapabilityStatus::Unverified), Some(&6));
        assert_eq!(counts.get(&CapabilityStatus::NotApplicable), Some(&9));
    }

    #[test]
    fn seed_rows_have_method_id() {
        let ledger = CapabilityLedger::seed_v0();
        for (tid, row) in ledger.iter() {
            assert!(!row.method_id.is_empty(), "{tid} missing method_id");
        }
        assert_eq!(
            ledger.get("T1596.003").map(|r| r.method_id.as_str()),
            Some("recon.collection")
        );
        assert_eq!(
            ledger.get("T1040").map(|r| r.method_id.as_str()),
            Some("sensing.wifi")
        );
        assert_eq!(
            ledger.get("T1614").map(|r| r.method_id.as_str()),
            Some("geoint.offline")
        );
        assert_eq!(
            ledger.get("T1614").map(|r| r.rust_component.as_str()),
            Some("util/geo")
        );
        assert_eq!(
            ledger.get("T1589").map(|r| r.method_id.as_str()),
            Some("identity.canonicalize")
        );
        assert_eq!(
            ledger.get("T1589").map(|r| r.rust_component.as_str()),
            Some("util/canonical")
        );
        assert_eq!(
            ledger.get("T1566").map(|r| r.method_id.as_str()),
            Some("n/a")
        );
    }

    #[test]
    fn manual_verified_without_evidence_is_impossible() {
        assert_eq!(
            derive_status(ClaimScope::InScope, &CapabilityEvidenceLinks::empty()),
            CapabilityStatus::Unverified
        );

        let ledger = CapabilityLedger::seed_v0();
        assert_eq!(ledger.verified_count(), 0);

        let incomplete = CapabilityEvidenceLinks {
            source_ids: vec!["s".into()],
            regression_ok: true,
            ..CapabilityEvidenceLinks::empty()
        };
        assert!(!incomplete.mandatory_complete());
        assert_ne!(
            derive_status(ClaimScope::InScope, &incomplete),
            CapabilityStatus::Verified
        );

        let full = complete_links();
        assert!(full.mandatory_complete());
        assert_eq!(
            derive_status(ClaimScope::InScope, &full),
            CapabilityStatus::Verified
        );
    }

    #[test]
    fn full_evidence_chain_derives_verified() {
        let mut ledger = CapabilityLedger::seed_v0();
        ledger
            .set_links("T1040", complete_links())
            .expect("T1040 present");
        assert_eq!(ledger.status_of("T1040"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 1);
    }

    #[test]
    fn evidence_failure_auto_downgrades() {
        let mut ledger = CapabilityLedger::seed_v0();
        ledger
            .set_links("T1040", complete_links())
            .expect("T1040 present");
        assert_eq!(ledger.status_of("T1040"), Some(CapabilityStatus::Verified));

        ledger
            .invalidate_test("T1040", "test-capability-1")
            .expect("invalidate");
        let after = ledger.status_of("T1040");
        assert!(
            after == Some(CapabilityStatus::Unverified) || after == Some(CapabilityStatus::Partial),
            "expected Unverified or Partial after invalidate, got {after:?}"
        );
        assert_ne!(after, Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 0);

        let layer = ledger.navigator_layer_string("test-layer", "enterprise-attack", "17.1");
        assert!(
            !layer.contains("\"techniqueID\":\"T1040\",\"score\":100,\"color\":\"#31a354\""),
            "navigator must not export Verified color after downgrade"
        );
        assert!(
            layer.contains("\"techniqueID\":\"T1040\""),
            "T1040 still present in layer"
        );
    }

    #[test]
    fn freshness_failure_auto_downgrades_verified() {
        let mut ledger = CapabilityLedger::seed_v0();
        ledger
            .set_links("T1590", complete_links())
            .expect("T1590 present");
        assert_eq!(ledger.status_of("T1590"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 1);

        ledger
            .invalidate_freshness("T1590")
            .expect("invalidate freshness");
        assert_eq!(
            ledger.status_of("T1590"),
            Some(CapabilityStatus::Unverified)
        );
        assert_eq!(ledger.verified_count(), 0);
    }

    #[test]
    fn reproducibility_failure_auto_downgrades_verified() {
        let mut ledger = CapabilityLedger::seed_v0();
        ledger
            .set_links("T1589", complete_links())
            .expect("T1589 present");
        assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));

        ledger
            .invalidate_reproducibility("T1589")
            .expect("invalidate reproducibility");
        assert_eq!(
            ledger.status_of("T1589"),
            Some(CapabilityStatus::Unverified)
        );
        assert_eq!(ledger.verified_count(), 0);
    }

    #[test]
    fn not_applicable_never_counts_as_verified() {
        let mut ledger = CapabilityLedger::seed_v0();
        let before = ledger.verified_count();
        assert_eq!(before, 0);

        ledger
            .set_links("T1566", complete_links())
            .expect("T1566 present");
        assert_eq!(
            ledger.status_of("T1566"),
            Some(CapabilityStatus::NotApplicable)
        );
        assert_eq!(ledger.verified_count(), before);

        let layer = ledger.navigator_layer("na-check", "enterprise-attack", "17.1");
        let tech = layer["techniques"]
            .as_array()
            .expect("techniques")
            .iter()
            .find(|t| t["techniqueID"] == "T1566")
            .expect("T1566 in layer");
        assert_eq!(tech["score"], 0);
        assert_eq!(tech["color"], "#bdbdbd");
    }

    #[test]
    fn navigator_deterministic_and_derived_only() {
        let ledger = CapabilityLedger::seed_v0();
        let a = ledger.navigator_layer("cap-v0", "enterprise-attack", "17.1");
        let b = ledger.navigator_layer("cap-v0", "enterprise-attack", "17.1");
        assert_eq!(a, b, "navigator export must be deterministic");

        assert_eq!(a["name"], "cap-v0");
        assert_eq!(a["domain"], "enterprise-attack");
        assert_eq!(a["versions"]["attack"], "17.1");
        assert_eq!(a["versions"]["navigator"], "4.9.1");
        assert_eq!(a["versions"]["layer"], "4.5");
        assert!(
            a["description"]
                .as_str()
                .unwrap_or("")
                .contains("capability ledger"),
            "must label as capability ledger layer"
        );
        assert!(
            a["description"]
                .as_str()
                .unwrap_or("")
                .contains("NOT a coverage heatmap"),
            "must distinguish from coverage heatmap"
        );

        let techniques = a["techniques"].as_array().expect("techniques array");
        let ids: Vec<&str> = techniques
            .iter()
            .map(|t| t["techniqueID"].as_str().unwrap())
            .collect();
        for tid in [
            "T1003",
            "T1016.002",
            "T1021",
            "T1040",
            "T1046",
            "T1059",
            "T1071",
            "T1486",
            "T1555",
            "T1566",
            "T1589",
            "T1590",
            "T1596.003",
            "T1598",
            "T1614",
        ] {
            assert!(ids.contains(&tid), "missing {tid}");
        }

        let t1040 = techniques
            .iter()
            .find(|t| t["techniqueID"] == "T1040")
            .expect("T1040");
        assert_eq!(t1040["score"], 10);
        assert_eq!(t1040["color"], "#de2d26");

        let t1566 = techniques
            .iter()
            .find(|t| t["techniqueID"] == "T1566")
            .expect("T1566");
        assert_eq!(t1566["score"], 0);
        assert_eq!(t1566["color"], "#bdbdbd");

        // Stable sort: BTreeMap techniqueID order
        assert!(ids.windows(2).all(|w| w[0] <= w[1]), "techniques sorted");
    }

    #[test]
    fn partial_when_incomplete_links() {
        let partial_links = CapabilityEvidenceLinks {
            source_ids: vec!["src-1".into()],
            input_ids: vec!["in-1".into()],
            execution_record_id: None,
            output_ids: vec![],
            provenance_claim_id: None,
            corroboration_ids: vec![],
            test_ids: vec![],
            benchmark_ids: vec![],
            regression_lock_ids: vec![],
            passed_test_ids: vec![],
            failed_test_ids: vec![],
            corroboration_ok: false,
            regression_ok: true,
            freshness_ok: true,
            reproducibility_ok: true,
            evidence_level: EvidenceLevel::Assertion,
        };
        assert!(!partial_links.mandatory_complete());
        assert_eq!(
            derive_status(ClaimScope::InScope, &partial_links),
            CapabilityStatus::Partial
        );

        let mut ledger = CapabilityLedger::seed_v0();
        ledger
            .set_links("T1016.002", partial_links)
            .expect("T1016.002 present");
        assert_eq!(
            ledger.status_of("T1016.002"),
            Some(CapabilityStatus::Partial)
        );
        assert_eq!(ledger.verified_count(), 0);

        let layer = ledger.navigator_layer("partial", "enterprise-attack", "17.1");
        let tech = layer["techniques"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["techniqueID"] == "T1016.002")
            .expect("T1016.002");
        assert_eq!(tech["score"], 50);
        assert_eq!(tech["color"], "#fec44f");
    }

    /// Cited `test_ids` must name a real `#[test] fn` in the tree, so a
    /// renamed or deleted test cannot silently keep a claim Verified.
    /// (`passed_test_ids` are declared, not executed; a cited test that
    /// fails is caught by `cargo test` itself.)
    #[test]
    fn cited_test_ids_resolve_to_real_test_fns() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let fixtures = [
            ("T1614", geoint_t1614_evidence_links_v1()),
            ("T1589", identity_t1589_evidence_links_v1()),
        ];
        for (tid, links) in fixtures {
            assert!(!links.test_ids.is_empty(), "{tid} cites no tests");
            for test_id in &links.test_ids {
                let parts: Vec<&str> = test_id.split("::").collect();
                assert!(
                    parts.len() >= 3 && parts[parts.len() - 2] == "tests",
                    "{tid}: {test_id} is not a module::tests::fn path"
                );
                let fn_name = parts[parts.len() - 1];
                let module = parts[..parts.len() - 2].join("/");
                let candidates = [
                    root.join(&module).join("tests.rs"),
                    root.join(format!("{module}.rs")),
                    root.join(&module).join("mod.rs"),
                ];
                let needle = format!("fn {fn_name}()");
                let found = candidates.iter().any(|path| {
                    std::fs::read_to_string(path).is_ok_and(|src| {
                        let lines: Vec<&str> = src.lines().collect();
                        lines
                            .windows(2)
                            .any(|w| w[0].trim() == "#[test]" && w[1].contains(&needle))
                    })
                });
                assert!(
                    found,
                    "{tid}: cited test {test_id} not found as a #[test] fn"
                );
            }
        }
    }

    #[test]
    fn verified_requires_regression_lock_id() {
        let mut links = complete_links();
        assert_eq!(
            derive_status(ClaimScope::InScope, &links),
            CapabilityStatus::Verified
        );
        // `regression_ok = true` with no lock artifact is not a regression link.
        links.regression_lock_ids.clear();
        assert!(!links.mandatory_complete());
        assert_ne!(
            derive_status(ClaimScope::InScope, &links),
            CapabilityStatus::Verified
        );
        assert_eq!(
            derive_status(ClaimScope::InScope, &links),
            CapabilityStatus::Partial
        );
    }

    #[test]
    fn verified_requires_independent_corroboration_level() {
        let mut links = complete_links();
        links.evidence_level = EvidenceLevel::Primary; // below floor
        assert!(!links.mandatory_complete());
        assert_ne!(
            derive_status(ClaimScope::InScope, &links),
            CapabilityStatus::Verified
        );

        links.evidence_level = EvidenceLevel::IndependentCorroboration;
        assert!(links.mandatory_complete());
        assert_eq!(
            derive_status(ClaimScope::InScope, &links),
            CapabilityStatus::Verified
        );

        links.evidence_level = EvidenceLevel::EndToEndDemonstration;
        assert_eq!(
            derive_status(ClaimScope::InScope, &links),
            CapabilityStatus::Verified
        );
    }

    #[test]
    fn catalog_mapping_alone_never_verifies() {
        // Seed rows exist because technique IDs are in the ATT&CK catalogue /
        // module maps — that must not produce Verified.
        let ledger = CapabilityLedger::seed_v0();
        assert_eq!(ledger.verified_count(), 0);
        for (_tid, row) in ledger.iter() {
            assert_ne!(
                derive_status(row.scope, &row.links),
                CapabilityStatus::Verified
            );
            assert_eq!(row.links.evidence_level, EvidenceLevel::Assertion);
        }
    }

    /// Smoke: coverage Navigator path still resolves (Coverage ≠ Verified).
    #[test]
    fn coverage_navigator_path_untouched() {
        use crate::core::attack::{ATTACK_VERSION, coverage, navigator_layer};
        use std::collections::BTreeMap;

        // Empty exercised map → honest zero coverage; proves attack::navigator_layer
        // remains a separate API from CapabilityLedger::navigator_layer.
        let cov = coverage(&BTreeMap::new());
        let layer = navigator_layer(&cov, "capability-smoke");
        assert!(
            layer["name"]
                .as_str()
                .unwrap_or("")
                .contains("Reconnaissance coverage"),
            "attack navigator remains coverage heatmap label"
        );
        assert!(
            layer["description"]
                .as_str()
                .unwrap_or("")
                .contains("coverage"),
            "attack navigator remains coverage heatmap"
        );
        let _ = ATTACK_VERSION;

        // Explicit: seed ledger verified_count stays 0 even though attack catalogue
        // and coverage APIs exist — mapping alone ≠ Verified.
        assert_eq!(CapabilityLedger::seed_v0().verified_count(), 0);
    }

    #[test]
    fn geoint_evidence_links_v1_are_mandatory_complete() {
        let links = geoint_t1614_evidence_links_v1();
        assert!(links.mandatory_complete());
        assert_eq!(
            links.evidence_level,
            EvidenceLevel::IndependentCorroboration
        );
        assert!(links.corroboration_ids.len() >= 2);
        assert!(
            links
                .test_ids
                .iter()
                .all(|t| links.passed_test_ids.contains(t))
        );
        assert!(links.failed_test_ids.is_empty());
        // Cited tests are real #[test] path strings (module::tests::fn_name).
        assert!(links.test_ids.iter().any(|t| t.contains("parse_coords")));
        assert!(links.test_ids.iter().any(|t| t.contains("haversine")));
    }

    #[test]
    fn apply_identity_geoint_evidence_v1_derives_verified() {
        let mut ledger = CapabilityLedger::seed_v0();
        assert_eq!(ledger.verified_count(), 0);
        apply_identity_geoint_evidence_v1(&mut ledger).expect("T1614 present");

        assert_eq!(ledger.status_of("T1614"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 1);

        // Other InScope seeds remain Unverified; N/A untouched.
        for tid in ["T1590", "T1596.003", "T1040", "T1016.002", "T1589"] {
            assert_eq!(
                ledger.status_of(tid),
                Some(CapabilityStatus::Unverified),
                "{tid} must stay Unverified"
            );
        }
        assert_eq!(
            ledger.status_of("T1566"),
            Some(CapabilityStatus::NotApplicable)
        );

        let layer = ledger.navigator_layer("geoint-v1", "enterprise-attack", "17.1");
        let tech = layer["techniques"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["techniqueID"] == "T1614")
            .expect("T1614 in layer");
        assert_eq!(tech["score"], 100);
        assert_eq!(tech["color"], "#31a354");
        assert!(
            tech["comment"]
                .as_str()
                .unwrap_or("")
                .contains("status=Verified"),
            "navigator comment must reflect derived Verified"
        );
    }

    #[test]
    fn apply_geoint_invalidate_still_downgrades() {
        let mut ledger = CapabilityLedger::seed_v0();
        apply_identity_geoint_evidence_v1(&mut ledger).expect("apply");
        assert_eq!(ledger.status_of("T1614"), Some(CapabilityStatus::Verified));

        let tid = "util::geo::tests::haversine_km_matches_known_distances";
        ledger.invalidate_test("T1614", tid).expect("invalidate");
        let after = ledger.status_of("T1614");
        assert_ne!(after, Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 0);

        let layer = ledger.navigator_layer("geoint-downgrade", "enterprise-attack", "17.1");
        let tech = layer["techniques"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["techniqueID"] == "T1614")
            .expect("T1614");
        assert_ne!(tech["score"], 100);
        assert_ne!(tech["color"], "#31a354");
    }

    #[test]
    fn identity_evidence_links_v1_are_mandatory_complete() {
        let links = identity_t1589_evidence_links_v1();
        assert!(links.mandatory_complete());
        assert_eq!(
            links.evidence_level,
            EvidenceLevel::IndependentCorroboration
        );
        assert!(links.corroboration_ids.len() >= 2);
        assert!(
            links
                .test_ids
                .iter()
                .all(|t| links.passed_test_ids.contains(t))
        );
        assert!(links.failed_test_ids.is_empty());
        assert!(
            links
                .test_ids
                .iter()
                .any(|t| t.contains("gmail") || t.contains("googlemail"))
        );
        assert!(
            links
                .test_ids
                .iter()
                .any(|t| t.contains("hyphen") || t.contains("edge_punctuation"))
        );
    }

    #[test]
    fn apply_identity_evidence_v1_derives_verified() {
        let mut ledger = CapabilityLedger::seed_v0();
        assert_eq!(ledger.verified_count(), 0);
        apply_identity_evidence_v1(&mut ledger).expect("T1589 present");

        assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 1);

        // GEOINT and other InScope seeds remain Unverified until their own apply.
        for tid in ["T1614", "T1590", "T1596.003", "T1040", "T1016.002"] {
            assert_eq!(
                ledger.status_of(tid),
                Some(CapabilityStatus::Unverified),
                "{tid} must stay Unverified"
            );
        }
        assert_eq!(
            ledger.status_of("T1566"),
            Some(CapabilityStatus::NotApplicable)
        );

        let layer = ledger.navigator_layer("identity-v1", "enterprise-attack", "17.1");
        let tech = layer["techniques"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["techniqueID"] == "T1589")
            .expect("T1589 in layer");
        assert_eq!(tech["score"], 100);
        assert_eq!(tech["color"], "#31a354");
        assert!(
            tech["comment"]
                .as_str()
                .unwrap_or("")
                .contains("status=Verified"),
            "navigator comment must reflect derived Verified"
        );
    }

    #[test]
    fn apply_identity_and_geoint_verified_count_is_two() {
        let mut ledger = CapabilityLedger::seed_v0();
        apply_identity_geoint_evidence_v1(&mut ledger).expect("geoint");
        apply_identity_evidence_v1(&mut ledger).expect("identity");
        assert_eq!(ledger.status_of("T1614"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 2);
    }

    #[test]
    fn apply_identity_invalidate_still_downgrades() {
        let mut ledger = CapabilityLedger::seed_v0();
        apply_identity_evidence_v1(&mut ledger).expect("apply");
        assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));

        let tid = "util::canonical::tests::gmail_dots_and_plus_tag_both_fold";
        ledger.invalidate_test("T1589", tid).expect("invalidate");
        let after = ledger.status_of("T1589");
        assert_ne!(after, Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 0);

        let layer = ledger.navigator_layer("identity-downgrade", "enterprise-attack", "17.1");
        let tech = layer["techniques"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["techniqueID"] == "T1589")
            .expect("T1589");
        assert_ne!(tech["score"], 100);
        assert_ne!(tech["color"], "#31a354");
    }

    #[test]
    fn evidence_content_hash_is_stable_and_64_hex() {
        let a = complete_links();
        let b = complete_links();
        let ha = evidence_links_content_hash(&a);
        let hb = b.content_hash();
        assert_eq!(ha, hb);
        assert_eq!(ha.len(), 64);
        assert!(ha.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ha.chars().all(|c| !c.is_ascii_uppercase()));

        let empty = CapabilityEvidenceLinks::empty();
        let he = empty.content_hash();
        assert_eq!(he.len(), 64);
        assert_ne!(he, ha, "empty links must not collide with complete fixture");

        let canonical = evidence_links_canonical_json(&a);
        assert!(canonical.contains(EVIDENCE_CONTENT_HASH_SCHEMA));
        let expected_prefix = format!("{{\"schema\":\"{EVIDENCE_CONTENT_HASH_SCHEMA}\"");
        assert!(
            canonical.starts_with(&expected_prefix),
            "canonical JSON must start with schema key; got {canonical}"
        );
    }

    #[test]
    fn evidence_hash_tamper_falsify_changes_digest() {
        let base = complete_links();
        let h0 = base.content_hash();

        let mut mutated = base.clone();
        mutated.source_ids.push("src-tamper".into());
        assert_ne!(mutated.content_hash(), h0);

        let mut mutated = base.clone();
        mutated.provenance_claim_id = Some("claim-tampered".into());
        assert_ne!(mutated.content_hash(), h0);

        let mut mutated = base.clone();
        mutated.corroboration_ok = false;
        assert_ne!(mutated.content_hash(), h0);

        let mut mutated = base.clone();
        mutated.evidence_level = EvidenceLevel::Primary;
        assert_ne!(mutated.content_hash(), h0);

        // Vec order is part of identity: reverse source_ids → new digest.
        let mut mutated = base.clone();
        mutated.source_ids = vec!["z-last".into(), "a-first".into()];
        let mut swapped = base.clone();
        swapped.source_ids = vec!["a-first".into(), "z-last".into()];
        assert_ne!(mutated.content_hash(), swapped.content_hash());
    }

    #[test]
    fn evidence_provenance_binding_joins_claim_and_hash() {
        let links = complete_links();
        let binding = evidence_links_provenance_binding(&links);
        let hash = links.content_hash();
        assert_eq!(binding, format!("claim-1|sha256:{hash}"));
        assert_eq!(links.provenance_binding(), binding);

        let empty = CapabilityEvidenceLinks::empty();
        let eb = empty.provenance_binding();
        assert!(eb.starts_with("sha256:"));
        assert_eq!(eb, format!("sha256:{}", empty.content_hash()));
    }

    #[test]
    fn hashed_evidence_apply_helpers_still_derive_verified() {
        // Seed stays Assertion-tier / verified_count 0 until apply.
        let seed = CapabilityLedger::seed_v0();
        assert_eq!(seed.verified_count(), 0);
        let seed_hash_t1614 = seed.evidence_content_hash("T1614").expect("T1614");
        let seed_hash_t1589 = seed.evidence_content_hash("T1589").expect("T1589");
        // Empty links share the same content address across seed rows.
        assert_eq!(seed_hash_t1614, seed_hash_t1589);

        let mut ledger = CapabilityLedger::seed_v0();
        apply_identity_geoint_evidence_v1(&mut ledger).expect("geoint");
        apply_identity_evidence_v1(&mut ledger).expect("identity");
        assert_eq!(ledger.verified_count(), 2);
        assert_eq!(ledger.status_of("T1614"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));

        let h_geo = ledger.evidence_content_hash("T1614").expect("geo hash");
        let h_id = ledger.evidence_content_hash("T1589").expect("id hash");
        assert_eq!(h_geo.len(), 64);
        assert_eq!(h_id.len(), 64);
        assert_ne!(
            h_geo, h_id,
            "distinct evidence chains must not share digest"
        );
        assert_ne!(h_geo, seed_hash_t1614);
        assert_ne!(h_id, seed_hash_t1589);

        let b_geo = ledger
            .evidence_provenance_binding("T1614")
            .expect("geo bind");
        let b_id = ledger
            .evidence_provenance_binding("T1589")
            .expect("id bind");
        assert!(b_geo.starts_with("prov-geoint-offline-fixture-v1|sha256:"));
        assert!(b_id.starts_with("prov-identity-canonicalize-fixture-v1|sha256:"));
        assert!(b_geo.ends_with(&h_geo));
        assert!(b_id.ends_with(&h_id));

        // Hash is not an input to derive_status: invalidate still downgrades,
        // and the digest changes when links mutate.
        let before = h_geo.clone();
        ledger
            .invalidate_test(
                "T1614",
                "util::geo::tests::haversine_km_matches_known_distances",
            )
            .expect("invalidate");
        assert_ne!(ledger.status_of("T1614"), Some(CapabilityStatus::Verified));
        let after = ledger.evidence_content_hash("T1614").expect("after");
        assert_ne!(after, before, "tamper/invalidate must change content hash");
        // Identity claim remains Verified — hashing did not weaken floor.
        assert_eq!(ledger.status_of("T1589"), Some(CapabilityStatus::Verified));
        assert_eq!(ledger.verified_count(), 1);
    }

    #[test]
    fn content_hash_is_not_a_verified_shortcut() {
        // Possessing a hash of empty/partial links must never yield Verified.
        let empty = CapabilityEvidenceLinks::empty();
        let _ = empty.content_hash();
        assert_eq!(
            derive_status(ClaimScope::InScope, &empty),
            CapabilityStatus::Unverified
        );

        // regression_ok must be true so hard-fail path does not force Unverified;
        // sparse links still cannot reach Verified via hashing alone.
        let partial = CapabilityEvidenceLinks {
            source_ids: vec!["s".into()],
            provenance_claim_id: Some("p".into()),
            regression_ok: true,
            ..CapabilityEvidenceLinks::empty()
        };
        let _ = partial.content_hash();
        assert_ne!(
            derive_status(ClaimScope::InScope, &partial),
            CapabilityStatus::Verified
        );
        assert_eq!(
            derive_status(ClaimScope::InScope, &partial),
            CapabilityStatus::Partial
        );
    }
}
