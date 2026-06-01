//! `core::entity` — HSE entity model.
//!
//! # Architecture invariants
//! - SHA-256 deterministic UIDs
//! - GREATEST-semantics merge (confidence, corroboration only ever increase)
//! - `C_eff` rises with the count of DISTINCT INDEPENDENT corroborating
//!   sources — not the raw `corroboration` field, and not the engine's own
//!   internal enrichment passes (see [`Entity::source_count`] / [`Evidence::internal`])
//! - `Classify()` is derived-only from `C_eff`
//! - No unsafe, no std::sync::Mutex (use tokio::sync)
//! - Zero CGO / native deps

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Corroboration boost coefficient (architecture invariant).
pub const CORROBORATION_COEFF: f64 = 0.15;

/// Residual-doubt decay per *additional* independent source in the
/// agreement model of [`Entity::c_effective`]. Each distinct corroborating
/// source shrinks the remaining doubt `(1 − confidence)` by this factor, so
/// independent agreement drives confidence toward certainty: at `0.65`, a
/// moderate finding (C=0.6) reaches ~0.74 at 2 sources and ~0.83 (Verified) at
/// 3 — which the purely-multiplicative model badly under-credits (0.66 / 0.73).
pub const CORROBORATION_DOUBT_DECAY: f64 = 0.65;

/// Confidence decay constant per hour (γ = 0.85).
pub const GAMMA_PER_HOUR: f64 = 0.85;

// ─── EntityKind ──────────────────────────────────────────────────────────────

/// All value types an entity can represent.
///
/// People-centric kinds (Person, Email, Phone, Username) are weighted highest
/// in module priority ordering. Infrastructure kinds are enrichment targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    // People-centric (priority identity)
    Person,
    Email,
    Phone,
    Username,

    // Document / credential
    Credential,
    ApiKey,
    Password, // never stored in evidence output

    // Network / infrastructure
    IpAddress,
    Domain,
    Url,
    Asn,

    // Physical / GEOINT
    Address,
    Coordinates,

    // Organisation
    Organisation,
    AbnAcn,

    // Device
    MacAddress,
    DeviceId,

    // Catch-all
    Other(String),
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Person => f.write_str("person"),
            Self::Email => f.write_str("email"),
            Self::Phone => f.write_str("phone"),
            Self::Username => f.write_str("username"),
            Self::Credential => f.write_str("credential"),
            Self::ApiKey => f.write_str("api_key"),
            Self::Password => f.write_str("password"),
            Self::IpAddress => f.write_str("ip_address"),
            Self::Domain => f.write_str("domain"),
            Self::Url => f.write_str("url"),
            Self::Asn => f.write_str("asn"),
            Self::Address => f.write_str("address"),
            Self::Coordinates => f.write_str("coordinates"),
            Self::Organisation => f.write_str("organisation"),
            Self::AbnAcn => f.write_str("abn_acn"),
            Self::MacAddress => f.write_str("mac_address"),
            Self::DeviceId => f.write_str("device_id"),
            Self::Other(s) => write!(f, "other:{s}"),
        }
    }
}

// ─── Classification ───────────────────────────────────────────────────────────

/// Derived-only classification tier from `C_eff`.
///
/// Never set directly — always call `Entity::classify()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    /// `C_eff < 0.40`
    Candidate,
    /// `0.40 ≤ C_eff < 0.75`
    Probable,
    /// `C_eff ≥ 0.75`
    Verified,
}

impl Classification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::Probable => "PROBABLE",
            Self::Verified => "VERIFIED",
        }
    }

    /// Stable, dense tier rank (0 = Candidate, 1 = Probable, 2 = Verified).
    ///
    /// This is the finite tier ladder intended to back a bounded best-first
    /// expansion: with a `(target, tier)` visited-set an entity is expanded at
    /// most once per rank, and because there are exactly
    /// [`Classification::COUNT`] ranks, total expansions are bounded by
    /// `entities × COUNT`.
    ///
    /// NOTE (current state): the engine's expansion visited-set is still keyed
    /// on `(TargetKind, normalised value)` and expands each target at most
    /// once overall — it does not yet key on tier or re-queue on tier
    /// graduation. `rank()`/[`COUNT`] are the ladder that the planned
    /// tier-aware frontier will use; until that lands, this method is consumed
    /// by tests and ranking, not by the live visited-set.
    #[inline]
    pub fn rank(self) -> u8 {
        match self {
            Self::Candidate => 0,
            Self::Probable => 1,
            Self::Verified => 2,
        }
    }

    /// Number of distinct confidence tiers. Fixed and finite — the
    /// multiplier in the halting bound `expansions ≤ entities × COUNT`.
    pub const COUNT: u8 = 3;
}

impl fmt::Display for Classification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── EntityView (operator-facing serialization) ──────────────────────────────

/// Operator-facing serialization of an entity.
///
/// `Entity`'s derived `Serialize` emits only its *stored* fields, so the two
/// DERIVED intelligence values the engine computes — `c_eff`
/// ([`Entity::c_effective`], the cross-source effective confidence) and
/// `classification` ([`Entity::classify`], the Verified / Probable / Candidate
/// tier) — never reach a JSON consumer. The CSV export
/// (`scan_handlers::entities_to_csv`) and the Web UI already surface them; this
/// wrapper is how every JSON export/report does too, so no downstream consumer
/// has to re-implement the (two-model) `c_eff` formula and risk drifting from
/// the engine. It borrows the entity, `#[serde(flatten)]`s its stored fields,
/// and appends the two derived fields. Serialize-only by design.
#[derive(Serialize)]
pub struct EntityView<'a> {
    #[serde(flatten)]
    entity: &'a Entity,
    /// Effective cross-source confidence — [`Entity::c_effective`].
    c_eff: f64,
    /// Verified / Probable / Candidate tier — [`Entity::classify`].
    classification: String,
}

impl<'a> EntityView<'a> {
    /// Wrap one entity, computing the derived fields once.
    pub fn new(entity: &'a Entity) -> Self {
        Self {
            c_eff: entity.c_effective(),
            classification: entity.classify().to_string(),
            entity,
        }
    }

    /// Wrap a slice of entities for JSON output.
    pub fn many(entities: &'a [Entity]) -> Vec<EntityView<'a>> {
        entities.iter().map(EntityView::new).collect()
    }
}

#[cfg(test)]
mod entity_view_tests {
    use super::*;

    #[test]
    fn view_adds_c_eff_and_classification_across_all_tiers() {
        // Exhaustive over the full (finite) domain of `classify()` — all three
        // tiers. With a single source c_eff == confidence, so `conf` selects
        // the tier directly. Each view must serialize c_eff == c_effective()
        // and classification == classify().to_string(), and must NOT drop the
        // flattened stored fields.
        for (conf, expect_tier) in [(0.20, "CANDIDATE"), (0.50, "PROBABLE"), (0.90, "VERIFIED")] {
            let e = Entity::new(EntityKind::Email, "a@b.com", conf, "scan");
            assert_eq!(e.classify().to_string(), expect_tier, "fixture tier");
            let v = serde_json::to_value(EntityView::new(&e)).unwrap();
            assert_eq!(v["classification"], expect_tier);
            assert!((v["c_eff"].as_f64().unwrap() - e.c_effective()).abs() < 1e-12);
            // Flattened stored fields survive and are inlined (not nested).
            assert_eq!(v["uid"], e.uid);
            assert_eq!(v["value"], "a@b.com");
            assert_eq!(v["kind"], "email");
            assert!(v["confidence"].as_f64().is_some());
            assert!(v.get("entity").is_none(), "flatten must inline, not nest");
        }
    }

    #[test]
    fn many_wraps_every_entity_with_derived_fields() {
        let es = vec![
            Entity::new(EntityKind::Email, "a@b.com", 0.9, "s"),
            Entity::new(EntityKind::Domain, "b.com", 0.3, "s"),
        ];
        let arr = serde_json::to_value(EntityView::many(&es)).unwrap();
        let arr = arr.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(
            arr.iter()
                .all(|v| v.get("c_eff").is_some() && v.get("classification").is_some()),
            "every wrapped entity must carry both derived fields"
        );
    }
}

// ─── Evidence ────────────────────────────────────────────────────────────────

/// A single piece of evidence attached to an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Module that produced this evidence.
    pub source: String,
    /// Human-readable summary. Passwords MUST NOT appear here.
    pub summary: String,
    /// Raw key/value pairs from the module (no passwords).
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    /// Unix timestamp (seconds) when evidence was recorded.
    pub recorded_at: u64,
    /// `true` when this evidence comes from one of the engine's OWN internal
    /// enrichment/derivation passes (e.g. `geo_normalize` adding a geohash +
    /// admin hierarchy to a Coordinates/Address) rather than an independent
    /// external observation. Internal evidence annotates an entity *already*
    /// discovered by some module, so it must NOT count toward the
    /// distinct-source cross-correlation signal (see [`Entity::source_count`]) —
    /// otherwise a single-source finding the engine merely geocodes looks
    /// "doubly sourced" and is over-promoted to *Verified*.
    ///
    /// Provenance is declared **at construction** (`Evidence::new` → external;
    /// `.as_internal()` → internal), so the corroboration filter is exact by
    /// origin rather than a fragile source-name denylist that silently rots
    /// when a new internal pass is added. Defaulted so older serialized
    /// evidence (and the ~365 external `Evidence::new` call sites) read as
    /// external automatically.
    #[serde(default)]
    pub internal: bool,
}

impl Evidence {
    /// Evidence from an independent external observation (a module). The
    /// overwhelmingly common case — counts toward cross-correlation.
    pub fn new(source: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            summary: summary.into(),
            attributes: HashMap::new(),
            recorded_at: unix_now(),
            internal: false,
        }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Mark this evidence as the engine's own internal enrichment/derivation
    /// (see [`Evidence::internal`]) so it is excluded from the corroboration
    /// count. Chainable with [`with_attr`](Self::with_attr) in any order.
    #[must_use]
    pub fn as_internal(mut self) -> Self {
        self.internal = true;
        self
    }
}

// ─── Entity ───────────────────────────────────────────────────────────────────

/// Core HSE entity.
///
/// # UID derivation
/// `uid = hex(SHA-256(kind_str + ":" + value_normalised))`
///
/// # Confidence formula
/// `C_eff = clamp(confidence × (1 + 0.15 × ln(corroboration)), 0.0, 1.0)`
///
/// # GREATEST-semantics merge
/// `confidence` and `corroboration` only ever increase during merge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Deterministic SHA-256 UID.
    pub uid: String,
    /// Value kind.
    pub kind: EntityKind,
    /// Normalised canonical value.
    pub value: String,
    /// Raw / display value (may differ from normalised).
    pub raw_value: String,
    /// Base confidence ∈ [0, 1].
    pub confidence: f64,
    /// Number of independent corroborating sources (≥ 1).
    pub corroboration: u32,
    /// Decay timestamp (Unix seconds). Used to compute time-decay.
    pub observed_at: u64,
    /// Evidence chain (append-only via `add_evidence`).
    pub evidence: Vec<Evidence>,
    /// Arbitrary tag bag (e.g. "au:breach", "geoint").
    #[serde(default)]
    pub tags: Vec<String>,
    /// Scan ID this entity was first seen in.
    pub scan_id: String,
}

impl Entity {
    // ── Construction ────────────────────────────────────────────────────────

    /// Create a new entity. `confidence` is clamped to [0, 1].
    pub fn new(
        kind: EntityKind,
        value: impl Into<String>,
        confidence: f64,
        scan_id: impl Into<String>,
    ) -> Self {
        let value = value.into();
        let normalised = normalise(&kind, &value);
        let uid = derive_uid(&kind, &normalised);
        Self {
            uid,
            kind,
            value: normalised,
            raw_value: value,
            confidence: confidence.clamp(0.0, 1.0),
            corroboration: 1,
            observed_at: unix_now(),
            evidence: Vec::new(),
            tags: Vec::new(),
            scan_id: scan_id.into(),
        }
    }

    // ── Derived metrics ──────────────────────────────────────────────────────

    /// Number of DISTINCT corroborating sources backing this entity — the
    /// true cross-correlation signal that drives the C_eff boost.
    ///
    /// This is `evidence_sources().len()` (count of distinct `evidence.source`
    /// strings, since every module emits one stable source name), floored at 1.
    /// When no evidence is attached (synthetic/test entities, or an entity
    /// constructed before its evidence) it falls back to the stored
    /// `corroboration` field so an explicitly-set strength value is still
    /// honoured.
    ///
    /// Why not the `corroboration` field directly: that field is the summed
    /// *observation magnitude* (e.g. hibp seeds it with verified-breach count,
    /// search_engines with engine-agreement count, and `merge()` adds them).
    /// Summed within-module counts are NOT a count of independent sources, so
    /// using them to boost C_eff over-credited single-source findings (a 5-breach
    /// hibp hit looked like "5 independent sources"). The distinct-source count
    /// is the honest cross-correlation measure — and is already the signal used
    /// by the expansion gate, the diagnostics diversity floor, and 6 correlator
    /// rules. The `corroboration` field is retained as the observation-magnitude
    /// signal for ranking/diagnostics; it no longer drives C_eff.
    #[inline]
    pub fn source_count(&self) -> u32 {
        let distinct = self.corroborating_sources().len() as u32;
        if distinct > 0 {
            // Independent sources is the authoritative cross-correlation count.
            // Neither the summed `corroboration` magnitude (the original
            // over-count bug) NOR the engine's own internal enrichment passes
            // (the false-Verified bug — see [`Evidence::internal`]) are
            // allowed to inflate it.
            distinct
        } else if self.evidence.is_empty() {
            // No evidence at all (synthetic/test entity, or constructed
            // pre-evidence): fall back to the explicitly-set field so a
            // deliberate strength value is still honoured.
            self.corroboration.max(1)
        } else {
            // Evidence exists but ALL of it is internal enrichment — that is a
            // single (effective) observation, never multi-source corroboration.
            // Floor at 1 rather than the (possibly inflated) `corroboration`.
            1
        }
    }

    /// Cross-source effective confidence — the stronger of two models over the
    /// number of DISTINCT corroborating sources `n` (see [`source_count`],
    /// floored at 1):
    ///
    /// * **Multiplicative** (legacy): `confidence × (1 + 0.15·ln n)` — a gentle,
    ///   sharply-diminishing boost.
    /// * **Independent-agreement** (noisy-OR): `1 − (1 − confidence)·γ^(n−1)`
    ///   with `γ = `[`CORROBORATION_DOUBT_DECAY`] — each *additional* independent
    ///   source shrinks the residual doubt, so N sources agreeing on a finding
    ///   drive confidence toward certainty.
    ///
    /// `C_eff = clamp(max(multiplicative, agreement), 0, 1)`.
    ///
    /// At `n = 1` both models equal `confidence`, so a single-source entity is
    /// unchanged. The agreement term is what gives genuine cross-correlation its
    /// due: the multiplicative model alone caps four independent confirmations of
    /// a moderate (C=0.6) finding at 0.73 ("Probable"); the agreement term lifts
    /// it to ~0.89 ("Verified"), which is what four independent sources warrant.
    /// `max` keeps the result monotonic and never below the legacy value, so the
    /// change only ever *adds* confidence for genuinely multi-sourced entities.
    #[inline]
    pub fn c_effective(&self) -> f64 {
        let n = f64::from(self.source_count());
        let multiplicative = self.confidence * CORROBORATION_COEFF.mul_add(n.ln(), 1.0);
        let residual_doubt = (1.0 - self.confidence) * CORROBORATION_DOUBT_DECAY.powf(n - 1.0);
        let agreement = 1.0 - residual_doubt;
        multiplicative.max(agreement).clamp(0.0, 1.0)
    }

    /// Derived classification tier from `c_effective()`.
    ///
    /// Never stored — always recomputed.
    #[inline]
    pub fn classify(&self) -> Classification {
        match self.c_effective() {
            c if c >= 0.75 => Classification::Verified,
            c if c >= 0.40 => Classification::Probable,
            _ => Classification::Candidate,
        }
    }

    /// The entity's current confidence tier — alias for [`classify`] that
    /// names the role the value is intended to play in a tier-aware bounded
    /// best-first expansion (key the visited-set on `(target, tier_rank)` and
    /// re-queue at most once per tier when a merge lifts the entity).
    ///
    /// NOTE (current state): the live engine does not yet key its visited-set
    /// on tier or re-queue on graduation — see [`Classification::rank`]. This
    /// alias documents intent and is used by ranking/tests today.
    #[inline]
    pub fn tier(&self) -> Classification {
        self.classify()
    }

    /// Apply gamma-decay over elapsed time since `observed_at`.
    ///
    /// Returns the decayed confidence without mutating. Use `apply_decay()`
    /// to mutate in place.
    pub fn decayed_confidence(&self) -> f64 {
        let now = unix_now();
        let hours_elapsed = (now.saturating_sub(self.observed_at)) as f64 / 3600.0;
        (self.confidence * GAMMA_PER_HOUR.powf(hours_elapsed)).clamp(0.0, 1.0)
    }

    /// Mutate confidence in place using gamma decay.
    pub fn apply_decay(&mut self) {
        self.confidence = self.decayed_confidence();
    }

    // ── Evidence ────────────────────────────────────────────────────────────

    /// Append evidence. Passwords must be stripped before calling.
    pub fn add_evidence(&mut self, ev: Evidence) {
        self.evidence.push(ev);
    }

    // ── Tags ────────────────────────────────────────────────────────────────

    pub fn tag(&mut self, t: impl Into<String>) {
        let t = t.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
    }

    pub fn has_tag(&self, t: &str) -> bool {
        self.tags.iter().any(|x| x == t)
    }

    // ── Evidence helpers ────────────────────────────────────────────────────

    pub fn evidence_sources(&self) -> std::collections::HashSet<&str> {
        self.evidence.iter().map(|ev| ev.source.as_str()).collect()
    }

    /// Distinct **independent** evidence sources: the source names of every
    /// non-internal evidence entry (see [`Evidence::internal`]). This is the
    /// honest cross-correlation count that drives [`source_count`](Self::source_count)
    /// (and hence [`c_effective`](Self::c_effective) /
    /// [`classify`](Self::classify)); [`evidence_sources`](Self::evidence_sources)
    /// remains the raw set for callers that want every source regardless of
    /// provenance.
    pub fn corroborating_sources(&self) -> std::collections::HashSet<&str> {
        self.evidence
            .iter()
            .filter(|ev| !ev.internal)
            .map(|ev| ev.source.as_str())
            .collect()
    }

    pub fn has_evidence_from(&self, source: &str) -> bool {
        self.evidence.iter().any(|ev| ev.source == source)
    }

    // ── GREATEST-semantics merge ─────────────────────────────────────────────

    /// Merge `other` into `self` using GREATEST-semantics.
    ///
    /// Rules:
    /// - `uid` must match (panics in debug, no-op in release if not)
    /// - `confidence`  = max(self, other)      — never decreases
    /// - `corroboration` += other.corroboration — only increases
    /// - `observed_at`  = max(self, other)      — most recent wins
    /// - `evidence` appended
    /// - `tags` union (dedup)
    pub fn merge(&mut self, other: Self) {
        debug_assert_eq!(self.uid, other.uid, "merge: UID mismatch");
        if self.uid != other.uid {
            return;
        }
        self.confidence = f64::max(self.confidence, other.confidence).clamp(0.0, 1.0);
        self.corroboration = self
            .corroboration
            .saturating_add(other.corroboration)
            .max(1);
        self.observed_at = u64::max(self.observed_at, other.observed_at);
        // Deduplicate evidence by (source, summary) to prevent accumulation
        // across live mode iterations or re-scans.
        for ev in other.evidence {
            let dominated = self
                .evidence
                .iter()
                .any(|e| e.source == ev.source && e.summary == ev.summary);
            if !dominated {
                self.evidence.push(ev);
            }
        }
        for t in other.tags {
            self.tag(t);
        }
    }
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) C={:.3} C_eff={:.3} corr={} → {}",
            self.kind,
            self.value,
            self.uid.get(..8).unwrap_or(&self.uid),
            self.confidence,
            self.c_effective(),
            self.corroboration,
            self.classify(),
        )
    }
}

// ─── EntityRef ───────────────────────────────────────────────────────────────

/// Lightweight handle referencing an entity by UID and kind.
/// Used in module I/O to avoid cloning full entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRef {
    pub uid: String,
    pub kind: EntityKind,
    pub value: String,
}

impl From<&Entity> for EntityRef {
    fn from(e: &Entity) -> Self {
        Self {
            uid: e.uid.clone(),
            kind: e.kind.clone(),
            value: e.value.clone(),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Derive a deterministic SHA-256 UID from kind + normalised value.
///
/// Format: `hex(SHA-256("<kind_str>:<normalised_value>"))`
pub(crate) fn derive_uid(kind: &EntityKind, normalised_value: &str) -> String {
    use std::io::Write;
    let mut h = Sha256::new();
    let _ = write!(h, "{kind}:");
    h.update(normalised_value.as_bytes());
    hex::encode(h.finalize())
}

/// Normalise a value for a given kind.
///
/// - Email → lowercase, trim
/// - Domain → lowercase, trim, strip trailing dot
/// - Username → lowercase, trim
/// - IpAddress → trim
/// - Phone → strip non-digits (keep leading +)
/// - Everything else → trim
pub(crate) fn normalise(kind: &EntityKind, value: &str) -> String {
    match kind {
        EntityKind::Email | EntityKind::Username => {
            let trimmed = value.trim();
            if trimmed.bytes().all(|b| !b.is_ascii_uppercase()) {
                return trimmed.to_string();
            }
            let mut s = String::with_capacity(trimmed.len());
            for c in trimmed.chars() {
                s.extend(c.to_lowercase());
            }
            s
        }
        EntityKind::Domain => {
            let trimmed = value.trim();
            let mut s = String::with_capacity(trimmed.len());
            for c in trimmed.chars() {
                s.extend(c.to_lowercase());
            }
            let len = s.trim_end_matches('.').len();
            s.truncate(len);
            // Strip www. prefix for deduplication
            if s.starts_with("www.") && s.len() > 4 {
                s = s[4..].to_string();
            }
            s
        }
        EntityKind::Phone => {
            let mut out = String::with_capacity(value.len());
            let mut chars = value.chars().peekable();
            if chars.peek() == Some(&'+') {
                out.push('+');
                chars.next();
            }
            for c in chars {
                if c.is_ascii_digit() {
                    out.push(c);
                }
            }
            out
        }
        EntityKind::IpAddress => {
            let trimmed = value.trim();
            // Parse and re-format to canonical form (handles IPv6 compression, mapped addresses)
            if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V6(v6) => {
                        // Convert IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4
                        if let Some(v4) = v6.to_ipv4_mapped() {
                            return v4.to_string();
                        }
                        ip.to_string()
                    }
                    _ => ip.to_string(),
                }
            } else {
                trimmed.to_string()
            }
        }
        EntityKind::MacAddress => {
            // Normalise to lowercase colon-separated: aa:bb:cc:dd:ee:ff
            let trimmed = value.trim();
            let hex: String = trimmed
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .flat_map(|c| c.to_lowercase())
                .collect();
            if hex.len() == 12 {
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    &hex[0..2],
                    &hex[2..4],
                    &hex[4..6],
                    &hex[6..8],
                    &hex[8..10],
                    &hex[10..12]
                )
            } else {
                trimmed.to_lowercase()
            }
        }
        EntityKind::Coordinates => {
            // Normalise to 6 decimal places: "lat,lon"
            let trimmed = value.trim();
            if let Some((lat_s, lon_s)) = trimmed.split_once(',')
                && let (Ok(lat), Ok(lon)) =
                    (lat_s.trim().parse::<f64>(), lon_s.trim().parse::<f64>())
            {
                return format!("{lat:.6},{lon:.6}");
            }
            trimmed.to_string()
        }
        EntityKind::Url => {
            let trimmed = value.trim();
            let lower = trimmed.to_lowercase();
            let (scheme, rest) = if lower.starts_with("https://") {
                ("https", &trimmed[8..])
            } else if lower.starts_with("http://") {
                ("http", &trimmed[7..])
            } else {
                return trimmed.to_string();
            };
            let no_frag = rest.split('#').next().unwrap_or(rest);
            let (host_and_path, query) = match no_frag.split_once('?') {
                Some((hp, q)) => (hp, Some(q)),
                None => (no_frag, None),
            };
            let (host, path) = host_and_path.split_once('/').unwrap_or((host_and_path, ""));
            let host_lower: String = host.chars().flat_map(char::to_lowercase).collect();
            let path_trimmed = path.trim_end_matches('/');
            let mut out = if path_trimmed.is_empty() {
                format!("{scheme}://{host_lower}")
            } else {
                format!("{scheme}://{host_lower}/{path_trimmed}")
            };
            if let Some(q) = query
                && !q.is_empty()
            {
                out.push('?');
                out.push_str(q);
            }
            out
        }
        _ => value.trim().to_string(),
    }
}

/// Current Unix timestamp in seconds.
#[inline]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a unique scan ID: `hex(SHA-256("<kind>:<value>:<unix_now>"))`.
///
/// NOT deterministic across calls for the same target — the timestamp
/// is mixed in so each invocation produces a fresh id.
pub fn scan_id(kind: &str, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(value.as_bytes());
    h.update(b":");
    h.update(unix_now().to_be_bytes());
    hex::encode(h.finalize())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // helpers
    fn email(v: &str) -> Entity {
        Entity::new(EntityKind::Email, v, 0.6, "scan-test")
    }

    // ── UID determinism ──────────────────────────────────────────────────────

    #[test]
    fn uid_is_deterministic() {
        let a = email("Matt@Example.com");
        let b = email("matt@example.com"); // normalised → same
        assert_eq!(a.uid, b.uid);
    }

    #[test]
    fn uid_differs_across_kinds() {
        let e = Entity::new(EntityKind::Email, "x@y.com", 0.5, "s");
        let d = Entity::new(EntityKind::Domain, "x@y.com", 0.5, "s");
        assert_ne!(e.uid, d.uid);
    }

    // ── C_eff formula ────────────────────────────────────────────────────────

    #[test]
    fn c_eff_single_source() {
        // corroboration=1 → ln(1)=0 → c_eff == confidence
        let e = email("a@b.com");
        assert!((e.c_effective() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn c_eff_boost_with_corroboration() {
        let mut e = email("a@b.com");
        e.corroboration = 4;
        // No evidence attached → source_count() falls back to the field (4).
        // C_eff = max(multiplicative, independent-agreement). At n=4 the
        // agreement term dominates: 1 - 0.4·γ^3 ≈ 0.890 > 0.726 multiplicative.
        let mult = 0.6 * 0.15f64.mul_add(4f64.ln(), 1.0);
        let agreement = 1.0 - 0.4 * CORROBORATION_DOUBT_DECAY.powf(3.0);
        let expected = mult.max(agreement);
        assert!((e.c_effective() - expected).abs() < 1e-9);
        assert!(
            e.c_effective() > 0.85,
            "4 independent sources → near-Verified"
        );
    }

    #[test]
    fn c_eff_boosts_on_distinct_sources_not_summed_corroboration() {
        // THE FIX: an entity backed by 2 DISTINCT sources but with a summed
        // corroboration of 8 (the merge() over-count bug) must boost on 2, not 8.
        let mut e = email("a@b.com");
        e.corroboration = 8; // as if hibp(5) merged with search_engines(3)
        e.add_evidence(Evidence::new("hibp", "found in 5 breaches"));
        e.add_evidence(Evidence::new("search_engines", "5 engines agree"));
        assert_eq!(e.source_count(), 2, "distinct sources, not the summed 8");
        // Boost is driven by the 2 DISTINCT sources, not the inflated count of 8.
        let mult = 0.6 * 0.15f64.mul_add(2f64.ln(), 1.0);
        let agreement = 1.0 - 0.4 * CORROBORATION_DOUBT_DECAY; // n=2 → γ^1
        let expected = mult.max(agreement);
        assert!(
            (e.c_effective() - expected).abs() < 1e-9,
            "C_eff must boost on 2 distinct sources, not the inflated corroboration=8"
        );
        // A summed-corroboration of 8 would (wrongly) push c_eff much higher.
        let if_summed = 1.0 - 0.4 * CORROBORATION_DOUBT_DECAY.powf(7.0);
        assert!(
            e.c_effective() < if_summed,
            "must not credit the inflated 8"
        );
    }

    #[test]
    fn c_eff_independent_agreement_lifts_moderate_findings() {
        // The grunt: independent corroboration of a MODERATE finding drives
        // confidence toward certainty, where the multiplicative model alone
        // would leave it merely "Probable". Monotonic non-decreasing in n.
        let mut e = email("a@b.com");
        e.confidence = 0.60;
        let mut last = e.c_effective(); // n=1 → 0.60
        assert!((last - 0.60).abs() < 1e-9, "single source unchanged");
        for n in 2..=5u32 {
            e.corroboration = n;
            let c = e.c_effective();
            assert!(
                c >= last,
                "c_eff must be monotonic non-decreasing in sources"
            );
            assert!(c <= 1.0);
            last = c;
        }
        // 3 independent sources earn Verified (≥ 0.75); 5 are near-certain.
        e.corroboration = 3;
        assert!(
            e.c_effective() >= 0.75,
            "3 independent sources → Verified tier"
        );
        e.corroboration = 5;
        assert!(
            e.c_effective() >= 0.90,
            "5 independent sources → near-certain"
        );
    }

    #[test]
    fn source_count_collapses_same_module_duplicate_evidence() {
        // Multiple evidence rows from ONE module (e.g. oathnet_pro returning
        // many breach rows) are a single independent source.
        let mut e = email("a@b.com");
        e.corroboration = 172; // oathnet within-module row count
        for i in 0..5 {
            e.add_evidence(Evidence::new("oathnet_pro", format!("breach row {i}")));
        }
        assert_eq!(
            e.source_count(),
            1,
            "one module = one source regardless of rows"
        );
        // ln(1)=0 → no boost; a single source must not be inflated.
        assert!((e.c_effective() - 0.6).abs() < 1e-9);
    }

    #[test]
    fn source_count_no_evidence_uses_field() {
        // Synthetic entity with no evidence honours the explicit field.
        let mut e = email("a@b.com");
        e.corroboration = 3;
        assert_eq!(e.source_count(), 3);
    }

    #[test]
    fn internal_enrichment_is_not_independent_corroboration() {
        // Reproduces the live false-Verified fault: a single-source (oathnet_pro)
        // breach address the engine then geocodes (geo_normalize) must NOT count
        // as two sources. With n=1 there is no agreement boost, so a moderate
        // 0.65 finding stays Probable rather than being promoted to Verified.
        let mut e = Entity::new(EntityKind::Address, "PO Box 1, Townsville, QLD", 0.65, "s");
        e.add_evidence(Evidence::new("oathnet_pro", "breach record"));
        e.add_evidence(
            Evidence::new("geo_normalize", "Address parse + normalization").as_internal(),
        );
        assert_eq!(
            e.corroborating_sources().len(),
            1,
            "internal-flagged enrichment is not an independent source"
        );
        assert_eq!(e.source_count(), 1);
        assert!(
            (e.c_effective() - 0.65).abs() < 1e-9,
            "no agreement boost from a single real source + internal enrichment"
        );
        assert_eq!(e.classify(), Classification::Probable);
    }

    #[test]
    fn genuine_second_source_still_boosts_alongside_internal_enrichment() {
        // An independent module alongside the internal pass still counts as the
        // 2nd source, so real cross-correlation is unaffected by the filter.
        let mut e = Entity::new(EntityKind::Address, "1 Main St, Brisbane, QLD", 0.65, "s");
        e.add_evidence(Evidence::new("oathnet_pro", "breach record"));
        e.add_evidence(Evidence::new("geo_normalize", "enrichment").as_internal());
        e.add_evidence(Evidence::new("whois", "registrant address"));
        assert_eq!(
            e.source_count(),
            2,
            "oathnet_pro + whois count; the internal-flagged pass is excluded"
        );
        assert!(
            e.c_effective() > 0.65,
            "two genuinely independent sources still boost confidence"
        );
    }

    #[test]
    fn only_internal_evidence_floors_at_one_not_field() {
        // Pathological: the only evidence is internal enrichment. It must read as
        // a single observation, never inflated by a stale corroboration field.
        let mut e = Entity::new(EntityKind::Coordinates, "-19.26,146.81", 0.6, "s");
        e.corroboration = 9;
        e.add_evidence(Evidence::new("geo_normalize", "enrichment").as_internal());
        assert_eq!(e.source_count(), 1);
    }

    #[test]
    fn corroboration_keys_on_internal_flag_not_source_name() {
        // The abstraction is provenance-by-construction: it's the `internal`
        // flag that excludes evidence, NOT a magic source name. An arbitrary
        // source marked internal is excluded; an unmarked "geo_normalize"
        // (should never happen in prod, but proves the name isn't special) counts.
        let mut e = Entity::new(EntityKind::Email, "a@b.com", 0.6, "s");
        e.add_evidence(Evidence::new("hibp", "breach"));
        e.add_evidence(Evidence::new("some_future_enrichment", "derived").as_internal());
        assert_eq!(
            e.source_count(),
            1,
            "internal-flagged source is excluded by flag"
        );

        let mut e2 = Entity::new(EntityKind::Email, "c@d.com", 0.6, "s");
        e2.add_evidence(Evidence::new("hibp", "breach"));
        e2.add_evidence(Evidence::new("geo_normalize", "NOT flagged internal"));
        assert_eq!(
            e2.source_count(),
            2,
            "the name 'geo_normalize' is no longer magic — only the flag excludes"
        );
    }

    #[test]
    fn c_eff_clamped_to_one() {
        let mut e = email("a@b.com");
        e.confidence = 0.99;
        e.corroboration = 1000;
        assert!(e.c_effective() <= 1.0);
    }

    #[test]
    fn tier_rank_is_monotonic_and_finite() {
        // Tier ladder used by the bounded best-first halting bound.
        assert!(Classification::Candidate.rank() < Classification::Probable.rank());
        assert!(Classification::Probable.rank() < Classification::Verified.rank());
        assert_eq!(Classification::COUNT, 3);
        // Highest rank must be < COUNT so it indexes a finite ladder.
        assert!(Classification::Verified.rank() < Classification::COUNT);
    }

    #[test]
    fn tier_tracks_c_eff_bands() {
        let mut e = email("a@b.com");
        e.confidence = 0.30;
        assert_eq!(e.tier(), Classification::Candidate);
        e.confidence = 0.50;
        assert_eq!(e.tier(), Classification::Probable);
        e.confidence = 0.90;
        assert_eq!(e.tier(), Classification::Verified);
    }

    #[test]
    fn c_eff_safe_with_zero_corroboration() {
        let mut e = email("a@b.com");
        e.corroboration = 0;
        let c = e.c_effective();
        assert!(!c.is_nan(), "c_effective must not be NaN");
        assert!((0.0..=1.0).contains(&c));
    }

    #[test]
    fn merge_clamps_confidence() {
        let mut a = email("x@y.com");
        a.confidence = 1.5; // corrupted
        let b = email("x@y.com");
        a.merge(b);
        assert!(a.confidence <= 1.0, "merge must clamp confidence");
    }

    #[test]
    fn merge_corroboration_never_zero() {
        let mut a = email("x@y.com");
        a.corroboration = 0;
        let mut b = email("x@y.com");
        b.corroboration = 0;
        a.merge(b);
        assert!(
            a.corroboration >= 1,
            "corroboration must be at least 1 after merge"
        );
    }

    // ── Classification ───────────────────────────────────────────────────────

    #[test]
    fn classify_candidate() {
        let mut e = email("a@b.com");
        e.confidence = 0.2;
        assert_eq!(e.classify(), Classification::Candidate);
    }

    #[test]
    fn classify_probable() {
        let mut e = email("a@b.com");
        e.confidence = 0.55;
        assert_eq!(e.classify(), Classification::Probable);
    }

    #[test]
    fn classify_verified() {
        let mut e = email("a@b.com");
        e.confidence = 0.9;
        assert_eq!(e.classify(), Classification::Verified);
    }

    // ── Merge (GREATEST-semantics) ───────────────────────────────────────────

    #[test]
    fn merge_confidence_never_decreases() {
        let mut a = email("x@y.com");
        a.confidence = 0.8;
        let mut b = email("x@y.com");
        b.confidence = 0.3;
        a.merge(b);
        assert!((a.confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn merge_corroboration_accumulates() {
        let mut a = email("x@y.com");
        let mut b = email("x@y.com");
        b.corroboration = 3;
        a.merge(b);
        assert_eq!(a.corroboration, 4); // 1 + 3
    }

    // ── Decay ────────────────────────────────────────────────────────────────

    #[test]
    fn decay_immediate_is_unchanged() {
        let e = email("a@b.com");
        // observed_at == now, so elapsed ≈ 0 → GAMMA^0 = 1.0
        let d = e.decayed_confidence();
        assert!((d - e.confidence).abs() < 0.001);
    }

    #[test]
    fn decay_one_hour_ago() {
        let mut e = email("a@b.com");
        e.confidence = 1.0;
        e.observed_at = unix_now() - 3600; // 1 hour ago
        let d = e.decayed_confidence();
        // Should be ≈ GAMMA_PER_HOUR^1 = 0.85
        assert!((d - GAMMA_PER_HOUR).abs() < 0.01);
    }

    // ── Normalisation ────────────────────────────────────────────────────────

    #[test]
    fn normalise_email_lowercases() {
        assert_eq!(
            normalise(&EntityKind::Email, " Matt@EXAMPLE.COM "),
            "matt@example.com"
        );
    }

    #[test]
    fn normalise_phone_strips_formatting() {
        let r = normalise(&EntityKind::Phone, "+61 04 1234 5678");
        assert_eq!(r, "+61041234567 8".replace(' ', ""));
    }

    #[test]
    fn normalise_domain_strips_trailing_dot() {
        assert_eq!(
            normalise(&EntityKind::Domain, "example.com."),
            "example.com"
        );
    }

    #[test]
    fn normalise_url_lowercases_host_strips_fragment() {
        assert_eq!(
            normalise(&EntityKind::Url, "HTTPS://GitHub.Com/user/repo#readme"),
            "https://github.com/user/repo"
        );
        assert_eq!(
            normalise(&EntityKind::Url, "https://X.COM/Profile/"),
            "https://x.com/Profile"
        );
        assert_eq!(
            normalise(&EntityKind::Url, "http://example.com/search?q=test"),
            "http://example.com/search?q=test"
        );
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    #[test]
    fn tag_dedup() {
        let mut e = email("a@b.com");
        e.tag("au:breach");
        e.tag("au:breach");
        assert_eq!(e.tags.len(), 1);
    }

    // ── Display ──────────────────────────────────────────────────────────────

    #[test]
    fn display_contains_kind_and_classification() {
        let e = email("a@b.com");
        let s = e.to_string();
        assert!(s.contains("email"));
        assert!(s.contains("CANDIDATE") || s.contains("PROBABLE") || s.contains("VERIFIED"));
    }

    // ── apply_decay ─────────────────────────────────────────────────────────

    #[test]
    fn apply_decay_mutates_confidence_in_place() {
        let mut e = email("a@b.com");
        e.confidence = 1.0;
        e.observed_at = unix_now() - 7200; // 2 hours ago
        let expected = e.decayed_confidence();
        e.apply_decay();
        assert!((e.confidence - expected).abs() < 1e-9);
    }

    // ── add_evidence ────────────────────────────────────────────────────────

    #[test]
    fn add_evidence_appends_to_vec() {
        let mut e = email("a@b.com");
        assert!(e.evidence.is_empty());
        e.add_evidence(Evidence::new("mod-a", "found via breach db"));
        e.add_evidence(Evidence::new("mod-b", "confirmed via DNS"));
        assert_eq!(e.evidence.len(), 2);
        assert_eq!(e.evidence[0].source, "mod-a");
        assert_eq!(e.evidence[1].source, "mod-b");
    }

    // ── Evidence::new ───────────────────────────────────────────────────────

    #[test]
    fn evidence_new_sets_fields_and_empty_attributes() {
        let before = unix_now();
        let ev = Evidence::new("src", "summary text");
        let after = unix_now();
        assert_eq!(ev.source, "src");
        assert_eq!(ev.summary, "summary text");
        assert!(ev.attributes.is_empty());
        assert!(ev.recorded_at >= before && ev.recorded_at <= after);
    }

    // ── Evidence::with_attr ─────────────────────────────────────────────────

    #[test]
    fn evidence_with_attr_chaining() {
        let ev = Evidence::new("src", "sum")
            .with_attr("key1", "val1")
            .with_attr("key2", "val2");
        assert_eq!(ev.attributes.len(), 2);
        assert_eq!(ev.attributes.get("key1").unwrap(), "val1");
        assert_eq!(ev.attributes.get("key2").unwrap(), "val2");
    }

    // ── Entity::new confidence clamping ─────────────────────────────────────

    #[test]
    fn new_clamps_confidence_above_one() {
        let e = Entity::new(EntityKind::Email, "a@b.com", 1.5, "s");
        assert!((e.confidence - 1.0).abs() < 1e-9);
    }

    #[test]
    fn new_clamps_confidence_below_zero() {
        let e = Entity::new(EntityKind::Email, "a@b.com", -0.3, "s");
        assert!((e.confidence - 0.0).abs() < 1e-9);
    }

    // ── Entity merge: evidence appended ─────────────────────────────────────

    #[test]
    fn merge_evidence_appended_from_both() {
        let mut a = email("x@y.com");
        a.add_evidence(Evidence::new("mod-a", "evidence A"));
        let mut b = email("x@y.com");
        b.add_evidence(Evidence::new("mod-b", "evidence B"));
        b.add_evidence(Evidence::new("mod-c", "evidence C"));
        a.merge(b);
        assert_eq!(a.evidence.len(), 3);
        let sources: Vec<&str> = a.evidence.iter().map(|e| e.source.as_str()).collect();
        assert!(sources.contains(&"mod-a"));
        assert!(sources.contains(&"mod-b"));
        assert!(sources.contains(&"mod-c"));
    }

    // ── Entity merge: tags union dedup ───────────────────────────────────────

    #[test]
    fn merge_tags_union_dedup() {
        let mut a = email("x@y.com");
        a.tag("shared");
        a.tag("only-a");
        let mut b = email("x@y.com");
        b.tag("shared");
        b.tag("only-b");
        a.merge(b);
        assert!(a.has_tag("shared"));
        assert!(a.has_tag("only-a"));
        assert!(a.has_tag("only-b"));
        // "shared" must not be duplicated
        assert_eq!(a.tags.iter().filter(|t| *t == "shared").count(), 1);
    }

    // ── Entity merge: observed_at takes max ─────────────────────────────────

    #[test]
    fn merge_observed_at_takes_max() {
        let mut a = email("x@y.com");
        a.observed_at = 1000;
        let mut b = email("x@y.com");
        b.observed_at = 2000;
        a.merge(b);
        assert_eq!(a.observed_at, 2000);

        // Also verify when self is already newer
        let mut c = email("x@y.com");
        c.observed_at = 5000;
        let mut d = email("x@y.com");
        d.observed_at = 3000;
        c.merge(d);
        assert_eq!(c.observed_at, 5000);
    }

    // ── Entity merge: UID mismatch is no-op (release mode) ──────────────────

    #[test]
    #[cfg(not(debug_assertions))]
    fn merge_uid_mismatch_is_noop() {
        let mut a = email("x@y.com");
        let original_confidence = a.confidence;
        let original_corroboration = a.corroboration;
        let b = Entity::new(EntityKind::Email, "different@z.com", 0.9, "s");
        a.merge(b);
        assert!((a.confidence - original_confidence).abs() < 1e-9);
        assert_eq!(a.corroboration, original_corroboration);
    }

    // ── EntityKind::Other Display ───────────────────────────────────────────

    #[test]
    fn entity_kind_other_display() {
        let kind = EntityKind::Other("foo".to_string());
        assert_eq!(kind.to_string(), "other:foo");
    }

    // ── EntityRef from Entity ───────────────────────────────────────────────

    #[test]
    fn entity_ref_from_entity() {
        let e = email("a@b.com");
        let r = EntityRef::from(&e);
        assert_eq!(r.uid, e.uid);
        assert_eq!(r.kind, e.kind);
        assert_eq!(r.value, e.value);
    }

    // ── normalise: non-email kinds just trim ────────────────────────────────

    #[test]
    fn normalise_ip_address_trims() {
        let result = normalise(&EntityKind::IpAddress, "  192.168.1.1  ");
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn normalise_other_kind_trims() {
        let result = normalise(&EntityKind::Other("custom".into()), "  some value  ");
        assert_eq!(result, "some value");
    }

    // ── normalise: Username ─────────────────────────────────────────────────

    #[test]
    fn normalise_username_lowercases_and_trims() {
        let result = normalise(&EntityKind::Username, "  MyUser  ");
        assert_eq!(result, "myuser");
    }

    // ── Classification::as_str round-trips ──────────────────────────────────

    #[test]
    fn classification_as_str_round_trips() {
        assert_eq!(Classification::Candidate.as_str(), "CANDIDATE");
        assert_eq!(Classification::Probable.as_str(), "PROBABLE");
        assert_eq!(Classification::Verified.as_str(), "VERIFIED");

        // Also verify Display matches as_str
        assert_eq!(Classification::Candidate.to_string(), "CANDIDATE");
        assert_eq!(Classification::Probable.to_string(), "PROBABLE");
        assert_eq!(Classification::Verified.to_string(), "VERIFIED");
    }

    // ── EntityKind serde round-trip ─────────────────────────────────────────

    #[test]
    fn entity_kind_serde_round_trip() {
        let variants = vec![
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Username,
            EntityKind::Credential,
            EntityKind::Password,
            EntityKind::IpAddress,
            EntityKind::Domain,
            EntityKind::Url,
            EntityKind::Asn,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::Other("custom".to_string()),
        ];
        for kind in variants {
            let json = serde_json::to_string(&kind)
                .unwrap_or_else(|e| panic!("serialize {kind:?} failed: {e}"));
            let back: EntityKind = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("deserialize {json} failed: {e}"));
            assert_eq!(kind, back, "round-trip failed for {json}");
        }
    }

    // ── scan_id ─────────────────────────────────────────────────────────────

    #[test]
    fn scan_id_is_64_hex_chars() {
        let id = scan_id("email", "x@y.com");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn scan_id_different_inputs_differ() {
        let a = scan_id("email", "a@b.com");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let b = scan_id("email", "a@b.com");
        assert_ne!(a, b, "same inputs at different times must differ");
    }

    #[test]
    fn scan_id_different_kinds_differ() {
        let a = scan_id("email", "x");
        let b = scan_id("domain", "x");
        assert_ne!(a, b);
    }
}
