//! `core::entity` — HSE entity model.
//!
//! # Architecture invariants
//! - SHA-256 deterministic UIDs
//! - GREATEST-semantics merge (confidence, corroboration only ever increase)
//! - `C_eff = clamp(C × (1 + 0.15 × ln(corroboration)), 0.0, 1.0)`
//! - `Classify()` is derived-only from `C_eff`
//! - No unsafe, no std::sync::Mutex (use tokio::sync)
//! - Zero CGO / native deps

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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

/// Evidence "sources" that are deterministic self-enrichment passes the engine
/// runs over every entity of a given kind — NOT independent intelligence.
///
/// `geo_normalize` is the geospatial enrichment pass ([`crate::core::engine`])
/// that attaches a geohash/timezone/parsed-address evidence record to *every*
/// `Coordinates`/`Address` entity. Because it fires unconditionally it is not a
/// cross-correlating observation: counting it as a distinct source silently
/// lifted single-source coarse geo guesses (a postcode centroid, a candidate
/// suburb) from their base confidence into the Probable tier via the
/// agreement model, and fired the corroboration correlator rules
/// (AU-003/AU-014/AU-030) once per such entity. These sources are still kept in
/// the evidence chain (their attributes are real and useful) and still appear
/// in [`Entity::evidence_sources`] for display; they are only excluded from the
/// *corroboration* count — see [`Entity::corroborating_sources`].
pub const ENRICHMENT_ONLY_SOURCES: &[&str] = &["geo_normalize"];

/// True if `source` is a deterministic self-enrichment pass rather than an
/// independent intelligence source (see [`ENRICHMENT_ONLY_SOURCES`]).
#[inline]
pub fn is_enrichment_source(source: &str) -> bool {
    ENRICHMENT_ONLY_SOURCES.contains(&source)
}

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
    /// A CIDR network block (`192.0.2.0/24`, `2001:db8::/48`). A scannable
    /// target that expands into its constituent host IPs (bounded).
    Cidr,

    // Physical / GEOINT
    Address,
    Coordinates,

    // Organisation
    Organisation,
    AbnAcn,

    // Device
    MacAddress,
    DeviceId,

    // Web-analytics / tracking identifier (Google Analytics `UA-`/`G-`, GTM
    // `GTM-`, AdSense `ca-pub-`, Facebook Pixel, Yandex Metrica, Hotjar). A shared
    // ID across otherwise-unrelated sites is strong evidence of common ownership —
    // the "affiliate" pivot. Not a scannable target; a correlation node only.
    TrackingId,

    // Financial — cryptocurrency wallet addresses (BTC/ETH/LTC/…). A first-class
    // OSINT artifact: case-sensitive (base58 / bech32 / 0x-hex), never an API
    // key, and the pivot point for free chain-explorer enrichment.
    CryptoAddress,

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
            Self::Cidr => f.write_str("cidr"),
            Self::Address => f.write_str("address"),
            Self::Coordinates => f.write_str("coordinates"),
            Self::Organisation => f.write_str("organisation"),
            Self::AbnAcn => f.write_str("abn_acn"),
            Self::MacAddress => f.write_str("mac_address"),
            Self::DeviceId => f.write_str("device_id"),
            Self::TrackingId => f.write_str("tracking_id"),
            Self::CryptoAddress => f.write_str("crypto_address"),
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
    /// Lower bound of the Verified tier: `C_eff ≥ VERIFIED_MIN`.
    ///
    /// The tier ladder's single source of truth (with [`Self::PROBABLE_MIN`]).
    /// Consumed by [`Self::from_c_eff`] / `Entity::classify`, the CLI's
    /// confidence colouring, the engine's subject-identity gate ("every
    /// VERIFIED identity"), and the wrong-identity pivot gate ("below the
    /// Verified tier") — previously each re-stated `0.75` as a bare literal,
    /// so a recalibration would have silently diverged them.
    pub const VERIFIED_MIN: f64 = 0.75;
    /// Lower bound of the Probable tier: `C_eff ≥ PROBABLE_MIN` (and below
    /// [`Self::VERIFIED_MIN`]). Below this is Candidate.
    pub const PROBABLE_MIN: f64 = 0.40;

    /// The tier for an effective confidence — the canonical ladder. A
    /// non-finite `c_eff` (never produced by `c_effective`, which clamps)
    /// fails both bounds and lands in `Candidate`, the conservative tier.
    #[inline]
    #[must_use]
    pub fn from_c_eff(c_eff: f64) -> Self {
        if c_eff >= Self::VERIFIED_MIN {
            Self::Verified
        } else if c_eff >= Self::PROBABLE_MIN {
            Self::Probable
        } else {
            Self::Candidate
        }
    }

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
    /// graduation. `rank()`/[`Self::COUNT`] are the ladder that the planned
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

// ─── Evidence ────────────────────────────────────────────────────────────────

/// A single piece of evidence attached to an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Module that produced this evidence.
    pub source: String,
    /// Human-readable summary / label for the record (not the raw data itself).
    pub summary: String,
    /// Raw key/value pairs from the module — the FULL source record, preserved
    /// verbatim for traceability (operator full-fidelity policy: nothing
    /// redacted or omitted, credentials included). The canonical leaked
    /// secret is additionally surfaced as a first-class `Password`/`Credential`
    /// entity so it is searchable and expandable, not just an attribute.
    /// `BTreeMap` (not `HashMap`) so the serialised evidence has a stable,
    /// sorted key order — identical findings must produce byte-identical JSON
    /// (reproducibility / hashable evidence chains), and HashMap iteration order
    /// is randomised per instance.
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    /// Unix timestamp (seconds) when evidence was recorded.
    pub recorded_at: u64,
}

impl Evidence {
    pub fn new(source: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            summary: summary.into(),
            attributes: BTreeMap::new(),
            recorded_at: unix_now(),
        }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
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
    /// This is `corroborating_sources().len()` (distinct `evidence.source`
    /// strings, since every module emits one stable source name, minus the
    /// deterministic self-enrichment passes in [`ENRICHMENT_ONLY_SOURCES`]),
    /// floored at 1. When no corroborating evidence is attached (synthetic/test
    /// entities, an entity constructed before its evidence, or one carrying only
    /// enrichment evidence) it falls back to the stored `corroboration` field so
    /// an explicitly-set strength value is still honoured.
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
            // Evidence is attached: distinct *corroborating* sources is the
            // authoritative cross-correlation count. The summed `corroboration`
            // magnitude is deliberately NOT allowed to inflate it (that was the
            // original bug), and deterministic self-enrichment passes
            // (`geo_normalize`) are excluded so they can't fabricate agreement.
            distinct
        } else {
            // No evidence (synthetic/test entity, or constructed pre-evidence):
            // fall back to the explicitly-set field so a deliberate strength
            // value is still honoured.
            self.corroboration.max(1)
        }
    }

    /// Cross-source effective confidence — the stronger of two models over the
    /// number of DISTINCT corroborating sources `n` (see [`Self::source_count`],
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
    ///
    /// ```
    /// use huntsman_search_engine::core::entity::{Entity, EntityKind};
    ///
    /// // Single source (no evidence attached → n = 1): C_eff equals confidence.
    /// let e = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan");
    /// assert_eq!(e.source_count(), 1);
    /// assert!((e.c_effective() - 0.6).abs() < 1e-9);
    /// ```
    #[inline]
    pub fn c_effective(&self) -> f64 {
        let n = f64::from(self.source_count());
        let multiplicative = self.confidence * CORROBORATION_COEFF.mul_add(n.ln(), 1.0);
        let residual_doubt = (1.0 - self.confidence) * CORROBORATION_DOUBT_DECAY.powf(n - 1.0);
        let agreement = 1.0 - residual_doubt;
        multiplicative.max(agreement).clamp(0.0, 1.0)
    }

    /// Derived classification tier from [`Self::c_effective`]: `Verified` at
    /// ≥ [`Classification::VERIFIED_MIN`] (0.75), `Probable` at ≥
    /// [`Classification::PROBABLE_MIN`] (0.40), else `Candidate`.
    ///
    /// Never stored — always recomputed, so a tier can only ever rise as merges
    /// add corroboration.
    ///
    /// ```
    /// use huntsman_search_engine::core::entity::{Classification, Entity, EntityKind};
    ///
    /// let mk = |c| Entity::new(EntityKind::Email, "x@example.com", c, "scan").classify();
    /// assert_eq!(mk(0.90), Classification::Verified);
    /// assert_eq!(mk(0.50), Classification::Probable);
    /// assert_eq!(mk(0.20), Classification::Candidate);
    /// ```
    #[inline]
    pub fn classify(&self) -> Classification {
        Classification::from_c_eff(self.c_effective())
    }

    /// The entity's current confidence tier — alias for [`Self::classify`] that
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

    /// Distinct evidence sources that represent *independent* intelligence —
    /// [`Self::evidence_sources`] minus the deterministic self-enrichment passes in
    /// [`ENRICHMENT_ONLY_SOURCES`]. This is the honest cross-correlation set
    /// that drives [`Self::source_count`]/[`Self::c_effective`] and the corroboration
    /// correlator rules; the full [`Self::evidence_sources`] set is retained for
    /// display and attribute access.
    pub fn corroborating_sources(&self) -> std::collections::HashSet<&str> {
        self.evidence
            .iter()
            .map(|ev| ev.source.as_str())
            .filter(|&s| !is_enrichment_source(s))
            .collect()
    }

    pub fn has_evidence_from(&self, source: &str) -> bool {
        self.evidence.iter().any(|ev| ev.source == source)
    }

    // ── GREATEST-semantics merge ─────────────────────────────────────────────

    /// Put this entity's evidence and tags into a deterministic order so the
    /// PERSISTED/EXPORTED result does not depend on the order modules happened to
    /// run in. Concurrent dispatch (the default, `max_concurrent > 0`) merges
    /// module results in completion order, which would otherwise leak into the
    /// evidence/tags ordering of the stored entity and make two runs' dossiers
    /// differ for no real reason (Determinism Requirement). Evidence is sorted by
    /// its dedup key — `(source, summary)`, already unique per entity — and tags
    /// lexicographically. Membership (`has_tag`) and the GREATEST
    /// confidence/corroboration are unaffected; only display/serialisation order
    /// is normalised. Called once per entity at scan finalisation, so it is not on
    /// the per-merge hot path.
    ///
    /// `raw_value` is likewise made order-independent by [`Entity::merge`],
    /// which keeps the lexicographically smaller spelling when two same-UID
    /// entities differ only in original casing/spacing (`Foo@Bar.com` vs
    /// `foo@bar.com`). Because `min` is commutative, the stored display value no
    /// longer depends on which module's result merged first.
    pub fn canonicalize_order(&mut self) {
        self.evidence.sort_by(|a, b| {
            a.source
                .cmp(&b.source)
                .then_with(|| a.summary.cmp(&b.summary))
        });
        self.tags.sort();
    }

    /// Merge `other` into `self` using GREATEST-semantics.
    ///
    /// This is the deduplication primitive: two entities with the same `uid`
    /// (same kind + normalised value) are folded so corroboration only ever
    /// grows — replaying the same finding never regresses confidence or drops
    /// evidence.
    ///
    /// Rules:
    /// - `uid` must match (debug-asserts; a mismatch is a no-op in release)
    /// - `confidence`  = max(self, other)        — never decreases
    /// - `corroboration` += other.corroboration  — only increases
    /// - `observed_at`  = max(self, other)        — most recent wins
    /// - `raw_value`    = min(self, other)        — deterministic display value
    /// - `evidence` merged, de-duplicated by `(source, summary)`
    /// - `tags` unioned (de-duplicated)
    ///
    /// ```
    /// use huntsman_search_engine::core::entity::{Entity, EntityKind, Evidence};
    ///
    /// let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.5, "scan");
    /// a.tag("breach");
    /// a.add_evidence(Evidence::new("hibp", "seen"));
    ///
    /// let mut b = Entity::new(EntityKind::Email, "X@Example.com", 0.9, "scan");
    /// b.tag("paste-exposed");
    /// b.add_evidence(Evidence::new("dehashed", "seen"));
    ///
    /// assert_eq!(a.uid, b.uid); // same kind + normalised value → same UID
    /// a.merge(b);
    /// assert_eq!(a.confidence, 0.9);    // GREATEST: confidence never decreases
    /// assert!(a.has_tag("breach") && a.has_tag("paste-exposed")); // tags unioned
    /// assert_eq!(a.evidence.len(), 2);  // distinct evidence both kept
    /// ```
    pub fn merge(&mut self, other: Self) {
        debug_assert_eq!(self.uid, other.uid, "merge: UID mismatch");
        if self.uid != other.uid {
            return;
        }
        // Canonical display value: pick the lexicographically smaller raw_value
        // so the stored spelling is independent of merge order. Two modules can
        // emit the same value with different original casing/spacing
        // ("Foo@Bar.com" vs "foo@bar.com" — both normalise to one UID); under the
        // default concurrent dispatch, results merge in completion order, so
        // keeping `self`'s would leak that order into the persisted dossier
        // (Determinism Requirement). `min` is commutative, so any merge order —
        // and any pairing — yields the same raw_value.
        if other.raw_value < self.raw_value {
            self.raw_value = other.raw_value.clone();
        }
        self.absorb(other);
    }

    /// Fold another entity's corroborating **signal** into this one — confidence
    /// (max), corroboration (sum), recency (max), deduplicated evidence and tags
    /// — without touching identity (`uid`/`value`/`raw_value`).
    ///
    /// This is the identity-preserving core of [`merge`](Self::merge), exposed
    /// for the rare case of intentionally combining two entities with DIFFERENT
    /// UIDs that nonetheless denote the same real-world thing — e.g. collapsing
    /// `Address` entities for one locality (`"X, NSW"` and `"X, NSW 2582"`),
    /// which `merge` would refuse because their UIDs differ. The caller is
    /// responsible for having decided the two are the same; `absorb` only fuses
    /// their evidence. Commutative in confidence/corroboration/evidence/tags, so
    /// folding a group in any order yields the same result.
    pub(crate) fn absorb(&mut self, other: Self) {
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
    // digest 0.11 dropped the `io::Write` impl for hashers; feed the same bytes
    // (`"<kind>:"`) via `update` so existing UIDs stay byte-identical.
    let mut h = Sha256::new();
    h.update(format!("{kind}:").as_bytes());
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
        EntityKind::Email => {
            // Total Unicode case-fold for dedup. `str::to_lowercase` maps every
            // char through `char::to_lowercase`, so a value whose only capital is
            // non-ASCII (`Ölaf`, a Cyrillic/Greek handle, Turkish `İ`) folds the
            // same as its all-caps spelling — they must share a UID. (A previous
            // ASCII-only "fast path" returned such values unfolded, fragmenting
            // one identity across two UIDs; it also still allocated, so it bought
            // nothing.)
            value.trim().to_lowercase()
        }
        EntityKind::Username => {
            // Same total Unicode case-fold as Email, plus stripping a leading `@`
            // handle sigil: a profile scraped as `@jordanavery` and one parsed
            // as `jordanavery` are the SAME account and must dedup to one UID.
            // Without this they fragmented into two identities, and the `@`-prefixed
            // copy also looked like a truncated value to the fragment auditor.
            value.trim().trim_start_matches('@').trim().to_lowercase()
        }
        EntityKind::Domain => {
            let trimmed = value.trim();
            let mut s = String::with_capacity(trimmed.len());
            for c in trimmed.chars() {
                s.extend(c.to_lowercase());
            }
            let len = s.trim_end_matches('.').len();
            s.truncate(len);
            // Strip leading `www.` label(s) so `www.foo.com` and `foo.com` dedup
            // to one host. Consume *all* consecutive leading `www.` labels in a
            // single pass (not just the first) so the result is a fixed point:
            // a single strip left `www.www.foo.com` → `www.foo.com`, which then
            // re-normalised to `foo.com`, so the same host could key to two UIDs.
            // The non-empty guard keeps a bare `www.` from collapsing to "".
            let mut host = s.as_str();
            while let Some(rest) = host.strip_prefix("www.") {
                if rest.is_empty() {
                    break;
                }
                host = rest;
            }
            if host.len() != s.len() {
                s = host.to_string();
            }
            s
        }
        EntityKind::Phone => {
            // Trim BEFORE the leading-`+` check: every other arm trims, and a
            // scraped value with leading whitespace (" +61 412 …") would
            // otherwise fail the first-char test and silently drop the
            // country-code `+`, fragmenting one number across two UIDs
            // ("61412…" vs "+61412…").
            let trimmed = value.trim();
            let mut out = String::with_capacity(trimmed.len());
            let mut chars = trimmed.chars().peekable();
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
                && lat.is_finite()
                && lon.is_finite()
            {
                // Round to 6 dp first, then `+ 0.0` to collapse IEEE negative
                // zero: formatting `-0.0000001` directly yields "-0.000000",
                // which is the same point as "0.000000" but a different UID —
                // coordinates straddling the equator/meridian must not
                // fragment on the sign of zero. Non-finite values (NaN/inf)
                // fall through to the raw string instead of a formatted
                // pseudo-coordinate.
                let lat = (lat * 1e6).round() / 1e6 + 0.0;
                let lon = (lon * 1e6).round() / 1e6 + 0.0;
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
    use std::sync::atomic::{AtomicU64, Ordering};
    // Collision-free per scan. The previous derivation mixed only `unix_now()`
    // at ONE-SECOND resolution, so two scans created in the same second with the
    // same (kind, value) — rapid web imports, a `/scans/batch`, a tight loop —
    // hashed identically and the second silently overwrote the first's row +
    // entities. Mix in a process-wide monotonic counter (guarantees uniqueness
    // within a run, even same-nanosecond) plus the sub-second nanos (separates
    // ids across a restart that resets the counter), keeping `unix_now()` for
    // human-meaningful time ordering. Re-scans still get a fresh id by design.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(b":");
    h.update(value.as_bytes());
    h.update(b":");
    h.update(unix_now().to_be_bytes());
    h.update(nanos.to_be_bytes());
    h.update(SEQ.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hex::encode(h.finalize())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
