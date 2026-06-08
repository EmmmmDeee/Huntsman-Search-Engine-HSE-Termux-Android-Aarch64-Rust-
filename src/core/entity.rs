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
    /// ≥ 0.75, `Probable` at ≥ 0.40, else `Candidate`.
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
        match self.c_effective() {
            c if c >= 0.75 => Classification::Verified,
            c if c >= 0.40 => Classification::Probable,
            _ => Classification::Candidate,
        }
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
        // Canonical display value: pick the lexicographically smaller raw_value
        // so the stored spelling is independent of merge order. Two modules can
        // emit the same value with different original casing/spacing
        // ("Foo@Bar.com" vs "foo@bar.com" — both normalise to one UID); under the
        // default concurrent dispatch, results merge in completion order, so
        // keeping `self`'s would leak that order into the persisted dossier
        // (Determinism Requirement). `min` is commutative, so any merge order —
        // and any pairing — yields the same raw_value.
        if other.raw_value < self.raw_value {
            self.raw_value = other.raw_value;
        }
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
            // handle sigil: a profile scraped as `@matthewdiegmann` and one parsed
            // as `matthewdiegmann` are the SAME account and must dedup to one UID.
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
    fn geo_normalize_does_not_count_as_corroboration() {
        // A coarse geo guess (one real module) that the engine's geospatial
        // enrichment pass also touched must NOT be credited as two-source
        // agreement: `geo_normalize` is deterministic self-enrichment, not an
        // independent observation. Otherwise a 0.30 candidate suburb would be
        // lifted into the Probable tier and fire the corroboration rules.
        let mut suburb = Entity::new(
            EntityKind::Address,
            "Maleny, QLD 4552, Australia",
            0.30,
            "s",
        );
        suburb.add_evidence(Evidence::new("qld_unclaimed", "locality within postcode"));
        suburb.add_evidence(Evidence::new(
            "geo_normalize",
            "Address parse + normalization",
        ));
        // Display still surfaces both sources…
        assert_eq!(suburb.evidence_sources().len(), 2);
        // …but corroboration sees only the one real intelligence source.
        assert_eq!(suburb.corroborating_sources().len(), 1);
        assert_eq!(suburb.source_count(), 1);
        // So c_eff stays at the base confidence → Candidate, not lifted to
        // Probable by a phantom second source.
        assert!((suburb.c_effective() - 0.30).abs() < 1e-9);
        assert_eq!(suburb.classify(), Classification::Candidate);

        // A second *real* source still corroborates as before.
        suburb.add_evidence(Evidence::new("geocode", "address confirmed"));
        assert_eq!(suburb.source_count(), 2);
        assert!(
            suburb.c_effective() > 0.30,
            "real second source still boosts"
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
    fn c_effective_contract_holds_across_grid() {
        // The analytical core's documented invariants, swept rather than
        // spot-checked — classification tiers AND the recursion/expansion gate
        // (`c_effective() >= min_expand_confidence`) ride on them, so a future
        // formula tweak that broke any of these would silently corrupt findings:
        //   (1) the fused confidence stays in [0, 1],
        //   (2) corroboration never *reduces* an entity's own confidence,
        //   (3) it is non-decreasing in the corroborating-source count, and
        //   (4) a single source is the identity (c_eff == confidence).
        for ci in 0..=20 {
            let c = f64::from(ci) / 20.0; // 0.00, 0.05, … 1.00
            let mut prev = f64::NEG_INFINITY;
            for n in 1..=25u32 {
                let mut e = email("a@b.com");
                e.confidence = c;
                e.corroboration = n; // no evidence ⇒ source_count() == n
                let ce = e.c_effective();
                assert!(
                    (0.0..=1.0).contains(&ce),
                    "c_eff out of [0,1]: c={c} n={n} ce={ce}"
                );
                assert!(
                    ce + 1e-12 >= c,
                    "corroboration must never reduce confidence: c={c} n={n} ce={ce}"
                );
                assert!(
                    ce + 1e-12 >= prev,
                    "c_eff must be non-decreasing in n: c={c} n={n} ce={ce} prev={prev}"
                );
                if n == 1 {
                    assert!(
                        (ce - c).abs() < 1e-12,
                        "a single source must be the identity: c={c} ce={ce}"
                    );
                }
                prev = ce;
            }
        }
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

    #[test]
    fn evidence_attributes_serialize_in_stable_sorted_order() {
        // BTreeMap → byte-identical JSON regardless of insertion order, so
        // identical findings serialise reproducibly (hashable evidence chains).
        let ev = Evidence::new("src", "sum")
            .with_attr("zulu", "1")
            .with_attr("alpha", "2")
            .with_attr("mike", "3");
        assert_eq!(
            serde_json::to_string(&ev.attributes).unwrap(),
            r#"{"alpha":"2","mike":"3","zulu":"1"}"#
        );
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

    #[test]
    fn canonicalize_order_is_merge_order_independent() {
        // DETERMINISM REQUIREMENT (evidence): an entity built by merging the same
        // module results in DIFFERENT orders (as concurrent completion-order
        // dispatch does) must finalise to identical evidence + tag ordering.
        let build = |order: &[(&str, &str)], tags: &[&str]| {
            let mut e = email("x@y.com");
            for (src, sum) in order {
                e.add_evidence(Evidence::new(*src, (*sum).to_string()));
            }
            for t in tags {
                e.tag(*t);
            }
            e.canonicalize_order();
            e
        };
        let a = build(
            &[("zmod", "z"), ("amod", "a"), ("amod", "b")],
            &["zeta", "alpha", "mid"],
        );
        let b = build(
            &[("amod", "b"), ("zmod", "z"), ("amod", "a")],
            &["mid", "zeta", "alpha"],
        );
        let ev = |e: &Entity| {
            e.evidence
                .iter()
                .map(|x| (x.source.clone(), x.summary.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(ev(&a), ev(&b), "evidence order depends on merge order");
        assert_eq!(a.tags, b.tags, "tag order depends on merge order");
        // Deterministic canonical order: evidence by (source, summary), tags sorted.
        assert_eq!(
            ev(&a),
            vec![
                ("amod".to_string(), "a".to_string()),
                ("amod".to_string(), "b".to_string()),
                ("zmod".to_string(), "z".to_string()),
            ]
        );
        assert_eq!(a.tags, vec!["alpha", "mid", "zeta"]);
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

    #[test]
    fn merge_raw_value_is_order_independent() {
        // Same UID (case-insensitive email), differing only in display spelling.
        let upper = email("Foo@Bar.com");
        let lower = email("foo@bar.com");
        assert_eq!(upper.uid, lower.uid, "must share a UID to exercise merge");

        // Merge both directions: the stored raw_value must not depend on order.
        let mut a = upper.clone();
        a.merge(lower.clone());
        let mut b = lower.clone();
        b.merge(upper.clone());
        assert_eq!(
            a.raw_value, b.raw_value,
            "raw_value must be merge-order independent (Determinism Requirement)"
        );
        // min() semantics: "Foo@Bar.com" < "foo@bar.com" (uppercase sorts first).
        assert_eq!(a.raw_value, "Foo@Bar.com");
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

    #[test]
    fn normalise_username_strips_leading_handle_sigil_for_dedup() {
        // `@matthewdiegmann` and `matthewdiegmann` are the same account: both must
        // normalise (and therefore derive the same UID) to the bare handle.
        assert_eq!(
            normalise(&EntityKind::Username, "@MatthewDiegmann"),
            "matthewdiegmann"
        );
        assert_eq!(
            normalise(&EntityKind::Username, "  @ matthewdiegmann "),
            "matthewdiegmann"
        );
        assert_eq!(
            derive_uid(
                &EntityKind::Username,
                &normalise(&EntityKind::Username, "@matthewdiegmann")
            ),
            derive_uid(
                &EntityKind::Username,
                &normalise(&EntityKind::Username, "matthewdiegmann")
            ),
            "@handle and handle must share a UID"
        );
        // Email is unaffected — a leading `@` there is a genuine fragment.
        assert_eq!(normalise(&EntityKind::Email, "Foo@Bar.com"), "foo@bar.com");
    }

    #[test]
    fn normalise_folds_non_ascii_uppercase_for_dedup() {
        // Regression: the old fast path returned early when a value had no ASCII
        // uppercase byte, so a value whose only capital is NON-ASCII (e.g. a
        // German/Scandinavian name, a Cyrillic/Greek handle, Turkish dotted-I)
        // was never folded — fragmenting one real identity across two UIDs while
        // its all-caps spelling folded correctly. Unicode folding must be total.
        for (mixed, lower) in [
            ("Ölaf", "ölaf"),
            ("İstanbul", "i\u{307}stanbul"), // İ folds to i + combining dot above
            ("ÉRIC", "éric"),
        ] {
            for kind in [EntityKind::Email, EntityKind::Username] {
                assert_eq!(
                    normalise(&kind, mixed),
                    lower,
                    "{kind:?}: {mixed:?} must fold to {lower:?}"
                );
                // The mixed-case and lower-case spellings must share a UID.
                assert_eq!(
                    Entity::new(kind.clone(), mixed, 0.5, "s").uid,
                    Entity::new(kind.clone(), lower, 0.5, "s").uid,
                    "{kind:?}: {mixed:?} and {lower:?} must dedup to one UID"
                );
            }
        }
    }

    /// All entity kinds, for the cross-kind normalisation invariants below.
    fn all_kinds() -> Vec<EntityKind> {
        use EntityKind::*;
        vec![
            Person,
            Email,
            Phone,
            Username,
            Credential,
            ApiKey,
            Password,
            IpAddress,
            Domain,
            Url,
            Asn,
            Address,
            Coordinates,
            Organisation,
            AbnAcn,
            MacAddress,
            DeviceId,
            CryptoAddress,
            Other("x".into()),
        ]
    }

    /// A corpus of awkward values spanning every normalisation arm: non-ASCII
    /// capitals, `+tag` emails, repeated/leading `www.`, mixed-case URLs with
    /// query+fragment, coordinates, dashed/`-0.0` numbers, MAC variants, IPv6.
    const NORM_CORPUS: &[&str] = &[
        "Ölaf",
        "ölaf",
        "ÉRIC",
        "İstanbul",
        "Ηandle",
        "Matthew.Diegmann+tag@Gmail.COM",
        "  spaced@x.com  ",
        "WWW.Example.COM.",
        "www.WWW.com",
        "www.com",
        "www.www.google.com",
        "HTTPS://Host.COM/Path/Sub/?Q=1&b=2#frag",
        "http://A.B/",
        "1.23456789,-2.5",
        "-0.0,0.0",
        "AA-BB-CC-DD-EE-FF",
        "+1 (555) 234-9999",
        "::ffff:1.2.3.4",
        "2001:DB8::1",
        "AS13335",
        "MixedCaseHandle",
    ];

    #[test]
    fn normalise_is_idempotent_for_every_kind() {
        // The normalised value keys the entity UID, so re-normalising an
        // already-normalised value MUST be a no-op — otherwise a stored or
        // re-emitted value can shift UID and silently fail to dedup. (Regression:
        // the `www.` strip removed only the first label, so `www.www.foo.com`
        // normalised to `www.foo.com` which then re-normalised to `foo.com`.)
        for k in all_kinds() {
            for v in NORM_CORPUS {
                let once = normalise(&k, v);
                let twice = normalise(&k, &once);
                assert_eq!(
                    once, twice,
                    "normalise not idempotent for {k:?}: {v:?} → {once:?} → {twice:?}"
                );
            }
        }
    }

    #[test]
    fn normalise_is_case_insensitive_for_folded_kinds() {
        // Email/Username/Domain dedup must be invariant under input case (full
        // Unicode), so the same identity from differently-cased sources merges.
        for k in [EntityKind::Email, EntityKind::Username, EntityKind::Domain] {
            for v in NORM_CORPUS {
                let base = normalise(&k, v);
                assert_eq!(
                    base,
                    normalise(&k, &v.to_uppercase()),
                    "{k:?} not case-invariant (upper): {v:?}"
                );
                assert_eq!(
                    base,
                    normalise(&k, &v.to_lowercase()),
                    "{k:?} not case-invariant (lower): {v:?}"
                );
            }
        }
    }

    #[test]
    fn normalise_domain_collapses_repeated_www_to_a_fixed_point() {
        assert_eq!(
            normalise(&EntityKind::Domain, "www.www.google.com"),
            "google.com"
        );
        assert_eq!(normalise(&EntityKind::Domain, "WWW.Foo.COM"), "foo.com");
        // A bare `www.` is never collapsed to the empty string (its trailing dot
        // is stripped first, leaving the literal `www`, which has no `www.` prefix).
        assert_eq!(normalise(&EntityKind::Domain, "www."), "www");
        // `www.www.` → trailing dot stripped → `www.www` → strip leading labels
        // down to the last non-`www.` label, which is itself `www`.
        assert_eq!(normalise(&EntityKind::Domain, "www.www."), "www");
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
            EntityKind::Cidr,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::MacAddress,
            EntityKind::DeviceId,
            EntityKind::TrackingId,
            EntityKind::CryptoAddress,
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
    fn scan_id_is_collision_free_for_rapid_identical_calls() {
        // Regression: two scans created within the SAME second with identical
        // (kind, value) previously hashed to the same id (only `unix_now()` at
        // 1 s resolution was mixed) and overwrote each other — a real defect for
        // rapid web imports / batch creates. No sleep: a tight burst of identical
        // calls must all be distinct.
        let ids: std::collections::HashSet<String> =
            (0..1000).map(|_| scan_id("email", "a@b.com")).collect();
        assert_eq!(
            ids.len(),
            1000,
            "scan_id must be collision-free within a second"
        );
    }

    #[test]
    fn scan_id_different_kinds_differ() {
        let a = scan_id("email", "x");
        let b = scan_id("domain", "x");
        assert_ne!(a, b);
    }
}
