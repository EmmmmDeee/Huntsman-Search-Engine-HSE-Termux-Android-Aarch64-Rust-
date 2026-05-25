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
use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Corroboration boost coefficient (architecture invariant).
pub const CORROBORATION_COEFF: f64 = 0.15;

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
    /// Human-readable summary. Passwords MUST NOT appear here.
    pub summary: String,
    /// Raw key/value pairs from the module (no passwords).
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    /// Unix timestamp (seconds) when evidence was recorded.
    pub recorded_at: u64,
}

impl Evidence {
    pub fn new(source: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            summary: summary.into(),
            attributes: HashMap::new(),
            recorded_at: unix_now(),
        }
    }

    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn with_opt_attr(self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.with_attr(key, v),
            None => self,
        }
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

    /// `C_eff = clamp(confidence × (1 + 0.15 × ln(corroboration)), 0.0, 1.0)`
    ///
    /// Architecture invariant — do not modify the formula.
    #[inline]
    pub fn c_effective(&self) -> f64 {
        if self.corroboration == 0 { return self.confidence.clamp(0.0, 1.0); }
        let boost = CORROBORATION_COEFF.mul_add((self.corroboration as f64).ln(), 1.0);
        (self.confidence * boost).clamp(0.0, 1.0)
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

    pub fn tag_if(&mut self, cond: bool, t: impl Into<String>) {
        if cond {
            self.tag(t);
        }
    }

    pub fn tag_opt(&mut self, opt: Option<bool>, t: impl Into<String>) {
        if opt == Some(true) {
            self.tag(t);
        }
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
        self.confidence = f64::max(self.confidence, other.confidence);
        self.corroboration = self.corroboration.saturating_add(other.corroboration);
        self.observed_at = u64::max(self.observed_at, other.observed_at);
        self.evidence.extend(other.evidence);
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
    let mut h = Sha256::new();
    h.update(kind.to_string().as_bytes());
    h.update(b":");
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
        EntityKind::Email | EntityKind::Domain | EntityKind::Username => {
            let trimmed = value.trim();
            let mut s = String::with_capacity(trimmed.len());
            for c in trimmed.chars() {
                s.extend(c.to_lowercase());
            }
            let len = s.trim_end_matches('.').len();
            s.truncate(len);
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
        // c_eff = 0.6 * (1 + 0.15 * ln(4)) = 0.6 * 1.2079...
        let expected = 0.6 * 0.15f64.mul_add(4f64.ln(), 1.0);
        assert!((e.c_effective() - expected).abs() < 1e-9);
    }

    #[test]
    fn c_eff_clamped_to_one() {
        let mut e = email("a@b.com");
        e.confidence = 0.99;
        e.corroboration = 1000;
        assert!(e.c_effective() <= 1.0);
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
}
