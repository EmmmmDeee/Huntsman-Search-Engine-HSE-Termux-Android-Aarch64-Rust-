//! Standard confidence values for entity emission across all modules.
//! Using consistent confidence levels ensures comparability across diverse
//! extraction sources and allows tuning signal strength globally.

/// No signal — for entity validation gates only, never emitted.
pub const ZERO: f64 = 0.00;

/// Very low confidence — stray signal or weak contextual match.
pub const VERY_LOW: f64 = 0.25;

/// Low confidence — minimal context or distant source.
pub const LOW: f64 = 0.40;

/// Low-medium confidence — some context, moderate source reliability.
pub const LOW_MEDIUM: f64 = 0.45;

/// Medium confidence — reasonable context or solid source.
pub const MEDIUM: f64 = 0.50;

/// Medium confidence + — solid context, slightly elevated reliability.
pub const MEDIUM_PLUS: f64 = 0.60;

/// Medium-high confidence — good context and source.
pub const MEDIUM_HIGH: f64 = 0.55;

/// High confidence — strong context or reliable source.
pub const HIGH: f64 = 0.65;

/// High confidence + — between high and very high, elevated agreement.
pub const HIGH_PLUS: f64 = 0.70;

/// High confidence ++ — approaching very high, strong corroboration.
pub const HIGH_PLUSPLUS: f64 = 0.80;

/// High confidence +++ — near-expert level, nearly authoritative.
pub const HIGH_PLUSPLUS_PLUS: f64 = 0.85;

/// Very high confidence — multi-source agreement or very strong context.
pub const VERY_HIGH: f64 = 0.75;

/// Very high confidence + — exceeds multi-source threshold.
pub const VERY_HIGH_PLUS: f64 = 0.90;

/// Very high confidence ++ — near-certain agreement across sources.
pub const VERY_HIGH_PLUSPLUS: f64 = 0.95;

/// Expert confidence — subject-supplied data or authoritative source.
pub const EXPERT: f64 = 0.88;

/// Certainty — direct identity match or canonical source.
pub const CERTAIN: f64 = 0.99;

// ─── Score converters ────────────────────────────────────────────────────────

/// Convert abuse/reputation score (0-100 scale) to confidence tier.
///
/// Used by reputation APIs (abuseipdb, criminal_ip, etc.) that emit scores as
/// percentiles. Maps `0 → MEDIUM_PLUS`, `100 → MEDIUM_PLUS + 0.35`, creating
/// a gentle slope that respects moderate findings while allowing high scores
/// to reach `VERY_HIGH` through corroboration.
///
/// # Arguments
/// * `score` — reputation score on 0-100 scale (clamped to that range)
#[inline]
pub fn from_abuse_score(score: u8) -> f64 {
    MEDIUM_PLUS + (score as f64 / 100.0) * 0.35
}

/// Convert threat level (0-N scale) to confidence tier.
///
/// Used by threat intelligence APIs (greynoise, anomali, etc.) that emit
/// severity or threat scores on arbitrary scales. Caller must specify the
/// maximum score for normalization.
///
/// Maps `0 → MEDIUM`, `max_score → MEDIUM + 0.40`, creating a slope that
/// escalates moderate findings through corroboration while respecting the
/// provider's own confidence.
///
/// # Arguments
/// * `score` — threat score value
/// * `max_score` — maximum value on the threat scale
#[inline]
pub fn from_threat_score(score: f64, max_score: f64) -> f64 {
    if max_score <= 0.0 {
        return MEDIUM;
    }
    MEDIUM + (score / max_score) * 0.40
}

/// Convert boolean match + supporting signal count to confidence tier.
///
/// Used when a finding is corroborated by multiple independent data points
/// (count, frequency, co-occurrence, etc.) WITHOUT full API-provided confidence.
/// Each supporting signal boosts confidence from `Candidate` → `Probable`
/// → `Strong`.
///
/// # Arguments
/// * `score_count` — number of supporting signals (e.g., breach corpus count)
///
/// # Returns
/// * 0 signals → `CANDIDATE` (0.25)
/// * 1-2 signals → `PROBABLE` (0.50)
/// * 3+ signals → `STRONG` (0.75)
#[inline]
pub fn from_corroborated_match(score_count: usize) -> f64 {
    match score_count {
        0 => VERY_LOW,   // Candidate tier
        1..=2 => MEDIUM, // Probable tier
        _ => VERY_HIGH,  // Strong tier
    }
}
