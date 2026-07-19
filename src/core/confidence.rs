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
