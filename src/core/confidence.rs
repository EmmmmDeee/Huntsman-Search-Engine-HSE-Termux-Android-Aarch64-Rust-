//! Standard confidence values for entity emission across all modules.
//! Using consistent confidence levels ensures comparability across diverse
//! extraction sources and allows tuning signal strength globally.

/// No signal — for entity validation gates only, never emitted.
pub const ZERO: f32 = 0.00;

/// Very low confidence — stray signal or weak contextual match.
pub const VERY_LOW: f32 = 0.25;

/// Low confidence — minimal context or distant source.
pub const LOW: f32 = 0.40;

/// Low-medium confidence — some context, moderate source reliability.
pub const LOW_MEDIUM: f32 = 0.45;

/// Medium confidence — reasonable context or solid source.
pub const MEDIUM: f32 = 0.50;

/// Medium-high confidence — good context and source.
pub const MEDIUM_HIGH: f32 = 0.55;

/// High confidence — strong context or reliable source.
pub const HIGH: f32 = 0.65;

/// Very high confidence — multi-source agreement or very strong context.
pub const VERY_HIGH: f32 = 0.75;

/// Expert confidence — subject-supplied data or authoritative source.
pub const EXPERT: f32 = 0.88;

/// Certainty — direct identity match or canonical source.
pub const CERTAIN: f32 = 0.99;
