//! Public types: [`Origin`], [`BatchQuery`], [`BatchOptions`], and the
//! re-exported [`Surface`].

// The surface vocabulary (breach/stealer ↔ path) is the shared OathNet query
// model — re-exported so `BatchQuery` and the CLI keep naming it
// `oathnet_batch::Surface` while there is exactly one definition.
pub use crate::util::oathnet::Surface;

/// Why a query was generated — surfaced in the plan so an operator can see how
/// each query relates to the seed, and so callers can weight derived queries
/// below the direct seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The seed value itself, searched on its native selector.
    Seed,
    /// A `username` search built from an email's local part.
    EmailLocalPart,
    /// A `domain` search built from an email's domain.
    EmailDomain,
    /// A `username` search built from a name/handle permutation.
    Handle,
    /// A reformatted phone number (digits-only, E.164, …).
    PhoneFormat,
    /// A synthesised candidate email (handle/role crossed with a domain).
    EmailCandidate,
}

impl Origin {
    /// Short human/JSON label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::EmailLocalPart => "email-local-part",
            Self::EmailDomain => "email-domain",
            Self::Handle => "handle-permutation",
            Self::PhoneFormat => "phone-format",
            Self::EmailCandidate => "email-candidate",
        }
    }
}

/// A single generated query: one surface × one selector field × one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchQuery {
    /// Which OathNet corpus this query targets.
    pub surface: Surface,
    /// OathNet selector field (`email`, `username`, `phone`, `domain`, `ip`, `q`).
    pub field: &'static str,
    /// The value to search for — always trimmed and non-empty.
    pub value: String,
    /// Why this query was generated — its provenance back to the seed.
    pub origin: Origin,
}

/// Knobs controlling how aggressively the seed is expanded.
///
/// Build from [`BatchOptions::default`] and override the fields you need:
///
/// ```
/// use huntsman_search_engine::util::oathnet_batch::BatchOptions;
///
/// // Breach-only, no speculative handle permutations, capped at 8 queries.
/// let opts = BatchOptions {
///     include_stealer: false,
///     permute_handles: false,
///     max_queries: 8,
///     ..BatchOptions::default()
/// };
/// assert!(!opts.synthesize_emails); // the conservative default is preserved
/// ```
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Also emit stealer-surface queries for login-indexable selectors
    /// (`email`/`username`). Breach is always emitted.
    pub include_stealer: bool,
    /// Fan names and email local parts out into handle permutations.
    pub permute_handles: bool,
    /// Synthesise candidate emails (handle/role crossed with common providers).
    /// Explosive and speculative — off by default.
    pub synthesize_emails: bool,
    /// Cap on the number of queries returned after de-duplication. `0` = no cap.
    pub max_queries: usize,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            include_stealer: true,
            permute_handles: true,
            synthesize_emails: false,
            max_queries: 0,
        }
    }
}
