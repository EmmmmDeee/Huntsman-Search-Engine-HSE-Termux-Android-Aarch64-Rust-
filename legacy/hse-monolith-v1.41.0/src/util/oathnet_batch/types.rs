//! Public types: [`Origin`], [`BatchQuery`], [`BatchOptions`], and the
//! re-exported [`Surface`].

// The surface vocabulary (breach/stealer ↔ path) is the shared OathNet query
// model — re-exported so `BatchQuery` and the CLI keep naming it
// `oathnet_batch::Surface` while there is exactly one definition.
pub use crate::util::oathnet::Surface;

use crate::core::scan::TargetKind;
use crate::util::oathnet::{FIELD_DOMAIN, FIELD_EMAIL, FIELD_IP, FIELD_PHONE, FIELD_USERNAME};

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

impl BatchQuery {
    /// The [`TargetKind`] this query's selector field dispatches as, or `None`
    /// when the field names no scannable identifier.
    ///
    /// The exact inverse of [`crate::util::oathnet::selector_field`], and it
    /// lives here — on the type that carries the field — rather than in the
    /// API client, for two reasons. It is pure (a `match` over `&'static str`
    /// constants; no state, network, or key), and it is what a *consumer* of a
    /// generated plan needs: every caller that turns queries into scan targets
    /// asks this question, so answering it once here stops each of them from
    /// re-deriving the mapping and drifting from the generator.
    ///
    /// `q` (free text) maps to `None`: it is a corpus-side full-text search,
    /// not an identifier, so there is no module graph to run for it. Callers
    /// must count those as skipped rather than dropping them in silence.
    ///
    /// ```
    /// use huntsman_search_engine::core::scan::TargetKind;
    /// use huntsman_search_engine::util::oathnet_batch::{generate, BatchOptions};
    ///
    /// let qs = generate(TargetKind::Email, "a.b@example.org", &BatchOptions::default());
    /// // Every query the generator emits either names a scannable kind or is
    /// // free text — never an unrecognised field.
    /// assert!(qs.iter().all(|q| q.target_kind().is_some() || q.field == "q"));
    /// ```
    #[must_use]
    pub fn target_kind(&self) -> Option<TargetKind> {
        Some(match self.field {
            FIELD_EMAIL => TargetKind::Email,
            FIELD_USERNAME => TargetKind::Username,
            FIELD_PHONE => TargetKind::Phone,
            FIELD_DOMAIN => TargetKind::Domain,
            FIELD_IP => TargetKind::IpAddress,
            // `FIELD_QUERY` and anything unrecognised.
            _ => return None,
        })
    }
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
    /// How many extra levels to **recursively** expand derived query values
    /// through the same per-kind fan-out (a derived `username` re-derives its own
    /// handle permutations / candidate emails, a derived `domain` its role
    /// emails, a synthesised email its own local-part username + domain, …).
    ///
    /// `0` (the default) keeps the precise single-level plan. Each extra level is
    /// a bounded, cycle-safe breadth-first step — a value is never expanded twice —
    /// so generation always terminates; but because it compounds with
    /// `permute_handles` / `synthesize_emails` it is opt-in, and `max_queries`
    /// remains the hard cap on the result. The recursion NEVER lowers precision of
    /// the base plan — it only appends deeper derived queries after it.
    pub recurse_depth: u32,
    /// Cap on the number of queries returned after de-duplication. `0` = no cap.
    pub max_queries: usize,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            include_stealer: true,
            permute_handles: true,
            synthesize_emails: false,
            recurse_depth: 0,
            max_queries: 0,
        }
    }
}
