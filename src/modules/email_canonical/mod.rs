//! Emit the canonical mailbox address for an `Email` seed — pure offline, no
//! network. Different-looking addresses that *provably* reach the same inbox
//! get normalised to one canonical `Email`, so the graph and the correlator
//! treat them as a single identity instead of N fragments:
//!
//!   * **`+tag` subaddressing** — `jdoe+news@x.com` → `jdoe@x.com` (Gmail,
//!     Outlook/Microsoft, Fastmail, Proton, iCloud, … all route the base);
//!   * **Gmail dot-blindness** — `j.doe@gmail.com` → `jdoe@gmail.com` (Gmail
//!     ignores `.` in the local-part);
//!   * **`googlemail.com` ≡ `gmail.com`** — the legacy domain is an alias.
//!
//! This directly serves cross-correlation: when breach corpora, search
//! results, and social profiles surface the same Gmail mailbox written three
//! different ways, the shared canonical address is one entity whose
//! corroboration accumulates, instead of three weak singletons. The canonical
//! is a proven-equivalent address (not a guess), so it is emitted *above* the
//! expansion floor — a `--depth 1+` scan pivots the whole email pipeline onto
//! it. Emits nothing when the seed is already canonical (no fragment to merge).

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::canonical::canonical_email_mailbox;

const SRC: &str = "email_canonical";

/// Confidence of the canonical address. High — the normalisation is a
/// documented routing equivalence (Gmail dot-blindness / `+tag`
/// subaddressing), not a heuristic guess — and deliberately above the confidence::MEDIUM
/// expansion floor so the canonical mailbox is pivoted on at depth.
const CANON_CONF: f64 = confidence::HIGH_PLUSPLUS;

pub struct EmailCanonical;

/// Compute the canonical mailbox form of `email`, or `None` when the address is
/// unparseable, has a domain with no dot (`user@localhost` is never a real
/// Internet mailbox), or is already canonical (nothing new to emit).
///
/// The Gmail-dot/`+tag` folding itself is
/// [`canonical_email_mailbox`] — the same rule
/// [`crate::core::resolve`]'s merge-suggestion pass applies to existing
/// entities, so the two can never disagree on what counts as one mailbox. This
/// wrapper adds only the two rules specific to *emitting a new entity*: reject
/// a domain that cannot be a real Internet mailbox, and emit nothing when the
/// seed was already canonical.
fn canonicalise(email: &str) -> Option<String> {
    let lower = email.trim().to_lowercase();
    let (_, domain) = lower.split_once('@')?;
    if !domain.contains('.') {
        return None;
    }
    let canon = canonical_email_mailbox(&lower)?;
    (canon != lower).then_some(canon)
}

#[async_trait]
impl Module for EmailCanonical {
    fn name(&self) -> &'static str {
        "email_canonical"
    }

    fn description(&self) -> &'static str {
        "Email canonicalisation — normalises to the canonical mailbox (Gmail dots, +tag subaddressing) so fragmented identities merge"
    }

    fn priority(&self) -> u8 {
        95
    }

    fn is_passive(&self) -> bool {
        true
    }

    /// Pure transform of data already in the graph — no observation of its
    /// own, so its evidence never counts as a corroborating source (see
    /// `Module::is_derivation` / `ENRICHMENT_ONLY_SOURCES`).
    fn is_derivation(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        // Purely offline, no network (is_passive=true): it accepts/produces only Email entities and
        // applies string-level canonicalization (Gmail dot-blindness, +tag stripping,
        // googlemail.com alias) to merge email-address variants into one identity — squarely and
        // exclusively Gather Victim Identity Information: Email Addresses, with no
        // DNS/WHOIS/domain/host behavior to justify broadening.
        ModuleCategory::Email
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        if let Some(canon) = canonicalise(&target.value) {
            let mut e = Entity::new(EntityKind::Email, &canon, CANON_CONF, &ctx.scan_id);
            e.tag("derived");
            e.tag("canonical");
            e.add_evidence(
                Evidence::new(SRC, format!("Canonical mailbox of {}", target.value))
                    .with_attr("source_email", &target.value)
                    .with_attr("derivation", "canonical_mailbox"),
            );
            result.push(e);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
