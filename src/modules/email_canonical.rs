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
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "email_canonical";

/// Confidence of the canonical address. High — the normalisation is a
/// documented routing equivalence (Gmail dot-blindness / `+tag`
/// subaddressing), not a heuristic guess — and deliberately above the 0.50
/// expansion floor so the canonical mailbox is pivoted on at depth.
const CANON_CONF: f64 = 0.80;

pub struct EmailCanonical;

/// Compute the canonical mailbox form of `email`, or `None` when the address is
/// unparseable or already canonical (nothing new to emit).
fn canonicalise(email: &str) -> Option<String> {
    let lower = email.trim().to_ascii_lowercase();
    let (local, domain) = lower.split_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return None;
    }

    // Strip `+tag` subaddressing — the base mailbox is what matters for
    // identity. Widely supported (Gmail, Microsoft, Fastmail, Proton, iCloud).
    let base = local.split('+').next().unwrap_or(local);

    // Gmail (and its googlemail.com alias) ignores dots in the local-part.
    let (local_canon, domain_canon) = if domain == "gmail.com" || domain == "googlemail.com" {
        (base.replace('.', ""), "gmail.com")
    } else {
        (base.to_string(), domain)
    };

    if local_canon.is_empty() {
        return None;
    }
    let canon = format!("{local_canon}@{domain_canon}");
    (canon != lower).then_some(canon)
}

#[async_trait]
impl Module for EmailCanonical {
    fn name(&self) -> &'static str {
        "email_canonical"
    }

    fn description(&self) -> &'static str {
        "Normalise an email to its canonical mailbox (Gmail dots, +tag subaddressing) so identity fragments merge"
    }

    fn priority(&self) -> u8 {
        95
    }

    fn is_passive(&self) -> bool {
        true
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
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
    use super::*;
    use std::collections::HashMap;

    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    #[test]
    fn gmail_dots_are_stripped() {
        assert_eq!(
            canonicalise("john.doe@gmail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn gmail_plus_tag_and_dots_stripped_together() {
        assert_eq!(
            canonicalise("john.doe+newsletter@gmail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn googlemail_alias_folds_to_gmail() {
        assert_eq!(
            canonicalise("johndoe@googlemail.com").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn case_is_normalised() {
        assert_eq!(
            canonicalise("JOHN.DOE@GMAIL.COM").as_deref(),
            Some("johndoe@gmail.com")
        );
    }

    #[test]
    fn plus_tag_stripped_for_non_gmail_provider() {
        // +tag subaddressing applies broadly; dots are NOT stripped off-Gmail.
        assert_eq!(
            canonicalise("jane+promo@outlook.com").as_deref(),
            Some("jane@outlook.com")
        );
        // dots are significant for non-Gmail → no change → None
        assert_eq!(canonicalise("jane.smith@outlook.com"), None);
    }

    #[test]
    fn already_canonical_yields_none() {
        assert_eq!(canonicalise("johndoe@gmail.com"), None);
        assert_eq!(canonicalise("jane@outlook.com"), None);
    }

    #[test]
    fn malformed_addresses_yield_none() {
        assert_eq!(canonicalise("notanemail"), None);
        assert_eq!(canonicalise("@gmail.com"), None);
        assert_eq!(canonicalise("user@localhost"), None); // no dot in domain
        assert_eq!(canonicalise("+tag@gmail.com"), None); // empty base local
    }

    #[tokio::test]
    async fn process_emits_canonical_email_above_floor() {
        let t = Target::new(TargetKind::Email, "j.doe+work@googlemail.com");
        let r = EmailCanonical.process(&t, &ctx()).await.unwrap();
        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Email);
        assert_eq!(e.value, "jdoe@gmail.com");
        assert!(
            e.confidence >= 0.50,
            "canonical mailbox should pivot at depth"
        );
        assert!(e.has_tag("canonical"));
        assert_eq!(e.evidence[0].source, SRC);
    }

    #[tokio::test]
    async fn process_emits_nothing_when_already_canonical() {
        let t = Target::new(TargetKind::Email, "jdoe@gmail.com");
        let r = EmailCanonical.process(&t, &ctx()).await.unwrap();
        assert!(r.entities.is_empty());
    }

    #[test]
    fn accepts_email_only_and_is_passive() {
        assert!(EmailCanonical.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!EmailCanonical.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(EmailCanonical.is_passive());
        assert_eq!(EmailCanonical.category(), ModuleCategory::Email);
    }
}
