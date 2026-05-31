//! `name_intel` — NAMINT-style name intelligence.
//!
//! Given a `FullName` seed this module derives, with **no network calls**:
//!
//!   * plausible **usernames** (→ `username_search`, `social_probe`,
//!     `github_user`, `keybase`),
//!   * speculative **emails** across a provider set (→ the whole email pivot
//!     pipeline: `hibp`, `hunter_io`, `epieos`, `emailrep`, `disposable_check`,
//!     `email_parse`, …), each carrying its **Gravatar** avatar URL,
//!   * ready-to-click **search-query pivots** (Google/Bing/DuckDuckGo/Yandex
//!     dorks + LinkedIn/Facebook/X/Instagram/TikTok/GitHub/WhatsMyName/Epieos).
//!
//! Permutations are emitted as low-confidence *candidate* entities: they enrich
//! the graph, feed the correlator's identity-surface rules, and are available
//! for expansion — but sit below the default `min_expand_confidence` (0.50) so a
//! `--depth` scan never auto-spends API budget on guesses. To pivot on them,
//! lower the floor (e.g. `--min-expand-confidence 0.40 --depth 1`).
//!
//! Priority 97 so derived identifiers exist during the seed round. Pure string
//! transformation + one MD5 — no C deps, ideal for Termux/aarch64.

mod permute;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "name_intel";

pub struct NameIntel;

#[async_trait]
impl Module for NameIntel {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "NAMINT-style name intelligence: derive usernames, emails, Gravatars and \
         platform search pivots from a full name (offline)"
    }
    fn priority(&self) -> u8 {
        97
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName)
    }
    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Username, EntityKind::Email, EntityKind::Url]
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let Some(name) = permute::parse(&target.value) else {
            return Ok(result);
        };
        let sid = &ctx.scan_id;

        // ── Usernames ───────────────────────────────────────────────────────
        for u in permute::usernames(&name) {
            let mut e = Entity::new(EntityKind::Username, &u.handle, u.weight, sid);
            e.tag("derived");
            e.tag("name-derived");
            e.add_evidence(
                Evidence::new(SRC, format!("Username '{}' derived from name", u.handle))
                    .with_attr("source_name", &target.value),
            );
            result.push(e);
        }

        // ── Emails (+ Gravatar) ─────────────────────────────────────────────
        let domains = permute::email_domains();
        let emails = permute::emails(&name, &domains);
        for addr in &emails {
            let mut e = Entity::new(EntityKind::Email, addr, permute::EMAIL_CONF, sid);
            e.tag("derived");
            e.tag("name-derived");
            e.tag("permuted");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Speculative email '{addr}' permuted from name"),
                )
                .with_attr("source_name", &target.value)
                .with_attr("gravatar", permute::gravatar_url(addr)),
            );
            result.push(e);
        }

        // ── Search-query / people-search pivots ─────────────────────────────
        for piv in permute::pivots(&name, emails.first().map(String::as_str)) {
            let mut e = Entity::new(EntityKind::Url, &piv.url, permute::PIVOT_CONF, sid);
            e.tag("search-pivot");
            e.tag("name-intel");
            e.tag("passive");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("{} pivot for '{}'", piv.platform, name.display_full()),
                )
                .with_attr("platform", piv.platform)
                .with_attr("source_name", &target.value),
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

    fn ctx(scan: &str) -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: scan.into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        }
    }

    #[tokio::test]
    async fn metadata_and_acceptance() {
        let m = NameIntel;
        assert_eq!(m.name(), "name_intel");
        assert!(m.is_passive());
        assert!(!m.description().is_empty());
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Meyers")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        // Default consumes() (probes accepts) must report exactly FullName so
        // the dispatch index serves it — and only it.
        assert_eq!(m.consumes(), vec![TargetKind::FullName]);
    }

    #[tokio::test]
    async fn emits_usernames_emails_and_pivots() {
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Jordan Leigh Meyers 1987"),
                &ctx("scan-x"),
            )
            .await
            .unwrap();

        let mut usernames = 0;
        let mut emails = 0;
        let mut pivots = 0;
        let mut gravatar_seen = false;
        for e in &out.entities {
            match e.kind {
                EntityKind::Username => {
                    usernames += 1;
                    assert!(e.has_tag("name-derived"));
                }
                EntityKind::Email => {
                    emails += 1;
                    assert!(e.has_tag("permuted"));
                    assert!(e.value.contains('@'));
                    if e.evidence
                        .iter()
                        .any(|ev| ev.attributes.contains_key("gravatar"))
                    {
                        gravatar_seen = true;
                    }
                }
                EntityKind::Url => {
                    pivots += 1;
                    assert!(e.has_tag("search-pivot"));
                    assert!(e.raw_value.starts_with("https://"));
                }
                ref other => panic!("unexpected kind {other}"),
            }
        }
        assert!(usernames > 5, "expected several usernames, got {usernames}");
        assert!(emails > 0, "expected emails, got {emails}");
        assert!(pivots > 5, "expected several pivots, got {pivots}");
        assert!(gravatar_seen, "emails must carry a gravatar attribute");
    }

    #[tokio::test]
    async fn single_token_name_yields_nothing() {
        let m = NameIntel;
        let out = m
            .process(
                &Target::new(TargetKind::FullName, "Madonna"),
                &ctx("scan-y"),
            )
            .await
            .unwrap();
        assert!(out.entities.is_empty());
    }
}
