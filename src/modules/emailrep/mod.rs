//! EmailRep — email reputation, breach history, and social media presence.
//!
//! Endpoint: `GET https://emailrep.io/{email_address}`
//! Auth:     `Key` header. Key-gated (`HUNTSMAN_EMAILREP_KEY`).
//!
//! Rate limit: 2 req/hour on the free tier. Returns domain reputation, breach
//! exposure, fraud/abuse flags, and social-media presence. Every reputation
//! field is surfaced as an evidence attribute, and the *actionable* ones
//! (breach, blacklist, malicious/spam, disposable/new/non-existent domain) also
//! become tags so downstream rules and the UI can pivot on them.
//!
//! The response → entity mapping lives in the pure [`build_email_entity`] so it
//! is unit-tested without a live API; `process` owns only auth/transport.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

#[cfg(test)]
mod tests;

pub(super) const KEY_ENV: &str = "HUNTSMAN_EMAILREP_KEY";
pub(super) const SRC: &str = "emailrep";

pub struct EmailRep;

#[derive(Deserialize)]
pub(super) struct RepResp {
    #[serde(default)]
    pub(super) reputation: Option<String>,
    #[serde(default)]
    pub(super) suspicious: Option<bool>,
    #[serde(default)]
    pub(super) references: Option<u64>,
    #[serde(default)]
    pub(super) details: Option<RepDetails>,
}

/// The `details` object, field names exactly as EmailRep sends them — see the
/// vendor's documented response (`sublime-security/emailrep.io` README, whose
/// example is this module's `the_vendors_documented_response_decodes` fixture).
/// Every field is optional, so a misspelt one decodes as absent and says
/// nothing: `credential_leaked` was read for `credentials_leaked`, and every
/// credential leak EmailRep reported was dropped (REQ-EMAILREP-002).
#[derive(Deserialize)]
pub(super) struct RepDetails {
    #[serde(default)]
    pub(super) blacklisted: Option<bool>,
    #[serde(default)]
    pub(super) malicious_activity: Option<bool>,
    #[serde(default)]
    pub(super) malicious_activity_recent: Option<bool>,
    #[serde(default)]
    pub(super) credentials_leaked: Option<bool>,
    #[serde(default)]
    pub(super) credentials_leaked_recent: Option<bool>,
    #[serde(default)]
    pub(super) data_breach: Option<bool>,
    #[serde(default)]
    pub(super) first_seen: Option<String>,
    #[serde(default)]
    pub(super) last_seen: Option<String>,
    #[serde(default)]
    pub(super) domain_exists: Option<bool>,
    #[serde(default)]
    pub(super) domain_reputation: Option<String>,
    #[serde(default)]
    pub(super) new_domain: Option<bool>,
    #[serde(default)]
    pub(super) days_since_domain_creation: Option<u64>,
    #[serde(default)]
    pub(super) free_provider: Option<bool>,
    #[serde(default)]
    pub(super) disposable: Option<bool>,
    #[serde(default)]
    pub(super) deliverable: Option<bool>,
    #[serde(default)]
    pub(super) spam: Option<bool>,
    #[serde(default)]
    pub(super) profiles: Vec<String>,
}

#[async_trait]
impl Module for EmailRep {
    fn name(&self) -> &'static str {
        "emailrep"
    }
    fn description(&self) -> &'static str {
        "Email reputation recon — correlates breach exposure, blacklists, and linked social profiles into a reputation score"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        5_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Beyond the Email default (T1589.002 Email Addresses), EmailRep reports
        // credential-leak / data-breach status (T1589.001 Credentials) and the
        // address's social-media presence (T1593.001 Social Media). Superset of
        // the default — coverage cannot regress.
        &["T1589.002", "T1589.001", "T1593.001"]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;

        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!("https://emailrep.io/{}", urlencode(email));

        let resp = ctx
            .http
            .get(&url)
            .header("Key", key)
            .header("Accept", "application/json")
            .header(
                "User-Agent",
                "huntsman-search-engine (+https://github.com/EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-)",
            )
            .send_tagged(SRC).await?;

        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: RepResp = crate::util::http::json_decode(SRC, resp).await?;

        let mut result = ModuleResult::new();
        result.push(build_email_entity(target, &body, &ctx.scan_id));
        Ok(result)
    }
}

/// Whether the report holds evidence about **this address**, not only its
/// domain. **Pure.** EmailRep's `references` does not qualify: the vendor
/// documents that it "can include reputation sources for the domain", so a
/// mailbox nobody holds at a reputable domain has references. What does
/// qualify: profiles the address is used on, a breach or credential leak it
/// appeared in, behaviour it was observed in (the `*_recent` flags included),
/// or a `first_seen` / `last_seen` date (the vendor writes `never` when there
/// is none).
pub(super) fn report_observes_the_address(body: &RepResp) -> bool {
    // A date the vendor writes when it has one, and `never` when it has not.
    let dated = |d: Option<&str>| {
        d.is_some_and(|d| !d.trim().is_empty() && !d.trim().eq_ignore_ascii_case("never"))
    };
    body.details.as_ref().is_some_and(|d| {
        !d.profiles.is_empty()
            || [
                d.data_breach,
                d.credentials_leaked,
                d.credentials_leaked_recent,
                d.malicious_activity,
                d.malicious_activity_recent,
                d.spam,
                d.blacklisted,
            ]
            .contains(&Some(true))
            || dated(d.first_seen.as_deref())
            || dated(d.last_seen.as_deref())
    })
}

/// The confidence the report earns for the address it re-emits. **Pure.**
///
/// The engine merges by uid and keeps the higher confidence, so a re-emission
/// is a claim that the address is real, made at this rung. At a fixed
/// [`confidence::HIGH_PLUSPLUS_PLUS`] (0.85), every address EmailRep answered
/// for became VERIFIED: an undeliverable one, one on a nonexistent domain, an
/// empty `{}` report (REQ-EMAILREP-001). Now:
/// - a report that observes the address ([`report_observes_the_address`])
///   earns [`confidence::HIGH_PLUS`], which is `hibp`'s rung for an address
///   seen in a breach: a real presence claim, from one third-party source,
///   below VERIFIED until something else corroborates it;
/// - any other report is an annotation, at [`confidence::SPECULATIVE`], below
///   [`crate::selftest::capability_probe::SEED_PRESENT_RUNG`] (the
///   `disposable_check` precedent, REQ-CANARY-003).
pub(super) fn report_confidence(body: &RepResp) -> f64 {
    if report_observes_the_address(body) {
        confidence::HIGH_PLUS
    } else {
        confidence::SPECULATIVE
    }
}

/// Enrich the email target with its EmailRep reputation report. **Pure** (no
/// network/IO) so every flag → tag/attribute decision is unit-tested directly.
///
/// A `true` boolean flag becomes both an evidence attribute and a pivotable tag;
/// `domain_exists` is the inverse — a `false` (the domain doesn't resolve) is
/// the actionable, suspicious case and is what gets tagged. The confidence is
/// [`report_confidence`]'s.
pub(super) fn build_email_entity(target: &Target, body: &RepResp, scan_id: &str) -> Entity {
    let email = target.value.trim();
    let mut entity = target.to_entity(report_confidence(body), scan_id);
    entity.tag("emailrep");

    let mut ev = Evidence::new(SRC, format!("EmailRep report for {email}"));
    if let Some(rep) = body.reputation.as_deref() {
        ev = ev.with_attr("reputation", rep);
        entity.tag(format!("reputation:{rep}"));
    }
    if let Some(s) = body.suspicious {
        ev = ev.with_attr("suspicious", s.to_string());
        if s {
            entity.tag("suspicious");
        }
    }
    if let Some(refs) = body.references {
        ev = ev.with_attr("references", refs.to_string());
    }

    if let Some(d) = &body.details {
        // `(field == Some(true))` flags → attribute + a pivotable tag.
        for (flag, attr, tag) in [
            (
                d.credentials_leaked,
                "credentials_leaked",
                crate::core::tags::BREACH,
            ),
            (d.data_breach, "data_breach", crate::core::tags::BREACH),
            (d.blacklisted, "blacklisted", "blacklisted"),
            (
                d.malicious_activity,
                "malicious_activity",
                crate::core::tags::MALICIOUS,
            ),
            (d.spam, "spam", "spam-source"),
            (d.disposable, "disposable", "disposable"),
            (d.free_provider, "free_provider", "freemail"),
            (d.new_domain, "new_domain", "new-domain"),
        ] {
            if flag == Some(true) {
                ev = ev.with_attr(attr, "true");
                entity.tag(tag);
            }
        }

        // The inverse case: a domain that does NOT exist is the suspicious one.
        if let Some(exists) = d.domain_exists {
            ev = ev.with_attr("domain_exists", exists.to_string());
            if !exists {
                entity.tag("domain-nonexistent");
            }
        }

        // Soft / informational attributes (no tag).
        for (flag, attr) in [
            (d.credentials_leaked_recent, "credentials_leaked_recent"),
            (d.malicious_activity_recent, "malicious_activity_recent"),
        ] {
            if flag == Some(true) {
                ev = ev.with_attr(attr, "true");
            }
        }
        if let Some(deliverable) = d.deliverable {
            ev = ev.with_attr("deliverable", deliverable.to_string());
        }
        if let Some(fs) = d.first_seen.as_deref() {
            ev = ev.with_attr("first_seen", fs);
        }
        if let Some(ls) = d.last_seen.as_deref() {
            ev = ev.with_attr("last_seen", ls);
        }
        if let Some(dr) = d.domain_reputation.as_deref() {
            ev = ev.with_attr("domain_reputation", dr);
        }
        if let Some(days) = d.days_since_domain_creation {
            ev = ev.with_attr("domain_age_days", days.to_string());
        }
        if !d.profiles.is_empty() {
            // Full-fidelity policy: surface EVERY discovered profile, never a
            // capped subset — the profile names are a result, not a preview.
            let csv = d
                .profiles
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            ev = ev
                .with_attr("profiles", csv)
                .with_attr("profile_count", d.profiles.len().to_string());
            // Tag each confirmed platform so graph rules can pivot on them
            // without needing to parse the CSV attribute.
            for platform in &d.profiles {
                let p = platform.trim().to_lowercase();
                if !p.is_empty() {
                    entity.tag(format!("has:{p}"));
                }
            }
        }
    }

    entity.add_evidence(ev);
    entity
}
