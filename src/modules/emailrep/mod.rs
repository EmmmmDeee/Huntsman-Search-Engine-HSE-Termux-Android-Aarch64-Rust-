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

#[derive(Deserialize)]
pub(super) struct RepDetails {
    #[serde(default)]
    pub(super) blacklisted: Option<bool>,
    #[serde(default)]
    pub(super) malicious_activity: Option<bool>,
    #[serde(default)]
    pub(super) credential_leaked: Option<bool>,
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
        "Email reputation scoring — breach exposure, blacklists, and social profiles"
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
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

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

/// Enrich the email target with its EmailRep reputation report. **Pure** (no
/// network/IO) so every flag → tag/attribute decision is unit-tested directly.
///
/// A `true` boolean flag becomes both an evidence attribute and a pivotable tag;
/// `domain_exists` is the inverse — a `false` (the domain doesn't resolve) is
/// the actionable, suspicious case and is what gets tagged.
pub(super) fn build_email_entity(target: &Target, body: &RepResp, scan_id: &str) -> Entity {
    let email = target.value.trim();
    let mut entity = target.to_entity(0.85, scan_id);
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
            (d.credential_leaked, "credential_leaked", "breach"),
            (d.data_breach, "data_breach", "breach"),
            (d.blacklisted, "blacklisted", "blacklisted"),
            (d.malicious_activity, "malicious_activity", "malicious"),
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
