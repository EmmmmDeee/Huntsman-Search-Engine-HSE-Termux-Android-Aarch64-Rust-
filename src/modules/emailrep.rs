//! EmailRep.io — email reputation and breach intelligence. Free, no key
//! required for basic lookups (rate-limited). Key-gated for full access.
//!
//! Endpoint: `GET https://emailrep.io/{email}`
//! Auth:     optional `Key: <HUNTSMAN_EMAILREP_KEY>` header.
//!
//! Returns reputation score, breach exposure, profile metadata (social
//! media presence, deliverability, domain age), and risk indicators
//! (disposable, free-provider, spam-trap, etc.). Fills the SpiderFoot
//! `sfp_emailrep` gap.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

#[derive(Deserialize)]
#[allow(dead_code)]
struct Resp {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    reputation: Option<String>,
    #[serde(default)]
    suspicious: Option<bool>,
    #[serde(default)]
    references: Option<u32>,
    #[serde(default)]
    details: Option<Details>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct Details {
    #[serde(default)]
    blacklisted: Option<bool>,
    #[serde(default)]
    malicious_activity: Option<bool>,
    #[serde(default)]
    credentials_leaked: Option<bool>,
    #[serde(default)]
    data_breach: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    free_provider: Option<bool>,
    #[serde(default)]
    spam: Option<bool>,
    #[serde(default)]
    deliverable: Option<bool>,
    #[serde(default)]
    domain_exists: Option<bool>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    days_since_domain_creation: Option<i64>,
}

pub struct EmailRep;

#[async_trait]
impl Module for EmailRep {
    fn name(&self) -> &'static str {
        "emailrep"
    }
    fn priority(&self) -> u8 {
        125
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let email = target.value.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://emailrep.io/{}",
            crate::util::http::urlencode(&email)
        );
        let mut req = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .header("User-Agent", "huntsman-search-engine");
        if let Some(key) = ctx.key_opt("HUNTSMAN_EMAILREP_KEY") {
            req = req.header("Key", key);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::module("emailrep", e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 429 {
            return Err(Error::module(
                "emailrep",
                "rate limited (add HUNTSMAN_EMAILREP_KEY for higher limits)",
            ));
        }
        if !status.is_success() {
            return Err(Error::module(
                "emailrep",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: Resp = resp
            .json()
            .await
            .map_err(|e| Error::module("emailrep", e.to_string()))?;

        let mut entity = Entity::new(EntityKind::Email, &email, 0.85, &ctx.scan_id);
        entity.tag("emailrep");

        let reputation = body.reputation.as_deref().unwrap_or("none");
        entity.tag(format!("reputation:{reputation}"));

        if body.suspicious == Some(true) {
            entity.tag("suspicious");
        }

        let details = body.details.as_ref();
        if details.and_then(|d| d.blacklisted) == Some(true) {
            entity.tag("blacklisted");
        }
        if details.and_then(|d| d.malicious_activity) == Some(true) {
            entity.tag("malicious");
        }
        if details.and_then(|d| d.credentials_leaked) == Some(true) {
            entity.tag("credentials-leaked");
        }
        if details.and_then(|d| d.data_breach) == Some(true) {
            entity.tag("breach");
        }
        if details.and_then(|d| d.disposable) == Some(true) {
            entity.tag("disposable");
        }
        if details.and_then(|d| d.spam) == Some(true) {
            entity.tag("spam");
        }

        let mut ev = Evidence::new(
            "emailrep",
            format!("EmailRep: {email} reputation={reputation}"),
        )
        .with_attr("reputation", reputation);

        if let Some(refs) = body.references {
            ev = ev.with_attr("references", refs.to_string());
        }
        if let Some(d) = details {
            if let Some(del) = d.deliverable {
                ev = ev.with_attr("deliverable", del.to_string());
            }
            if let Some(ls) = d.last_seen.as_deref() {
                ev = ev.with_attr("last_seen", ls);
            }
            if let Some(age) = d.days_since_domain_creation {
                ev = ev.with_attr("domain_age_days", age.to_string());
            }
            if !d.profiles.is_empty() {
                ev = ev.with_attr("profiles", d.profiles.join(","));
                for p in &d.profiles {
                    entity.tag(format!("profile:{p}"));
                }
            }
        }

        entity.add_evidence(ev);
        let mut result = ModuleResult::new();
        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_email_only() {
        let m = EmailRep;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    }
}
