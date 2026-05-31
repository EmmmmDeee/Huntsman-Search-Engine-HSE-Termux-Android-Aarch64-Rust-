//! EmailRep — email reputation, breach history, and social media presence.
//!
//! Endpoint: `GET https://emailrep.io/{email_address}`
//! Auth:     `Key` header. Key-gated (`HUNTSMAN_EMAILREP_KEY`).
//!
//! Rate limit: 2 req/hour on the free tier. Returns domain reputation,
//! breach exposure, social media presence flags, and risk scoring.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::Evidence,
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{error_snippet, urlencode};

const KEY_ENV: &str = "HUNTSMAN_EMAILREP_KEY";
const SRC: &str = "emailrep";

pub struct EmailRep;

#[derive(Deserialize)]
struct RepResp {
    #[allow(dead_code)]
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    reputation: Option<String>,
    #[serde(default)]
    suspicious: Option<bool>,
    #[serde(default)]
    references: Option<u64>,
    #[serde(default)]
    details: Option<RepDetails>,
}

#[derive(Deserialize)]
struct RepDetails {
    #[serde(default)]
    blacklisted: Option<bool>,
    #[serde(default)]
    malicious_activity: Option<bool>,
    #[serde(default)]
    credential_leaked: Option<bool>,
    #[serde(default)]
    data_breach: Option<bool>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    domain_exists: Option<bool>,
    #[serde(default)]
    domain_reputation: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    new_domain: Option<bool>,
    #[serde(default)]
    days_since_domain_creation: Option<u64>,
    #[serde(default)]
    free_provider: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    deliverable: Option<bool>,
    #[allow(dead_code)]
    #[serde(default)]
    spam: Option<bool>,
    #[serde(default)]
    profiles: Vec<String>,
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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            let code = status.as_u16();
            if code == 429 || code == 401 || code == 403 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let body: RepResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut result = ModuleResult::new();
        let mut entity = target.to_entity(0.85, &ctx.scan_id);
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

        if let Some(details) = &body.details {
            if details.credential_leaked == Some(true) {
                entity.tag("breach");
                ev = ev.with_attr("credential_leaked", "true");
            }
            if details.data_breach == Some(true) {
                entity.tag("breach");
                ev = ev.with_attr("data_breach", "true");
            }
            if details.blacklisted == Some(true) {
                entity.tag("blacklisted");
                ev = ev.with_attr("blacklisted", "true");
            }
            if details.malicious_activity == Some(true) {
                entity.tag("malicious");
                ev = ev.with_attr("malicious_activity", "true");
            }
            if details.disposable == Some(true) {
                entity.tag("disposable");
                ev = ev.with_attr("disposable", "true");
            }
            if details.free_provider == Some(true) {
                entity.tag("freemail");
                ev = ev.with_attr("free_provider", "true");
            }
            if let Some(d) = details.deliverable {
                ev = ev.with_attr("deliverable", d.to_string());
            }
            if let Some(fs) = details.first_seen.as_deref() {
                ev = ev.with_attr("first_seen", fs);
            }
            if let Some(ls) = details.last_seen.as_deref() {
                ev = ev.with_attr("last_seen", ls);
            }
            if let Some(dr) = details.domain_reputation.as_deref() {
                ev = ev.with_attr("domain_reputation", dr);
            }
            if let Some(days) = details.days_since_domain_creation {
                ev = ev.with_attr("domain_age_days", days.to_string());
            }
            if !details.profiles.is_empty() {
                let profiles_csv = details
                    .profiles
                    .iter()
                    .take(20)
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(",");
                ev = ev
                    .with_attr("profiles", profiles_csv)
                    .with_attr("profile_count", details.profiles.len().to_string());
            }
        }

        entity.add_evidence(ev);
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
        assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::Phone, "+1")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(EmailRep.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(EmailRep.name(), "emailrep");
        assert_eq!(EmailRep.priority(), 90);
        assert_eq!(EmailRep.max_timeout_ms(), 5_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "email": "test@example.com",
            "reputation": "high",
            "suspicious": false,
            "references": 15,
            "details": {
                "blacklisted": false,
                "malicious_activity": false,
                "credential_leaked": true,
                "data_breach": true,
                "first_seen": "2010-01-01",
                "last_seen": "2024-06-01",
                "domain_exists": true,
                "domain_reputation": "high",
                "free_provider": false,
                "disposable": false,
                "deliverable": true,
                "profiles": ["linkedin", "twitter", "github"]
            }
        }"#;
        let r: RepResp = serde_json::from_str(raw).unwrap();
        assert_eq!(r.reputation.as_deref(), Some("high"));
        assert_eq!(r.suspicious, Some(false));
        let d = r.details.unwrap();
        assert_eq!(d.credential_leaked, Some(true));
        assert_eq!(d.profiles.len(), 3);
    }
}
