//! Have I Been Pwned (HIBP) — the canonical breach lookup by Troy Hunt.
//! Key-gated ($3.50/mo). The single most authoritative email-breach
//! source in OSINT — complements HudsonRock (stealer logs) and
//! XposedOrNot (free but less comprehensive).
//!
//! Endpoint: `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false`
//! Auth:     `hibp-api-key: {HUNTSMAN_HIBP_KEY}` header.
//!
//! Returns an array of breach objects with Name, Domain, BreachDate,
//! DataClasses, and IsVerified fields. We surface names + dates +
//! data classes in evidence, tag `breach` for the correlator, and
//! push the breach count into `platforms_count` for AU-001.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::error_snippet;

const KEY_ENV: &str = "HUNTSMAN_HIBP_KEY";

#[derive(Deserialize)]
#[allow(dead_code)]
struct Breach {
    #[serde(default, rename = "Name")]
    name: Option<String>,
    #[serde(default, rename = "Domain")]
    domain: Option<String>,
    #[serde(default, rename = "BreachDate")]
    breach_date: Option<String>,
    #[serde(default, rename = "DataClasses")]
    data_classes: Vec<String>,
    #[serde(default, rename = "IsVerified")]
    is_verified: Option<bool>,
    #[serde(default, rename = "PwnCount")]
    pwn_count: Option<u64>,
}

pub struct HaveIBeenPwned;

#[async_trait]
impl Module for HaveIBeenPwned {
    fn name(&self) -> &'static str {
        "haveibeenpwned"
    }
    fn priority(&self) -> u8 {
        135
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;
        let email = target.value.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{}?truncateResponse=false",
            crate::util::http::urlencode(&email)
        );
        let resp = ctx
            .http
            .get(&url)
            .header("hibp-api-key", key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module("haveibeenpwned", e.to_string()))?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(ModuleResult::new());
        }
        if status == 401 {
            return Err(Error::module("haveibeenpwned", "invalid API key"));
        }
        if status == 429 {
            return Err(Error::module(
                "haveibeenpwned",
                "rate limited — wait and retry",
            ));
        }
        if !(200..=299).contains(&status) {
            return Err(Error::module(
                "haveibeenpwned",
                format!("HTTP {status}: {}", error_snippet(resp).await),
            ));
        }

        let breaches: Vec<Breach> = resp
            .json()
            .await
            .map_err(|e| Error::module("haveibeenpwned", e.to_string()))?;

        if breaches.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut entity = Entity::new(EntityKind::Email, &email, 0.95, &ctx.scan_id);
        entity.tag("breach");
        entity.tag("haveibeenpwned");

        let verified_count = breaches
            .iter()
            .filter(|b| b.is_verified == Some(true))
            .count();
        let breach_names: Vec<&str> = breaches
            .iter()
            .filter_map(|b| b.name.as_deref())
            .take(20)
            .collect();
        let latest_date = breaches
            .iter()
            .filter_map(|b| b.breach_date.as_deref())
            .max();

        let mut all_data_classes: std::collections::BTreeSet<&str> =
            std::collections::BTreeSet::new();
        for b in &breaches {
            for dc in &b.data_classes {
                all_data_classes.insert(dc.as_str());
            }
        }
        if all_data_classes.contains("Passwords") {
            entity.tag("credentials-leaked");
        }

        let mut ev = Evidence::new(
            "haveibeenpwned",
            format!(
                "HIBP: {email} found in {} breach(es) ({verified_count} verified)",
                breaches.len()
            ),
        )
        .with_attr("breach_count", breaches.len().to_string())
        .with_attr("verified_count", verified_count.to_string())
        .with_attr("breaches", breach_names.join(", "));

        if let Some(d) = latest_date {
            ev = ev.with_attr("latest_breach_date", d);
        }
        if !all_data_classes.is_empty() {
            let dc_list: Vec<&str> = all_data_classes.into_iter().take(15).collect();
            ev = ev.with_attr("data_classes", dc_list.join(", "));
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
    fn accepts_email() {
        assert!(HaveIBeenPwned.accepts(&Target::new(TargetKind::Email, "x@y")));
        assert!(!HaveIBeenPwned.accepts(&Target::new(TargetKind::Domain, "y")));
    }
    #[test]
    fn cost_is_paid() {
        assert!(matches!(HaveIBeenPwned.cost(), ModuleCost::Paid));
    }
}
