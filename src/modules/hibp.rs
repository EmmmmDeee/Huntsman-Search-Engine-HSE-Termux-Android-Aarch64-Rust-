//! Have I Been Pwned (HIBP) v3 API — definitive breach + paste oracle.
//!
//! Endpoints:
//!   GET /api/v3/breachedaccount/{email}  — breaches containing this email
//!   GET /api/v3/pasteaccount/{email}     — pastes containing this email
//!   GET /api/v3/breaches?domain={domain} — breaches affecting a domain
//!
//! Rate limit: 10 req/min on the basic subscription. The module
//! throttles internally with 6.5s inter-request delay to stay within
//! budget across all queries per process() call.
//!
//! Key: hardcoded for testing, overridden by HUNTSMAN_HIBP_KEY env var.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{error_snippet, urlencode};

const SRC: &str = "hibp";
const KEY_ENV: &str = "HUNTSMAN_HIBP_KEY";
const HARDCODED_KEY: &str = "42587552dce6424a87312941c8a2c3c5";
const BASE_URL: &str = "https://haveibeenpwned.com/api/v3";

const RATE_LIMIT_DELAY: Duration = Duration::from_millis(6500);

fn resolve_key(ctx_key: Option<&str>) -> &str {
    match ctx_key {
        Some(k) if !k.is_empty() => k,
        _ => HARDCODED_KEY,
    }
}

// ── API response types ──────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct Breach {
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    breach_date: Option<String>,
    #[serde(default)]
    added_date: Option<String>,
    #[serde(default)]
    modified_date: Option<String>,
    #[serde(default)]
    pwn_count: Option<u64>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    is_verified: Option<bool>,
    #[serde(default)]
    is_fabricated: Option<bool>,
    #[serde(default)]
    is_sensitive: Option<bool>,
    #[serde(default)]
    is_retired: Option<bool>,
    #[serde(default)]
    is_spam_list: Option<bool>,
    #[serde(default)]
    is_subscription_free: Option<bool>,
    #[serde(default)]
    logo_path: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct Paste {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    email_count: Option<u64>,
}

// ── Module impl ─────────────────────────────────────────────────────

pub struct Hibp;

#[async_trait]
impl Module for Hibp {
    fn name(&self) -> &'static str {
        "hibp"
    }

    fn description(&self) -> &'static str {
        "Have I Been Pwned — definitive breach + paste oracle (API v3)"
    }

    fn priority(&self) -> u8 {
        120
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Domain)
    }

    fn max_timeout_ms(&self) -> u64 {
        60_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = resolve_key(ctx.key_opt(KEY_ENV));
        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::Email => {
                self.query_breached_account(key, target, ctx, &mut result)
                    .await?;
                if !ctx.cancel.is_cancelled() {
                    tokio::time::sleep(RATE_LIMIT_DELAY).await;
                    self.query_paste_account(key, target, ctx, &mut result)
                        .await?;
                }
            }
            TargetKind::Domain => {
                self.query_domain_breaches(key, target, ctx, &mut result)
                    .await?;
            }
            _ => {}
        }

        Ok(result)
    }
}

impl Hibp {
    async fn api_get<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        url: &str,
        ctx: &ModuleContext,
    ) -> Result<Option<T>> {
        let mut retries = 0u8;
        loop {
            let resp = ctx
                .http
                .get(url)
                .header("hibp-api-key", key)
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(15))
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;

            let status = resp.status().as_u16();
            match status {
                200 => {
                    let data = resp
                        .json::<T>()
                        .await
                        .map_err(|e| Error::module(SRC, format!("JSON parse: {e}")))?;
                    return Ok(Some(data));
                }
                404 => return Ok(None),
                401 | 403 => {
                    ctx.report_key_exhausted(SRC, key, status);
                    return Err(Error::module(
                        SRC,
                        format!("HTTP {status}: invalid or expired API key"),
                    ));
                }
                429 if retries < 3 => {
                    let retry_secs = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(7);
                    retries += 1;
                    tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                    continue;
                }
                429 => {
                    ctx.report_key_exhausted(SRC, key, status);
                    let snippet = error_snippet(resp).await;
                    return Err(Error::module(
                        SRC,
                        format!("HTTP 429 rate-limited after {retries} retries: {snippet}"),
                    ));
                }
                _ => {
                    let snippet = error_snippet(resp).await;
                    return Err(Error::module(SRC, format!("HTTP {status}: {snippet}")));
                }
            }
        }
    }

    /// GET /api/v3/breachedaccount/{email}?truncateResponse=false
    async fn query_breached_account(
        &self,
        key: &str,
        target: &Target,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let email = urlencode(target.value.trim());
        let url = format!("{BASE_URL}/breachedaccount/{email}?truncateResponse=false");
        let breaches: Vec<Breach> = match self.api_get(key, &url, ctx).await? {
            Some(b) => b,
            None => return Ok(()),
        };

        if breaches.is_empty() {
            return Ok(());
        }

        let verified_count = breaches
            .iter()
            .filter(|b| b.is_verified == Some(true))
            .count();
        let total = breaches.len();
        let breach_names: Vec<&str> = breaches.iter().map(|b| b.name.as_str()).collect();
        let top_names: String = breach_names
            .iter()
            .take(10)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");

        let base_conf = match verified_count {
            0 => 0.65,
            1..=2 => 0.80,
            3..=5 => 0.88,
            _ => 0.95,
        };

        let mut email_ent = Entity::new(
            EntityKind::Email,
            target.value.trim(),
            base_conf,
            &ctx.scan_id,
        );
        email_ent.tag(tags::BREACH);
        email_ent.tag("hibp");
        if verified_count >= 3 {
            email_ent.tag(tags::HIGH_EXPOSURE);
        }
        email_ent.corroboration = verified_count.max(1) as u32;
        email_ent.add_evidence(
            Evidence::new(
                SRC,
                format!("Found in {total} breach(es) ({verified_count} verified): {top_names}"),
            )
            .with_attr("breach_count", total.to_string())
            .with_attr("verified_count", verified_count.to_string())
            .with_attr("breach_names", breach_names.join(", ")),
        );
        result.push(email_ent);

        // Extract data classes to tag risk level
        let mut has_passwords = false;
        let mut has_phone = false;
        let mut has_physical = false;

        for breach in &breaches {
            for dc in &breach.data_classes {
                let dcl = dc.to_lowercase();
                if dcl.contains("password") {
                    has_passwords = true;
                }
                if dcl.contains("phone") {
                    has_phone = true;
                }
                if dcl.contains("physical") || dcl.contains("address") || dcl.contains("location") {
                    has_physical = true;
                }
            }

            // Extract associated domains as expansion seeds
            if let Some(domain) = &breach.domain
                && !domain.is_empty()
                && domain.contains('.')
            {
                let mut de = Entity::new(EntityKind::Domain, domain, 0.55, &ctx.scan_id);
                de.tag(tags::BREACH);
                de.tag("hibp");
                de.tag(tags::BREACH_DERIVED);
                de.add_evidence(
                    Evidence::new(
                        SRC,
                        format!(
                            "Domain from breach '{}' ({})",
                            breach.name,
                            breach.breach_date.as_deref().unwrap_or("unknown date")
                        ),
                    )
                    .with_attr("breach_name", &breach.name)
                    .with_attr("pwn_count", breach.pwn_count.unwrap_or(0).to_string())
                    .with_attr("data_classes", breach.data_classes.join(", ")),
                );
                result.push(de);
            }
        }

        // Emit risk-level tags on the email entity
        if has_passwords && let Some(e) = result.entities.first_mut() {
            e.tag(tags::PASSWORD_AT_RISK);
        }
        if has_phone && let Some(e) = result.entities.first_mut() {
            e.tag("phone-exposed");
        }
        if has_physical && let Some(e) = result.entities.first_mut() {
            e.tag("address-exposed");
        }

        Ok(())
    }

    /// GET /api/v3/pasteaccount/{email}
    async fn query_paste_account(
        &self,
        key: &str,
        target: &Target,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let email = urlencode(target.value.trim());
        let url = format!("{BASE_URL}/pasteaccount/{email}");
        let pastes: Vec<Paste> = match self.api_get(key, &url, ctx).await? {
            Some(p) => p,
            None => return Ok(()),
        };

        if pastes.is_empty() {
            return Ok(());
        }

        let total = pastes.len();
        let sources: Vec<String> = pastes
            .iter()
            .map(|p| {
                let src = p.source.as_deref().unwrap_or("unknown");
                let id = p.id.as_deref().unwrap_or("?");
                format!("{src}:{id}")
            })
            .take(10)
            .collect();

        // Boost the existing email entity if present, otherwise create one
        if let Some(existing) = result.entities.iter_mut().find(|e| {
            e.kind == EntityKind::Email && e.value.eq_ignore_ascii_case(target.value.trim())
        }) {
            existing.tag(tags::PASTE_EXPOSED);
            existing.confidence = (existing.confidence + 0.05).min(1.0);
            existing.corroboration = existing.corroboration.saturating_add(1);
            existing.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Found in {total} paste(s): {}", sources.join(", ")),
                )
                .with_attr("paste_count", total.to_string())
                .with_attr("paste_sources", sources.join(", ")),
            );
        } else {
            let mut e = Entity::new(EntityKind::Email, target.value.trim(), 0.60, &ctx.scan_id);
            e.tag(tags::PASTE_EXPOSED);
            e.tag("hibp");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Found in {total} paste(s): {}", sources.join(", ")),
                )
                .with_attr("paste_count", total.to_string())
                .with_attr("paste_sources", sources.join(", ")),
            );
            result.push(e);
        }

        Ok(())
    }

    /// GET /api/v3/breaches?domain={domain}
    async fn query_domain_breaches(
        &self,
        key: &str,
        target: &Target,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let domain = urlencode(target.value.trim());
        let url = format!("{BASE_URL}/breaches?domain={domain}");
        let breaches: Vec<Breach> = match self.api_get(key, &url, ctx).await? {
            Some(b) => b,
            None => return Ok(()),
        };

        if breaches.is_empty() {
            return Ok(());
        }

        let total = breaches.len();
        let verified = breaches
            .iter()
            .filter(|b| b.is_verified == Some(true))
            .count();
        let total_pwns: u64 = breaches.iter().filter_map(|b| b.pwn_count).sum();
        let names: Vec<&str> = breaches.iter().map(|b| b.name.as_str()).collect();

        let base_conf = if verified >= 2 { 0.80 } else { 0.65 };

        let mut domain_ent = Entity::new(
            EntityKind::Domain,
            target.value.trim(),
            base_conf,
            &ctx.scan_id,
        );
        domain_ent.tag(tags::BREACH);
        domain_ent.tag("hibp");
        if total_pwns > 1_000_000 {
            domain_ent.tag(tags::HIGH_EXPOSURE);
        }
        domain_ent.corroboration = verified.max(1) as u32;
        domain_ent.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Domain affected by {total} breach(es) ({verified} verified, {total_pwns} total records): {}",
                    names.iter().take(10).copied().collect::<Vec<_>>().join(", ")
                ),
            )
            .with_attr("breach_count", total.to_string())
            .with_attr("verified_count", verified.to_string())
            .with_attr("total_pwn_count", total_pwns.to_string())
            .with_attr("breach_names", names.join(", ")),
        );
        result.push(domain_ent);

        // Extract data classes across all breaches for intelligence
        let mut all_data_classes: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for breach in &breaches {
            for dc in &breach.data_classes {
                all_data_classes.insert(dc.clone());
            }
        }
        if !all_data_classes.is_empty() {
            let mut sorted: Vec<String> = all_data_classes.into_iter().collect();
            sorted.sort();
            if let Some(e) = result.entities.first_mut() {
                e.add_evidence(
                    Evidence::new(SRC, format!("Exposed data classes: {}", sorted.join(", ")))
                        .with_attr("data_classes", sorted.join(", ")),
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_and_domain() {
        let m = Hibp;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    #[test]
    fn priority_above_free_breach_modules() {
        let m = Hibp;
        assert!(
            m.priority() > 100,
            "HIBP should run before free breach modules"
        );
    }

    #[test]
    fn cost_is_key_gated() {
        assert_eq!(Hibp.cost(), ModuleCost::KeyGated);
    }

    #[test]
    fn resolve_key_prefers_provided() {
        assert_eq!(resolve_key(Some("my-key")), "my-key");
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded() {
        assert_eq!(resolve_key(None), HARDCODED_KEY);
    }

    #[test]
    fn resolve_key_falls_back_on_empty() {
        assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
    }

    #[test]
    fn name_is_hibp() {
        assert_eq!(Hibp.name(), "hibp");
    }

    #[test]
    fn description_non_empty() {
        assert!(!Hibp.description().is_empty());
    }

    #[test]
    fn max_timeout_generous() {
        assert!(Hibp.max_timeout_ms() >= 30_000);
    }

    #[test]
    fn breach_deser_full_payload() {
        let json = r#"[{
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04",
            "ModifiedDate": "2022-05-15",
            "PwnCount": 152445165,
            "Description": "Adobe breach",
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": true,
            "IsFabricated": false,
            "IsSensitive": false,
            "IsRetired": false,
            "IsSpamList": false,
            "IsSubscriptionFree": false,
            "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png"
        }]"#;
        let breaches: Vec<Breach> = serde_json::from_str(json).unwrap();
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].name, "Adobe");
        assert_eq!(breaches[0].domain.as_deref(), Some("adobe.com"));
        assert_eq!(breaches[0].pwn_count, Some(152445165));
        assert!(breaches[0].is_verified == Some(true));
        assert_eq!(breaches[0].data_classes.len(), 4);
        assert!(breaches[0].data_classes.contains(&"Passwords".to_string()));
    }

    #[test]
    fn breach_deser_minimal() {
        let json = r#"[{"Name": "Unknown"}]"#;
        let breaches: Vec<Breach> = serde_json::from_str(json).unwrap();
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].name, "Unknown");
        assert!(breaches[0].domain.is_none());
        assert!(breaches[0].data_classes.is_empty());
    }

    #[test]
    fn paste_deser() {
        let json = r#"[{
            "Source": "Pastebin",
            "Id": "Ab1cD2eF",
            "Title": "test dump",
            "Date": "2024-01-15T00:00:00",
            "EmailCount": 42
        }]"#;
        let pastes: Vec<Paste> = serde_json::from_str(json).unwrap();
        assert_eq!(pastes.len(), 1);
        assert_eq!(pastes[0].source.as_deref(), Some("Pastebin"));
        assert_eq!(pastes[0].id.as_deref(), Some("Ab1cD2eF"));
        assert_eq!(pastes[0].email_count, Some(42));
    }

    #[test]
    fn rate_limit_delay_respects_quota() {
        assert!(
            RATE_LIMIT_DELAY.as_millis() >= 6000,
            "10 req/min = 6s between requests minimum"
        );
    }
}
