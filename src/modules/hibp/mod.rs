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

#[cfg(test)]
mod tests;

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::RequestBuilderExt;
use crate::util::http::{error_snippet, urlencode};

const SRC: &str = "hibp";
const KEY_ENV: &str = "HUNTSMAN_HIBP_KEY";
// Embedded fallback: single source of truth lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::HIBP_DEFAULT_KEY;
const BASE_URL: &str = "https://haveibeenpwned.com/api/v3";

pub(super) fn resolve_key(ctx_key: Option<&str>) -> &str {
    crate::util::keys::resolve_or_default(ctx_key, HARDCODED_KEY)
}

// ── API response types ──────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub(super) struct Breach {
    pub(super) name: String,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) domain: Option<String>,
    #[serde(default)]
    pub(super) breach_date: Option<String>,
    #[serde(default)]
    pub(super) added_date: Option<String>,
    #[serde(default)]
    pub(super) modified_date: Option<String>,
    #[serde(default)]
    pub(super) pwn_count: Option<u64>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) data_classes: Vec<String>,
    #[serde(default)]
    pub(super) is_verified: Option<bool>,
    #[serde(default)]
    pub(super) is_fabricated: Option<bool>,
    #[serde(default)]
    pub(super) is_sensitive: Option<bool>,
    #[serde(default)]
    pub(super) is_retired: Option<bool>,
    #[serde(default)]
    pub(super) is_spam_list: Option<bool>,
    #[serde(default)]
    pub(super) is_subscription_free: Option<bool>,
    #[serde(default)]
    pub(super) logo_path: Option<String>,
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        // HIBP returns breach metadata on the input Email/Domain — it
        // does NOT emit standalone Credential entities (policy: leaked
        // passwords are redacted, only the fact of the breach surfaces
        // as tags/evidence on the seed). Declaration is therefore
        // limited to the corroborated seed kinds.
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Domain];
        KINDS
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
                .send_tagged(SRC)
                .await?;

            let status = resp.status().as_u16();
            match status {
                200 => {
                    // Via json_scanned: the paid breach body is retained in the
                    // raw archive and scanned for leaked keys (the "retain all
                    // paid data" invariant), then deserialised.
                    let data = crate::util::http::json_scanned::<T>(resp, SRC)
                        .await
                        .map_err(|e| Error::module(SRC, e))?;
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
                    // 60s module budget, up to 3 sleeps: cap each at 10s so the
                    // retry chain stays within process()'s timeout.
                    let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 7, 10);
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
        let mut top_names = String::new();
        for (i, name) in breach_names.iter().take(10).enumerate() {
            if i > 0 {
                top_names.push_str(", ");
            }
            top_names.push_str(name);
        }

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
            .with_attr("breach_names", breach_names.join(", "))
            .with_attr(
                "breach_date",
                breaches
                    .iter()
                    .filter_map(|b| b.breach_date.as_deref())
                    .max()
                    .unwrap_or(""),
            ),
        );
        result.push(email_ent);

        // Extract data classes to tag risk level. Single pass over all data
        // classes, lowercasing each at most once into a reused buffer rather
        // than allocating a fresh String per flag-check per class.
        let (mut has_passwords, mut has_phone, mut has_physical) = (false, false, false);
        let mut dcl = String::new();
        for dc in breaches.iter().flat_map(|b| &b.data_classes) {
            if has_passwords && has_phone && has_physical {
                break;
            }
            dcl.clear();
            dcl.extend(dc.chars().map(|c| c.to_ascii_lowercase()));
            has_passwords |= dcl.contains("password");
            has_phone |= dcl.contains("phone");
            has_physical |=
                dcl.contains("physical") || dcl.contains("address") || dcl.contains("location");
        }

        // Extract associated domains as expansion seeds.
        result.extend(breaches.iter().filter_map(|breach| {
            let domain = breach
                .domain
                .as_deref()
                .filter(|d| !d.is_empty() && d.contains('.'))?;
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
                .with_attr("data_classes", breach.data_classes.join(", "))
                .with_attr("breach_date", breach.breach_date.as_deref().unwrap_or("")),
            );
            Some(de)
        }));

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
                    names.iter().take(10).copied().enumerate().fold(String::new(), |mut acc, (i, s)| {
                        if i > 0 {
                            acc.push_str(", ");
                        }
                        acc.push_str(s);
                        acc
                    })
                ),
            )
            .with_attr("breach_count", total.to_string())
            .with_attr("verified_count", verified.to_string())
            .with_attr("total_pwn_count", total_pwns.to_string())
            .with_attr("breach_names", names.join(", ")),
        );
        result.push(domain_ent);

        // Extract data classes across all breaches for intelligence
        let all_data_classes: std::collections::HashSet<String> = breaches
            .iter()
            .flat_map(|breach| breach.data_classes.iter().cloned())
            .collect();
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
