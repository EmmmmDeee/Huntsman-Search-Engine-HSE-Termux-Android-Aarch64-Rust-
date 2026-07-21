//! Have I Been Pwned (HIBP) v3 API — definitive breach + paste oracle.
//!
//! Endpoints:
//!   GET /api/v3/breachedaccount/{email}  — breaches containing this email
//!   GET /api/v3/pasteaccount/{email}     — public pastes (Pastebin, …) the
//!                                          email appeared in (the "paste" half)
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
    confidence,
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
    // A stealer log or malware dump is a fundamentally different — and more
    // severe — compromise class than a routine website breach: the credential
    // was harvested off a victim's *own device* by info-stealer malware, so it
    // implies live device compromise (browser-stored passwords, cookies,
    // autofill) rather than a third-party site leaking its user table. HIBP
    // carries these as first-class flags on every breach object; surface them.
    #[serde(default)]
    pub(super) is_stealer_log: Option<bool>,
    #[serde(default)]
    pub(super) is_malware: Option<bool>,
    #[serde(default)]
    pub(super) logo_path: Option<String>,
}

/// Full-fidelity [`Evidence`] for one HIBP breach. Surfaces **every** field the
/// v3 API returns — title/description, the date trail (breach/added/modified),
/// pwn_count, data classes, the logo, and the data-quality/severity flags
/// (verified/fabricated/sensitive/retired/spam/subscription-free plus
/// stealer-log/malware) — so a breach-derived finding carries HIBP's complete
/// characterisation, not just a name + date. **Pure** (no IO) and unit-tested
/// directly.
fn breach_evidence(breach: &Breach) -> Evidence {
    let nonempty = |o: &Option<String>| o.as_deref().filter(|s| !s.is_empty()).map(str::to_string);

    let mut ev = Evidence::new(
        SRC,
        format!(
            "Breach '{}' ({})",
            breach.title.as_deref().unwrap_or(&breach.name),
            breach.breach_date.as_deref().unwrap_or("unknown date"),
        ),
    )
    .with_attr("breach_name", &breach.name)
    .with_attr("pwn_count", breach.pwn_count.unwrap_or(0).to_string())
    .with_attr("data_classes", breach.data_classes.join(", "));

    for (key, val) in [
        ("title", nonempty(&breach.title)),
        ("breach_domain", nonempty(&breach.domain)),
        ("breach_date", nonempty(&breach.breach_date)),
        ("added_date", nonempty(&breach.added_date)),
        ("modified_date", nonempty(&breach.modified_date)),
        ("description", nonempty(&breach.description)),
        ("logo_path", nonempty(&breach.logo_path)),
    ] {
        if let Some(v) = val {
            ev = ev.with_attr(key, &v);
        }
    }

    // Data-quality flags — the signal that separates a corroborated breach from
    // fabricated / spam-list / unverified noise.
    for (key, flag) in [
        ("verified", breach.is_verified),
        ("fabricated", breach.is_fabricated),
        ("sensitive", breach.is_sensitive),
        ("retired", breach.is_retired),
        ("spam_list", breach.is_spam_list),
        ("subscription_free", breach.is_subscription_free),
        ("stealer_log", breach.is_stealer_log),
        ("malware", breach.is_malware),
    ] {
        if let Some(b) = flag {
            ev = ev.with_attr(key, b.to_string());
        }
    }
    ev
}

/// One HIBP paste record (the `/pasteaccount` array element). Pastes are often
/// the FIRST public appearance of a compromised credential, predating the
/// aggregated breach record — surfaced under the same subscription key at zero
/// extra key cost. The free-text `comment`/content is deliberately NOT modelled:
/// only the metadata (source, id, date, count) becomes evidence/pivots.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Paste {
    #[serde(default)]
    pub(super) source: Option<String>,
    #[serde(default)]
    pub(super) id: Option<String>,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) date: Option<String>,
    #[serde(default)]
    pub(super) email_count: Option<u64>,
}

/// Reconstruct the public URL for a paste when its source has a deterministic
/// URL scheme. Only `Pastebin` (`https://pastebin.com/{id}`) is reconstructable
/// today; any other source yields `None` rather than a fabricated URL.
fn paste_url(paste: &Paste) -> Option<String> {
    let id = paste
        .id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    match paste.source.as_deref() {
        Some("Pastebin") => Some(format!("https://pastebin.com/{id}")),
        _ => None,
    }
}

/// Build the entities for a set of HIBP pastes containing an email: the Email
/// re-emitted with a `paste` tag + count/recency evidence (merged onto the
/// breach Email by the engine), plus one `Url` pivot per URL-reconstructable
/// paste. **Pure** (no IO) so the tag, the count evidence, and the Pastebin URL
/// reconstruction are unit-tested directly. Empty input yields nothing.
fn paste_entities(pastes: &[Paste], email: &str, scan_id: &str) -> Vec<Entity> {
    if pastes.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();

    let mut sources: Vec<&str> = pastes
        .iter()
        .filter_map(|p| p.source.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    sources.sort_unstable();
    sources.dedup();
    let latest = pastes
        .iter()
        .filter_map(|p| p.date.as_deref())
        .filter(|s| !s.is_empty())
        .max()
        .unwrap_or("");

    let mut e = Entity::new(EntityKind::Email, email, 0.70, scan_id);
    e.tag(tags::BREACH);
    e.tag("hibp");
    e.tag("paste");
    let mut ev = Evidence::new(SRC, format!("Appears in {} paste(s)", pastes.len()))
        .with_attr("paste_count", pastes.len().to_string());
    if !sources.is_empty() {
        ev = ev.with_attr("paste_sources", sources.join(", "));
    }
    if !latest.is_empty() {
        ev = ev.with_attr("latest_paste", latest);
    }
    e.add_evidence(ev);
    out.push(e);

    for paste in pastes {
        if let Some(url) = paste_url(paste) {
            let mut u = Entity::new(EntityKind::Url, &url, 0.55, scan_id);
            u.tag("hibp");
            u.tag("paste");
            let mut ev = Evidence::new(SRC, format!("Paste containing {email}"));
            if let Some(title) = paste.title.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("title", title);
            }
            if let Some(date) = paste.date.as_deref().filter(|s| !s.is_empty()) {
                ev = ev.with_attr("date", date);
            }
            // Scale of the leak: how many emails the paste exposed.
            if let Some(n) = paste.email_count {
                ev = ev.with_attr("email_count", n.to_string());
            }
            u.add_evidence(ev);
            out.push(u);
        }
    }

    out
}

/// Tag a breach-derived entity with HIBP's data-quality flags so the operator
/// can filter low-trust breach intel (fabricated / spam-list) and flag
/// sensitive/retired breaches. Only `Some(true)` flags emit a tag.
fn tag_breach_quality(e: &mut Entity, breach: &Breach) {
    if breach.is_fabricated == Some(true) {
        e.tag("breach-fabricated");
    }
    if breach.is_spam_list == Some(true) {
        e.tag("breach-spam-list");
    }
    if breach.is_sensitive == Some(true) {
        e.tag("breach-sensitive");
    }
    if breach.is_retired == Some(true) {
        e.tag("breach-retired");
    }
    if breach.is_stealer_log == Some(true) {
        // A stealer-log hit is device compromise (info-stealer malware harvested
        // the credential off the victim's own machine), not a third-party site
        // leaking its user table — a materially more severe class. Route it into
        // the canonical `stealer-log` correlation machinery (exposure scoring,
        // AU breach rules, lead extraction) that HudsonRock / niamonx feed, so a
        // HIBP stealer-log hit escalates identically to a dedicated stealer-log
        // module's hit rather than reading as a routine breach.
        e.tag(tags::STEALER_LOG);
    }
    if breach.is_malware == Some(true) {
        // Malware-sourced dump (e.g. an Emotet address-book harvest). A weaker
        // signal than a full stealer log, so it stays a descriptive `breach-*`
        // quality tag rather than escalating into stealer-log correlation.
        e.tag("breach-malware");
    }
}

// ── Module impl ─────────────────────────────────────────────────────

pub struct Hibp;

#[async_trait]
impl Module for Hibp {
    fn name(&self) -> &'static str {
        "hibp"
    }

    fn description(&self) -> &'static str {
        "Have I Been Pwned — the definitive breach & paste oracle; surfaces an email's exposure across known corpora (API v3)"
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
        // as tags/evidence on the seed). The paste oracle additionally
        // mints a Url pivot per URL-reconstructable paste (e.g. Pastebin).
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Domain, EntityKind::Url];
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
                // `query_breached_account` delivers both halves of the module's
                // "breach + paste oracle" billing: breaches, then (best-effort,
                // same subscription key) the /pasteaccount pastes folded onto the
                // same Email entity.
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
            if ctx.cancel.is_cancelled() {
                return Ok(None);
            }
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
        let top_names: String = breach_names
            .iter()
            .take(10)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");

        let base_conf = match verified_count {
            0 => confidence::HIGH,
            1..=2 => confidence::HIGH_PLUSPLUS,
            3..=5 => confidence::EXPERT,
            _ => confidence::VERY_HIGH_PLUSPLUS,
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
        email_ent.corroboration = u32::try_from(verified_count.max(1)).unwrap_or(u32::MAX);
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
        // Attach the per-breach FULL-FIDELITY detail (description, dates, logo,
        // affected data classes, quality flags) and the per-breach quality tags
        // (`breach-fabricated`/`breach-sensitive`/…) to the EMAIL entity itself.
        // These existing pure helpers were applied only to the derived Domain
        // entities, so an email scan — the common case — dropped the rich
        // per-breach record the no-omission policy requires. The summary evidence
        // above stays evidence[0] (the headline); these add the detail beneath it.
        for breach in &breaches {
            email_ent.add_evidence(breach_evidence(breach));
            tag_breach_quality(&mut email_ent, breach);
        }
        result.push(email_ent);

        // Extract data classes to tag risk level — short-circuit scan per flag.
        let has_passwords = breaches
            .iter()
            .flat_map(|b| &b.data_classes)
            .any(|dc| dc.to_ascii_lowercase().contains("password"));
        let has_phone = breaches
            .iter()
            .flat_map(|b| &b.data_classes)
            .any(|dc| dc.to_ascii_lowercase().contains("phone"));
        let has_physical = breaches.iter().flat_map(|b| &b.data_classes).any(|dc| {
            let dcl = dc.to_ascii_lowercase();
            dcl.contains("physical") || dcl.contains("address") || dcl.contains("location")
        });

        // Extract associated domains as expansion seeds.
        result.extend(breaches.iter().filter_map(|breach| {
            let domain = breach
                .domain
                .as_deref()
                .filter(|d| !d.is_empty() && d.contains('.'))?;
            let mut de = Entity::new(
                EntityKind::Domain,
                domain,
                confidence::MEDIUM_HIGH,
                &ctx.scan_id,
            );
            de.tag(tags::BREACH);
            de.tag("hibp");
            de.tag(tags::BREACH_DERIVED);
            tag_breach_quality(&mut de, breach);
            de.add_evidence(breach_evidence(breach));
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

        // Paste oracle: the same subscription key authorises /pasteaccount at no
        // extra key cost, and pastes are frequently the FIRST public appearance
        // of a leaked credential. A 404 means no pastes (clean); on any hit, the
        // pure builder folds a `paste` tag + count/recency evidence onto the
        // Email and mints a Url pivot per URL-reconstructable paste.
        let paste_url = format!("{BASE_URL}/pasteaccount/{email}");
        if let Some(pastes) = self.api_get::<Vec<Paste>>(key, &paste_url, ctx).await? {
            result.extend(paste_entities(&pastes, target.value.trim(), &ctx.scan_id));
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

        let base_conf = if verified >= 2 {
            confidence::HIGH_PLUSPLUS
        } else {
            confidence::HIGH
        };

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
        domain_ent.corroboration = u32::try_from(verified.max(1)).unwrap_or(u32::MAX);
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
