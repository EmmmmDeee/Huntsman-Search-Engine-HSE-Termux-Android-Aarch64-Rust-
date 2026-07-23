//! SEON email and phone enrichment — fraud/risk scoring, domain quality,
//! breach exposure, WHOIS-style registrant lookups, and HLR/CNAM phone
//! network status.
//!
//! **Email path:**
//! `POST https://api.seon.io/SeonRestService/email-api/v3`
//! Fraud score, email/domain quality signals, breach history, and
//! WHOIS-style registrant PII for domains associated with the email.
//!
//! **Phone path:**
//! `POST https://api.seon.io/SeonRestService/phone-api/v2`
//! Fraud score, carrier/line-type details, live HLR network status
//! (ported/roaming carrier, serving MSC, IMSI), and CNAM Caller-ID-Name
//! subscriber lookup.
//!
//! Auth: `X-API-KEY` header. Key-gated (`HUNTSMAN_SEON_KEY`).
//!
//! ## The v3/v2 schema migration this fix corrects
//!
//! SEON's own migration guide states the per-platform `account_details`
//! object (`{facebook: {registered, name, url}, twitter: {...}, …}`) this
//! module's response types previously modelled was **removed** from both
//! endpoints and replaced with `account_aggregates` — CATEGORY-level
//! registration counts only (e.g. `social_media: {registered: 8, checked:
//! 21}`), never a per-platform name or profile URL. Because the top-level
//! `success`/`data` keys still deserialize, the module never errored; it
//! silently returned a near-empty result for every real call (every field
//! the old structs expected was absent, so `#[serde(default)]` filled them
//! all with `None`) while still spending the paid/keyed quota. This was
//! fixed across two cycles, one API surface per cycle: first the **email**
//! path against SEON's verified current schema (v3), adding real,
//! previously-uncaptured signal (`breach_details` — an HIBP-style breach
//! list, `Domain`-per-breach + `breach_date`-stamped so it date-clusters
//! with the same breach surfaced by another module — and
//! `associated_domain_registrations`, WHOIS-style registrant PII mirroring
//! `whois`'s registrant extraction); then the **phone** path against
//! `phone-api/v2`'s verified current schema, which moved `score` under the
//! same `risk_scores` shape the email path uses, moved `valid`/`carrier`/
//! `country`/`type` under `provider_carrier_details`, replaced per-platform
//! messaging presence with the same `account_aggregates` shape the email
//! path uses, and added two sections this module never modelled before:
//! `hlr_details` (live HLR network status) and `cnam_details` (PSTN
//! Caller-ID-Name lookup) — both mirroring the dedicated `hlr_cnam`
//! module's own HLR/CNAM entity patterns (carrier → `Organisation` pivot,
//! CNAM name → `Person` pivot) rather than inventing new ones.
//!
//! The two response → entity mappings live in the pure [`build_email_entities`]
//! / [`build_phone_entities`] so they are unit-tested without a live API; the
//! `*_lookup` methods own only transport.

mod entity_builders;
mod types;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

use entity_builders::{build_email_entities, build_phone_entities};
use types::{SeonEmailResp, SeonPhoneResp};

pub(crate) const KEY_ENV: &str = "HUNTSMAN_SEON_KEY";
pub(crate) const SRC: &str = "seon";

/// A fraud score at/above this (0–100) flags the identity high-risk.
pub(super) const HIGH_RISK_SCORE: f64 = 80.0;

pub struct Seon;

#[async_trait]
impl Module for Seon {
    fn name(&self) -> &'static str {
        "seon"
    }
    fn description(&self) -> &'static str {
        "SEON email/phone enrichment — surfaces fraud score, breach exposure, and WHOIS-style registrant PII"
    }
    fn priority(&self) -> u8 {
        95
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Phone)
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // The People-category default (T1589.003 Employee Names + T1591.004
        // Identify Roles) fits neither path: no role/job-title field exists
        // anywhere in SEON's real schema (T1591.004 was never earned — the
        // same "over-claims a role mapping never performed" issue already
        // corrected for oathnet_pro/dehashed this session), and the
        // Social Media technique (T1593.001) this module previously claimed
        // no longer reflects real extraction on EITHER path — SEON's v3/v2
        // migration removed all per-platform presence data, so declaring it
        // would misstate coverage the API can no longer deliver (see this
        // file's top doc comment). What the FIXED email path genuinely
        // extracts: breach exposure confirmation (T1589.002, mirroring
        // `hibp`'s identical Breach-category-default precedent) and
        // WHOIS-style registrant PII — name (T1589.003), address
        // (T1591.001), company (T1591.002). What the FIXED phone path
        // genuinely extracts: carrier/HLR network status and CNAM
        // subscriber-name identity information — the same coverage the
        // dedicated `hlr_cnam` module declares for identical signal (bare
        // `T1589`, the ATT&CK parent; no phone-specific sub-technique exists
        // in the real catalogue), which `ipqs` also already pairs alongside
        // a more specific sub-technique (precedent for declaring both).
        &["T1589", "T1589.002", "T1589.003", "T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Always re-emits the seed (Email or Phone) enriched with SEON
        // signal. The email path additionally mints: Domain (breach
        // exposure + registrant domains), Person/Organisation/Address/Phone
        // (WHOIS-style registrant PII from associated_domain_registrations).
        // The phone path additionally mints: Organisation (carrier/network
        // pivot) and Person (CNAM Caller-ID-Name pivot). `EntityKind::Url`
        // is deliberately NOT declared: the pre-fix phone path's
        // `profile_url_entity` call (the only site that ever constructed
        // one) is gone now that both paths are rewritten against their real
        // schemas, so this module no longer mints that kind at all.
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = ctx.key(KEY_ENV)?;

        match target.kind {
            TargetKind::Email => self.email_lookup(target, key, ctx).await,
            TargetKind::Phone => self.phone_lookup(target, key, ctx).await,
            _ => Ok(ModuleResult::new()),
        }
    }
}

impl Seon {
    async fn email_lookup(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://api.seon.io/SeonRestService/email-api/v3")
            .header("X-API-KEY", key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "email": email }))
            .send_tagged(SRC)
            .await?;

        // 401/403/429 → note_keyed_error + Err; 404 → empty; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: SeonEmailResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_email_entities(target, &data, &ctx.scan_id));
        Ok(result)
    }

    async fn phone_lookup(
        &self,
        target: &Target,
        key: &str,
        ctx: &ModuleContext,
    ) -> Result<ModuleResult> {
        let phone = target.value.trim();
        if phone.is_empty() {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .post("https://api.seon.io/SeonRestService/phone-api/v2")
            .header("X-API-KEY", key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "phone": phone }))
            .send_tagged(SRC)
            .await?;

        // 401/403/429 → note_keyed_error + Err; 404 → empty; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: SeonPhoneResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        if body.success != Some(true) {
            return Ok(ModuleResult::new());
        }
        let Some(data) = body.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(build_phone_entities(target, &data, &ctx.scan_id));
        Ok(result)
    }
}
