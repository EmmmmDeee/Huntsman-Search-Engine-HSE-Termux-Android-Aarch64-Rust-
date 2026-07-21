//! OsintCat — email footprint, breach lookup, and deep email-osint.
//!
//! Endpoints (GET, auth via `x-api-key` header):
//!   `/api/user`             credit preflight — free, checked before paid call
//!   `/api/email-footprint`  100+ platform registration check — free
//!   `/api/breach`           multi-source breach search — free
//!   `/api/email-osint`      paid deep search — skipped when credits insufficient
//!
//! Accepts: Email. Requires `HUNTSMAN_OSINTCAT_KEY`.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::{debug, warn};

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{
    RequestBuilderExt, fetch_keyed_json, json_scanned, keyed_ok_or_404, urlencode,
};
use crate::util::str_util::slugify;

const SRC: &str = "osintcat";
const KEY_ENV: &str = "HUNTSMAN_OSINTCAT_KEY";
const BASE: &str = "https://www.osintcat.net/api";
const PURPOSE: &str = "Law Enforcement Intelligence";

pub struct OsintCat;

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct OcUserResponse {
    email_osint_credits: OcCredits,
}

#[derive(Deserialize)]
struct OcCredits {
    has_sufficient_credits: bool,
    current_balance: f64,
    price_per_search: f64,
}

#[derive(Deserialize)]
struct OcFootprintResponse {
    stats: OcFootprintStats,
    results: Vec<OcFootprintResult>,
}

#[derive(Deserialize)]
struct OcFootprintStats {
    total_checked: u32,
    registered_count: u32,
}

#[derive(Deserialize)]
struct OcFootprintResult {
    domain: String,
    taken: bool,
    #[serde(rename = "ExtraData")]
    extra_data: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
struct OcBreachResponse {
    results_count: u32,
    breach_data: Vec<Value>,
}

// ── Module trait ───────────────────────────────────────────────────────────────

#[async_trait]
impl Module for OsintCat {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "OsintCat enrichment — sweeps an email footprint for breach and deep-osint intelligence"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let email = &target.value;

        // Credits preflight — no query param needed.
        let user: OcUserResponse =
            fetch_keyed_json(ctx, SRC, &format!("{BASE}/user"), KEY_ENV, "x-api-key")
                .await?
                .ok_or_else(|| Error::module(SRC, "credits endpoint returned 404"))?;
        let credits = user.email_osint_credits;
        debug!(balance = credits.current_balance, "osintcat credit check");

        let mut entity = target.to_entity(confidence::VERY_HIGH, &ctx.scan_id);
        entity.tag(SRC);

        // Footprint — free endpoint.
        let fp_url = format!("{BASE}/email-footprint?query={}", urlencode(email));
        match fetch_keyed_json::<OcFootprintResponse>(ctx, SRC, &fp_url, KEY_ENV, "x-api-key").await
        {
            Ok(Some(fp)) => emit_footprint(&fp, &mut entity, &mut result),
            Ok(None) => {} // 404 — no footprint data
            Err(e) => warn!(error = %e, "osintcat footprint failed"),
        }

        // Breach — free endpoint.
        let br_url = format!("{BASE}/breach?query={}", urlencode(email));
        match fetch_keyed_json::<OcBreachResponse>(ctx, SRC, &br_url, KEY_ENV, "x-api-key").await {
            Ok(Some(br)) => emit_breach(&br, &mut entity),
            Ok(None) => {} // 404 — no breach data
            Err(e) => warn!(error = %e, "osintcat breach failed"),
        }

        // Deep email-osint — paid; needs an extra `x-purpose` header so we
        // can't use `fetch_keyed_json` directly.
        if credits.has_sufficient_credits {
            match fetch_email_osint(email, ctx).await {
                Ok(raw) => emit_email_osint(&raw, &mut entity),
                Err(e) => warn!(error = %e, "osintcat email-osint failed"),
            }
        } else {
            warn!(
                balance = credits.current_balance,
                price = credits.price_per_search,
                "osintcat skipping email-osint: insufficient credits"
            );
        }

        // Only emit the entity when at least one endpoint contributed evidence.
        // A bare entity with only the SRC tag and no evidence adds no value.
        if !entity.evidence.is_empty() {
            result.push(entity);
        }
        Ok(result)
    }
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────

/// Fetch the paid email-osint endpoint. Needs an extra `x-purpose` header that
/// [`fetch_keyed_json`] does not support, so we build the request manually and
/// delegate status classification to [`keyed_ok_or_404`].
async fn fetch_email_osint(email: &str, ctx: &ModuleContext) -> Result<Value> {
    let key = ctx.key(KEY_ENV)?;
    let resp = ctx
        .http
        .get(format!("{BASE}/email-osint?query={}", urlencode(email)))
        .header("x-api-key", key)
        .header("x-purpose", PURPOSE)
        .send_tagged(SRC)
        .await?;

    let Some(resp) = keyed_ok_or_404(SRC, key, ctx, resp).await? else {
        return Ok(Value::Null);
    };
    json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

// ── Emitters ───────────────────────────────────────────────────────────────────

fn emit_footprint(fp: &OcFootprintResponse, entity: &mut Entity, result: &mut ModuleResult) {
    if fp.stats.registered_count == 0 {
        return;
    }
    entity.add_evidence(
        Evidence::new(
            SRC,
            format!(
                "Found on {}/{} platforms checked",
                fp.stats.registered_count, fp.stats.total_checked
            ),
        )
        .with_attr("registered_count", fp.stats.registered_count.to_string())
        .with_attr("total_checked", fp.stats.total_checked.to_string()),
    );

    for r in fp.results.iter().filter(|r| r.taken) {
        entity.tag(format!("osintcat:registered:{}", slugify(&r.domain)));

        if let Some(extra) = &r.extra_data {
            for (k, v) in extra {
                if v.is_null() {
                    continue;
                }
                entity.add_evidence(
                    Evidence::new(SRC, format!("[{}] {k}: {v}", r.domain))
                        .with_attr("platform", &r.domain)
                        .with_attr("key", k)
                        .with_attr("value", v.to_string()),
                );
                // Username ExtraData keys become pivot entities.
                if k.eq_ignore_ascii_case("username")
                    && let Some(uname) = v.as_str()
                {
                    let mut pivot = Entity::new(
                        EntityKind::Username,
                        uname,
                        confidence::HIGH_PLUS,
                        &entity.scan_id,
                    );
                    pivot.tag("osintcat");
                    pivot.tag("footprint-pivot");
                    result.push(pivot);
                }
            }
        }
    }
}

fn emit_breach(br: &OcBreachResponse, entity: &mut Entity) {
    if br.results_count == 0 {
        return;
    }
    entity.tag("breach");
    let mut ev = Evidence::new(
        SRC,
        format!("{} breach record(s) via OsintCat", br.results_count),
    )
    .with_attr("breach_count", br.results_count.to_string());

    for record in &br.breach_data {
        let source = record
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let date = record
            .get("breach_date")
            .and_then(Value::as_str)
            .unwrap_or("unknown date");
        ev = ev.with_attr(
            format!("breach_{source}"),
            format!("Breach: {source} ({date})"),
        );
        entity.tag(format!("osintcat:breach:{}", slugify(source)));
    }
    entity.add_evidence(ev);
}

fn emit_email_osint(raw: &Value, entity: &mut Entity) {
    let Some(obj) = raw.as_object() else { return };
    let mut ev = Evidence::new(SRC, "OsintCat email-osint deep findings".to_string());
    for (k, v) in obj {
        if v.is_null() {
            continue;
        }
        ev = ev.with_attr(k, v.to_string());
    }
    entity.add_evidence(ev);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
