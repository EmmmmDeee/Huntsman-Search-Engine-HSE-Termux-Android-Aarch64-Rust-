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
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

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
        "OsintCat email footprint, breach, and deep-osint enrichment"
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
        let key = ctx.key(KEY_ENV)?;

        let credits = fetch_credits(&ctx.http, key, ctx).await?;
        debug!(balance = credits.current_balance, "osintcat credit check");

        let mut entity = target.to_entity(0.75, &ctx.scan_id);
        entity.tag(SRC);

        match fetch_footprint(&ctx.http, key, email, ctx).await {
            Ok(fp) => emit_footprint(&fp, &mut entity, &mut result),
            Err(e) => warn!(error = %e, "osintcat footprint failed"),
        }

        match fetch_breach(&ctx.http, key, email, ctx).await {
            Ok(br) => emit_breach(&br, &mut entity),
            Err(e) => warn!(error = %e, "osintcat breach failed"),
        }

        if credits.has_sufficient_credits {
            match fetch_email_osint(&ctx.http, key, email, ctx).await {
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

async fn fetch_credits(
    http: &reqwest::Client,
    key: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<OcCredits> {
    let resp = http
        .get(format!("{BASE}/user"))
        .header("x-api-key", key)
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    let r: OcUserResponse = crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))?;
    Ok(r.email_osint_credits)
}

async fn fetch_footprint(
    http: &reqwest::Client,
    key: &str,
    email: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<OcFootprintResponse> {
    let resp = http
        .get(format!("{BASE}/email-footprint"))
        .header("x-api-key", key)
        .query(&[("query", email)])
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

async fn fetch_breach(
    http: &reqwest::Client,
    key: &str,
    email: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<OcBreachResponse> {
    let resp = http
        .get(format!("{BASE}/breach"))
        .header("x-api-key", key)
        .query(&[("query", email)])
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    crate::util::http::json_scanned(resp, SRC)
        .await
        .map_err(|e| Error::module(SRC, e))
}

async fn fetch_email_osint(
    http: &reqwest::Client,
    key: &str,
    email: &str,
    ctx: &crate::core::module::ModuleContext,
) -> Result<Value> {
    let resp = http
        .get(format!("{BASE}/email-osint"))
        .header("x-api-key", key)
        .header("x-purpose", PURPOSE)
        .query(&[("query", email)])
        .send()
        .await
        .map_err(|e| Error::module(SRC, e.to_string()))?;
    if !resp.status().is_success() {
        crate::util::http::note_keyed_error(resp.status().as_u16(), SRC, key, ctx);
        return Err(crate::util::http::http_status_error(SRC, resp).await);
    }
    crate::util::http::json_scanned(resp, SRC)
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
                    let mut pivot = Entity::new(EntityKind::Username, uname, 0.70, &entity.scan_id);
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

// ── Utilities ──────────────────────────────────────────────────────────────────

/// Lowercase + replace non-alphanumeric runs with `-`, strip leading/trailing.
fn slugify(s: &str) -> String {
    let mut slug = String::with_capacity(s.len());
    let mut last_dash = true;
    for ch in s.chars() {
        if ch.is_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }
    if slug.ends_with('-') {
        slug.pop();
    }
    slug
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_only() {
        let m = OsintCat;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    }

    #[test]
    fn slugify_normalises() {
        assert_eq!(slugify("github.com"), "github-com");
        assert_eq!(slugify("Stealer Logs"), "stealer-logs");
        assert_eq!(slugify("LinkedIn 2021"), "linkedin-2021");
        assert_eq!(slugify("---"), "");
    }

    #[test]
    fn emit_breach_tags_entity() {
        let br = OcBreachResponse {
            results_count: 2,
            breach_data: vec![
                serde_json::json!({"source": "ExampleLeak", "breach_date": "2021-01-01"}),
            ],
        };
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut entity = target.to_entity(0.75, "s");
        emit_breach(&br, &mut entity);
        assert!(entity.has_tag("breach"));
        assert!(entity.has_tag("osintcat:breach:exampleleak"));
        assert!(!entity.evidence.is_empty());
    }

    #[test]
    fn emit_breach_noop_on_zero() {
        let br = OcBreachResponse {
            results_count: 0,
            breach_data: vec![],
        };
        let target = Target::new(TargetKind::Email, "x@y.com");
        let mut entity = target.to_entity(0.75, "s");
        emit_breach(&br, &mut entity);
        assert!(!entity.has_tag("breach"));
        assert!(entity.evidence.is_empty());
    }
}
