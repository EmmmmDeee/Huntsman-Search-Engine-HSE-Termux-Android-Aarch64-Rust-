//! Hunter.io — find email addresses associated with a domain.
//!
//! Endpoint: `GET https://api.hunter.io/v2/domain-search?domain={d}&api_key={k}`
//! Auth:     `api_key` query param. Key-gated (`HUNTSMAN_HUNTER_KEY`).
//! Free tier: 25 searches/month, 50 verifications/month.
//!
//! The single highest-leverage gap for HSE's identity-enrichment
//! chain: a Domain → list-of-Emails pivot. Pairs naturally with
//! `email_parse` (parsed Emails feed back as new targets) and
//! `hibp` (each discovered Email gets a breach check).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const KEY_ENV: &str = "HUNTSMAN_HUNTER_KEY";
const SRC: &str = "hunter_io";

pub struct HunterIo;

#[derive(Deserialize)]
struct Wrap {
    #[serde(default)]
    data: Option<HunterData>,
    /// Hunter occasionally returns HTTP 200 with an `errors` array
    /// instead of `data` when the key is rate-limited or out of
    /// quota for the current plan. Capture so we report the key
    /// exhausted rather than silently emitting an empty result.
    #[serde(default)]
    errors: Vec<HunterApiError>,
}

#[derive(Deserialize)]
struct HunterApiError {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    details: Option<String>,
}

#[derive(Deserialize)]
struct HunterData {
    #[allow(dead_code)]
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    emails: Vec<HunterEmail>,
}

#[derive(Deserialize)]
struct HunterEmail {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    position: Option<String>,
    #[serde(default)]
    department: Option<String>,
    #[serde(default)]
    sources: Vec<HunterSource>,
}

#[derive(Deserialize)]
struct HunterSource {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    uri: Option<String>,
}

#[async_trait]
impl Module for HunterIo {
    fn name(&self) -> &'static str {
        "hunter_io"
    }

    fn description(&self) -> &'static str {
        "Email-finder: enumerate addresses associated with a target domain"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Email
    }

    fn priority(&self) -> u8 {
        62
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::Domain]
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[
            EntityKind::Email,
            EntityKind::Person,
            EntityKind::Organisation,
        ]
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(key) = ctx.key_opt(KEY_ENV) else {
            return Ok(ModuleResult::new());
        };
        let domain = target.value.trim();
        if domain.is_empty() {
            return Ok(ModuleResult::new());
        }

        let url = format!(
            "https://api.hunter.io/v2/domain-search?domain={}&api_key={}",
            crate::util::http::urlencode(domain),
            crate::util::http::urlencode(key),
        );

        let resp = ctx
            .http
            .get(&url)
            .send()
            .await
            // `without_url()` strips the URL (which carries the API key
            // as a query param) before formatting, so transport errors
            // don't leak the key into logs / events.
            .map_err(|e| Error::module(SRC, e.without_url().to_string()))?;
        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            ctx.report_key_exhausted(SRC, key, status.as_u16());
            return Err(Error::module(
                SRC,
                format!("HTTP {status}: invalid or expired API key"),
            ));
        }
        if status.as_u16() == 429 {
            ctx.report_key_exhausted(SRC, key, 429);
            return Err(Error::module(SRC, "rate-limited (429)"));
        }
        if !status.is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
        }

        let wrap: Wrap = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, format!("JSON: {e}")))?;
        // HTTP-200-with-errors array: Hunter signals quota / scope /
        // plan problems out-of-band of the HTTP status. Mark the
        // key exhausted instead of silently returning empty.
        if !wrap.errors.is_empty() {
            let first = &wrap.errors[0];
            let detail = first
                .details
                .as_deref()
                .or(first.id.as_deref())
                .unwrap_or("api error");
            ctx.report_key_exhausted(SRC, key, 200);
            return Err(Error::module(SRC, format!("api 200 error: {detail}")));
        }
        let Some(data) = wrap.data else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();

        // ── Organisation entity (if Hunter resolved one for the domain) ──
        if let Some(org) = data.organization.as_deref().filter(|s| !s.is_empty()) {
            let mut e = Entity::new(EntityKind::Organisation, org, 0.70, &ctx.scan_id);
            e.tag("hunter-io");
            let mut ev =
                Evidence::new(SRC, format!("Hunter.io resolved organisation for {domain}"))
                    .with_attr("domain", domain);
            if let Some(c) = data.country.as_deref() {
                ev = ev.with_attr("country", c);
            }
            if let Some(p) = data.pattern.as_deref() {
                ev = ev.with_attr("email_pattern", p);
            }
            e.add_evidence(ev);
            result.push(e);
        }

        // ── Email entities + co-located Person entities ──
        for entry in &data.emails {
            let Some(addr) = entry.value.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let conf = confidence_from_hunter_score(entry.confidence);
            let mut ee = Entity::new(EntityKind::Email, addr, conf, &ctx.scan_id);
            ee.tag("hunter-io");
            ee.tag("email-finder");
            let mut ev = Evidence::new(SRC, format!("Hunter.io email for {domain}"))
                .with_attr("domain", domain)
                .with_attr(
                    "hunter_confidence",
                    entry.confidence.unwrap_or(0).to_string(),
                );
            if let Some(p) = entry.position.as_deref() {
                ev = ev.with_attr("position", p);
            }
            if let Some(d) = entry.department.as_deref() {
                ev = ev.with_attr("department", d);
            }
            if let Some(src) = entry.sources.first()
                && let Some(uri) = src.uri.as_deref()
            {
                ev = ev.with_attr("source_url", uri);
                if let Some(d) = src.domain.as_deref() {
                    ev = ev.with_attr("source_domain", d);
                }
            }
            ee.add_evidence(ev);
            result.push(ee);

            // ── Person entity if Hunter has a name attached ──
            if let (Some(first), Some(last)) = (
                entry.first_name.as_deref().filter(|s| !s.is_empty()),
                entry.last_name.as_deref().filter(|s| !s.is_empty()),
            ) {
                let full = format!("{first} {last}");
                let mut pe = Entity::new(EntityKind::Person, &full, conf.min(0.75), &ctx.scan_id);
                pe.tag("hunter-io");
                pe.tag("email-attribution");
                let mut pev = Evidence::new(SRC, format!("Hunter.io attributed {addr} to {full}"))
                    .with_attr("email", addr)
                    .with_attr("domain", domain);
                if let Some(p) = entry.position.as_deref() {
                    pev = pev.with_attr("position", p);
                }
                pe.add_evidence(pev);
                result.push(pe);
            }
        }

        Ok(result)
    }
}

/// Map Hunter's 0-100 confidence score to an HSE confidence in
/// [0.0, 1.0]. Buckets follow Hunter's own tier semantics:
/// 90+ verified, 70-89 high, 40-69 medium, 1-39 low, explicit 0 or
/// missing → uncertain (None and Some(0) collapse to the same
/// floor — an explicit 0 from Hunter means "no signal", which
/// shouldn't outrank a missing field).
fn confidence_from_hunter_score(score: Option<u8>) -> f64 {
    match score {
        Some(c) if c >= 90 => 0.85,
        Some(c) if c >= 70 => 0.70,
        Some(c) if c >= 40 => 0.55,
        Some(c) if c > 0 => 0.45,
        _ => 0.50,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_domain_only() {
        let m = HunterIo;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn cost_is_key_gated() {
        assert_eq!(HunterIo.cost(), ModuleCost::KeyGated);
    }

    #[test]
    fn category_is_email() {
        assert!(matches!(HunterIo.category(), ModuleCategory::Email));
    }

    #[test]
    fn description_is_non_empty() {
        assert!(!HunterIo.description().is_empty());
    }

    #[test]
    fn produces_email_person_organisation() {
        let kinds = HunterIo.produces();
        assert!(kinds.contains(&EntityKind::Email));
        assert!(kinds.contains(&EntityKind::Person));
        assert!(kinds.contains(&EntityKind::Organisation));
    }

    #[test]
    fn confidence_mapping_for_hunter_confidence_score() {
        // Drive the public helper so the test catches threshold drift
        // (previously the test re-implemented the match arms and
        // asserted against its own copy).
        let cases: [(Option<u8>, f64); 7] = [
            (Some(95), 0.85),
            (Some(75), 0.70),
            (Some(50), 0.55),
            (Some(20), 0.45),
            (Some(1), 0.45),
            (Some(0), 0.50), // explicit 0 collapses to unknown floor
            (None, 0.50),
        ];
        for (input, expected) in cases {
            let got = confidence_from_hunter_score(input);
            assert!(
                (got - expected).abs() < f64::EPSILON,
                "confidence {input:?} → {got} (expected {expected})"
            );
        }
    }
}
