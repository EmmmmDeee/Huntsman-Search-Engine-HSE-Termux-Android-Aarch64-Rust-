//! OpenCorporates — Australian company director and shell-company lookup.
//!
//! Endpoint: `GET https://api.opencorporates.com/v0.4/companies/search?q={name}&jurisdiction_code=au`
//! Auth:     API Token (`HUNTSMAN_OPENCORP_KEY`). As of 2026 the keyless free
//!           tier returns `401 Invalid Api Token`, so without a token the
//!           endpoint yields no data — that 401/403 is treated as an empty
//!           result, not a module error (an expected "needs key" condition).
//!
//! Cross-references company names, directors, and registration details
//! against the global OpenCorporates dataset with Australian jurisdiction focus.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const KEY_ENV: &str = "HUNTSMAN_OPENCORP_KEY";
const SRC: &str = "opencorporates";

pub struct OpenCorporates;

#[derive(Deserialize)]
struct OcResp {
    #[serde(default)]
    results: Option<OcResults>,
}

#[derive(Deserialize)]
struct OcResults {
    #[serde(default)]
    companies: Vec<OcCompanyWrapper>,
    #[serde(default)]
    total_count: Option<u64>,
}

#[derive(Deserialize)]
struct OcCompanyWrapper {
    #[serde(default)]
    company: Option<OcCompany>,
}

#[derive(Deserialize)]
struct OcCompany {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    company_number: Option<String>,
    #[serde(default)]
    jurisdiction_code: Option<String>,
    #[serde(default)]
    incorporation_date: Option<String>,
    #[serde(default)]
    dissolution_date: Option<String>,
    #[serde(default)]
    company_type: Option<String>,
    #[serde(default)]
    current_status: Option<String>,
    #[serde(default)]
    registered_address_in_full: Option<String>,
    #[serde(default)]
    opencorporates_url: Option<String>,
}

#[async_trait]
impl Module for OpenCorporates {
    fn name(&self) -> &'static str {
        "opencorporates"
    }
    fn description(&self) -> &'static str {
        "OpenCorporates company/director search with Australian jurisdiction focus"
    }
    fn priority(&self) -> u8 {
        80
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::FullName | TargetKind::AbnAcn
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.is_empty() || query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let mut url = format!(
            "https://api.opencorporates.com/v0.4/companies/search?q={}&jurisdiction_code=au&per_page=5",
            urlencode(query),
        );

        if let Some(key) = ctx.key_opt(KEY_ENV) {
            url.push_str(&format!("&api_token={}", urlencode(key)));
        }

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            // 401/403 (auth required — the keyless free tier is gone), 404 (no
            // match), and 429 (rate limited) are expected, non-fault outcomes:
            // degrade to an empty result instead of inflating modules_errored
            // and logging a WARN on every keyless name/org/abn scan. Any other
            // status is a genuine error worth surfacing.
            if status_is_soft_empty(status.as_u16()) {
                return Ok(ModuleResult::new());
            }
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let body: OcResp = resp
            .json()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let Some(results) = body.results else {
            return Ok(ModuleResult::new());
        };
        if results.companies.is_empty() {
            return Ok(ModuleResult::new());
        }

        let total = results
            .total_count
            .unwrap_or(results.companies.len() as u64);
        let mut result = ModuleResult::new();

        for wrapper in results.companies.iter().take(5) {
            let Some(co) = &wrapper.company else {
                continue;
            };
            let Some(name) = co.name.as_deref() else {
                continue;
            };
            if name.is_empty() {
                continue;
            }

            let mut entity = Entity::new(EntityKind::Organisation, name, 0.75, &ctx.scan_id);
            entity.tag("opencorporates");
            if co.jurisdiction_code.as_deref() == Some("au") {
                entity.tag("country:AU");
            }
            if co.current_status.as_deref() == Some("Active") {
                entity.tag("active");
            }

            let mut ev = Evidence::new(SRC, format!("OpenCorporates: {name}"));
            if let Some(num) = co.company_number.as_deref() {
                ev = ev.with_attr("company_number", num);
            }
            if let Some(jc) = co.jurisdiction_code.as_deref() {
                ev = ev.with_attr("jurisdiction", jc);
            }
            if let Some(inc) = co.incorporation_date.as_deref() {
                ev = ev.with_attr("incorporation_date", inc);
            }
            if let Some(dis) = co.dissolution_date.as_deref() {
                ev = ev.with_attr("dissolution_date", dis);
            }
            if let Some(ct) = co.company_type.as_deref() {
                ev = ev.with_attr("company_type", ct);
            }
            if let Some(cs) = co.current_status.as_deref() {
                ev = ev.with_attr("status", cs);
            }
            if let Some(addr) = co.registered_address_in_full.as_deref() {
                ev = ev.with_attr("registered_address", addr);
            }
            if let Some(url_str) = co.opencorporates_url.as_deref() {
                ev = ev.with_attr("opencorporates_url", url_str);
            }
            ev = ev.with_attr("total_matches", total.to_string());
            entity.add_evidence(ev);
            result.push(entity);

            if let Some(addr) = co.registered_address_in_full.as_deref()
                && addr.len() >= 5
            {
                let mut ae = Entity::new(EntityKind::Address, addr, 0.70, &ctx.scan_id);
                ae.tag("opencorporates");
                ae.tag("registered-address");
                ae.tag("validated");
                ae.add_evidence(Evidence::new(SRC, format!("Registered address for {name}")));
                result.push(ae);
            }

            if let Some(num) = co.company_number.as_deref()
                && !num.is_empty()
                && co.jurisdiction_code.as_deref() == Some("au")
            {
                let mut acn = Entity::new(EntityKind::AbnAcn, num, 0.80, &ctx.scan_id);
                acn.tag("opencorporates");
                acn.tag("company-number");
                acn.add_evidence(
                    Evidence::new(SRC, format!("AU company number for {name}"))
                        .with_attr("company_name", name),
                );
                result.push(acn);
            }
        }

        Ok(result)
    }
}

/// Non-2xx statuses that are expected, non-fault outcomes and should degrade
/// to an empty result rather than a module error:
///   * 401 / 403 — auth required (the keyless free tier returns 401 as of 2026)
///   * 404       — no company matched the query
///   * 429       — rate limited
fn status_is_soft_empty(code: u16) -> bool {
    matches!(code, 401 | 403 | 404 | 429)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_no_match_statuses_are_soft_empty() {
        // 401 is what the keyless free tier returns now — must not be a fault.
        assert!(status_is_soft_empty(401));
        assert!(status_is_soft_empty(403));
        assert!(status_is_soft_empty(404));
        assert!(status_is_soft_empty(429));
        // Real server faults must still surface as errors.
        assert!(!status_is_soft_empty(500));
        assert!(!status_is_soft_empty(502));
        assert!(!status_is_soft_empty(400));
    }

    #[test]
    fn accepts_org_and_fullname() {
        let m = OpenCorporates;
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Atlassian")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "John Smith")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(OpenCorporates.name(), "opencorporates");
        assert_eq!(OpenCorporates.priority(), 80);
        assert_eq!(OpenCorporates.max_timeout_ms(), 10_000);
    }

    #[test]
    fn parse_response() {
        let raw = r#"{
            "results": {
                "companies": [{
                    "company": {
                        "name": "ATLASSIAN PTY LTD",
                        "company_number": "111222333",
                        "jurisdiction_code": "au",
                        "incorporation_date": "2002-01-01",
                        "company_type": "Australian Proprietary Company",
                        "current_status": "Active",
                        "registered_address_in_full": "Level 6, 341 George Street, Sydney NSW 2000",
                        "opencorporates_url": "https://opencorporates.com/companies/au/111222333"
                    }
                }],
                "total_count": 1
            }
        }"#;
        let r: OcResp = serde_json::from_str(raw).unwrap();
        let results = r.results.unwrap();
        let co = results.companies[0].company.as_ref().unwrap();
        assert_eq!(co.name.as_deref(), Some("ATLASSIAN PTY LTD"));
        assert_eq!(co.jurisdiction_code.as_deref(), Some("au"));
    }
}
