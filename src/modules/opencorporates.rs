//! OpenCorporates — Australian company director and shell-company lookup.
//!
//! Endpoint: `GET https://api.opencorporates.com/v0.4/companies/search?q={name}&jurisdiction_code=au`
//! Auth:     Optional API Token (`HUNTSMAN_OPENCORP_KEY`). Free tier is generous.
//!
//! Cross-references company names, directors, and registration details
//! against the global OpenCorporates dataset with Australian jurisdiction focus.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const KEY_ENV: &str = "HUNTSMAN_OPENCORP_KEY";
const SRC: &str = "opencorporates";

/// Companies to request and map per search — the free tier is generous but a
/// generic name can match thousands; the first page is plenty to pivot on.
const PER_PAGE: usize = 5;
/// A registered address shorter than this is too sparse to be a usable
/// `Address` entity (e.g. a bare state code).
const MIN_ADDRESS_LEN: usize = 5;

/// Map one OpenCorporates company record to its entities. **Pure** (no
/// network/IO): always yields the `Organisation` (tagged with jurisdiction /
/// active status and all present registry fields as evidence), and additionally
/// a `validated` `Address` entity when a usable registered address is present and
/// an `AbnAcn` company-number entity for AU registrations. `total` is the
/// search's full match count, carried on the org evidence. Returns an empty `Vec`
/// for a record with no usable name.
fn build_company_entities(co: &OcCompany, total: u64, scan_id: &str) -> Vec<Entity> {
    let Some(name) = co.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) else {
        return Vec::new();
    };

    let mut out = Vec::new();

    let mut entity = Entity::new(EntityKind::Organisation, name, 0.75, scan_id);
    entity.tag("opencorporates");
    if co.jurisdiction_code.as_deref() == Some("au") {
        entity.tag("country:AU");
    }
    if co.current_status.as_deref() == Some("Active") {
        entity.tag("active");
    }

    let mut ev = Evidence::new(SRC, format!("OpenCorporates: {name}"));
    for (attr, val) in [
        ("company_number", co.company_number.as_deref()),
        ("jurisdiction", co.jurisdiction_code.as_deref()),
        ("incorporation_date", co.incorporation_date.as_deref()),
        ("dissolution_date", co.dissolution_date.as_deref()),
        ("company_type", co.company_type.as_deref()),
        ("status", co.current_status.as_deref()),
        (
            "registered_address",
            co.registered_address_in_full.as_deref(),
        ),
        ("opencorporates_url", co.opencorporates_url.as_deref()),
    ] {
        if let Some(v) = val {
            ev = ev.with_attr(attr, v);
        }
    }
    ev = ev.with_attr("total_matches", total.to_string());
    entity.add_evidence(ev);
    out.push(entity);

    // Trim first: a whitespace-only/short address would normalise to a blank
    // `Address` entity. The length floor (≥ MIN_ADDRESS_LEN) then implies non-empty.
    if let Some(addr) = co.registered_address_in_full.as_deref().map(str::trim)
        && addr.len() >= MIN_ADDRESS_LEN
    {
        let mut ae = Entity::new(EntityKind::Address, addr, 0.70, scan_id);
        ae.tag("opencorporates");
        ae.tag("registered-address");
        ae.tag("validated");
        ae.add_evidence(Evidence::new(SRC, format!("Registered address for {name}")));
        out.push(ae);
    }

    if let Some(num) = co.company_number.as_deref()
        && !num.is_empty()
        && co.jurisdiction_code.as_deref() == Some("au")
    {
        let mut acn = Entity::new(EntityKind::AbnAcn, num, 0.80, scan_id);
        acn.tag("opencorporates");
        acn.tag("company-number");
        acn.add_evidence(
            Evidence::new(SRC, format!("AU company number for {name}"))
                .with_attr("company_name", name),
        );
        out.push(acn);
    }

    out
}

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
        // Government / public-records band (110-118): company registry, dispatched
        // just below abn_lookup and above the generic free modules.
        116
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

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.is_empty() || query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let mut url = format!(
            "https://api.opencorporates.com/v0.4/companies/search?q={}&jurisdiction_code=au&per_page={PER_PAGE}",
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
        // Graceful no-op statuses. OpenCorporates' v0.4 search now answers 401
        // (sometimes 403) to unauthenticated callers — its keyless public tier
        // was withdrawn — so on a no-key scan this means "nothing to do", not an
        // error worth a WARN (observed live: a keyless FullName scan logged
        // `module error … HTTP 401 Unauthorized`). 404 = no match, 429 = rate
        // limited. All degrade to an empty result (the module is best-effort).
        // A *configured* key that gets 401/403 is a bad key, also nothing to
        // surface as a scan error — the key pool handles key health separately.
        if matches!(status.as_u16(), 401 | 403 | 404 | 429) {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
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

        for wrapper in results.companies.iter().take(PER_PAGE) {
            if let Some(co) = &wrapper.company {
                for e in build_company_entities(co, total, &ctx.scan_id) {
                    result.push(e);
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Government / public-records band (see priority() doc).
        assert_eq!(OpenCorporates.priority(), 116);
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

    fn company(json: &str) -> OcCompany {
        serde_json::from_str(json).unwrap()
    }

    fn org_attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn au_company_yields_org_address_and_company_number() {
        let co = company(
            r#"{
                "name":"ATLASSIAN PTY LTD","company_number":"111222333",
                "jurisdiction_code":"au","incorporation_date":"2002-01-01",
                "current_status":"Active",
                "registered_address_in_full":"Level 6, 341 George Street, Sydney NSW 2000",
                "opencorporates_url":"https://opencorporates.com/companies/au/111222333"
            }"#,
        );
        let ents = build_company_entities(&co, 7, "s");
        // Org + Address + AbnAcn.
        assert_eq!(ents.len(), 3);

        let org = &ents[0];
        assert_eq!(org.kind, EntityKind::Organisation);
        assert!(
            org.has_tag("opencorporates") && org.has_tag("country:AU") && org.has_tag("active")
        );
        assert_eq!(org_attr(org, "company_number"), Some("111222333"));
        assert_eq!(org_attr(org, "status"), Some("Active"));
        assert_eq!(org_attr(org, "total_matches"), Some("7"));

        assert_eq!(ents[1].kind, EntityKind::Address);
        assert!(ents[1].has_tag("registered-address") && ents[1].has_tag("validated"));

        assert_eq!(ents[2].kind, EntityKind::AbnAcn);
        assert!(ents[2].has_tag("company-number"));
        assert_eq!(ents[2].value, "111222333");
    }

    #[test]
    fn non_au_company_omits_company_number_entity() {
        // A non-AU jurisdiction → no AbnAcn entity, no country:AU / no active tag.
        let co = company(
            r#"{"name":"Globex Inc","company_number":"C-99","jurisdiction_code":"us",
                "current_status":"Dissolved",
                "registered_address_in_full":"1 Market St, San Francisco"}"#,
        );
        let ents = build_company_entities(&co, 1, "s");
        // Org + Address only (no AU company-number).
        assert_eq!(ents.len(), 2);
        assert!(!ents[0].has_tag("country:AU") && !ents[0].has_tag("active"));
        assert!(ents.iter().all(|e| e.kind != EntityKind::AbnAcn));
    }

    #[test]
    fn short_address_and_missing_number_drop_optional_entities() {
        let co = company(
            r#"{"name":"Tiny Co","jurisdiction_code":"au","registered_address_in_full":"NSW"}"#,
        );
        let ents = build_company_entities(&co, 1, "s");
        // Address too short (< MIN_ADDRESS_LEN) and no company_number → org only.
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].kind, EntityKind::Organisation);
    }

    #[test]
    fn whitespace_address_does_not_create_blank_entity() {
        // A whitespace-only registered address must not become an Address entity.
        let co = company(
            r#"{"name":"Acme","jurisdiction_code":"au","registered_address_in_full":"        "}"#,
        );
        let ents = build_company_entities(&co, 1, "s");
        assert!(ents.iter().all(|e| e.kind != EntityKind::Address));
    }

    #[test]
    fn blank_name_yields_nothing() {
        assert!(build_company_entities(&company(r#"{"name":"   "}"#), 1, "s").is_empty());
        assert!(build_company_entities(&company("{}"), 1, "s").is_empty());
    }
}
