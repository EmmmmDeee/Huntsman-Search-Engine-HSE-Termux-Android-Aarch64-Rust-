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
use crate::util::http::RequestBuilderExt;
use crate::util::http::urlencode;

#[cfg(test)]
mod tests;

pub(super) const KEY_ENV: &str = "HUNTSMAN_OPENCORP_KEY";
pub(super) const SRC: &str = "opencorporates";

/// Companies to request and map per search — the free tier is generous but a
/// generic name can match thousands; the first page is plenty to pivot on.
pub(super) const PER_PAGE: usize = 5;
/// A registered address shorter than this is too sparse to be a usable
/// `Address` entity (e.g. a bare state code).
pub(super) const MIN_ADDRESS_LEN: usize = 5;

/// Map one OpenCorporates company record to its entities. **Pure** (no
/// network/IO): always yields the `Organisation` (tagged with jurisdiction /
/// active status and all present registry fields as evidence), and additionally
/// a `validated` `Address` entity when a usable registered address is present and
/// an `AbnAcn` company-number entity for AU registrations. `total` is the
/// search's full match count, carried on the org evidence. Returns an empty `Vec`
/// for a record with no usable name.
pub(super) fn build_company_entities(co: &OcCompany, total: u64, scan_id: &str) -> Vec<Entity> {
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

    let mut ev = [
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
    ]
    .into_iter()
    .filter_map(|(attr, val)| val.map(|v| (attr, v)))
    .fold(
        Evidence::new(SRC, format!("OpenCorporates: {name}")),
        |ev, (attr, v)| ev.with_attr(attr, v),
    );
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
        ae.tag("geoint");
        if let Some(sc) = crate::util::address_au::state_code(addr) {
            ae.tag(format!("au-state:{sc}"));
            ae.tag("country:AU");
        }
        ae.add_evidence(Evidence::new(SRC, format!("Registered address for {name}")));
        out.push(ae);

        if let Some((lat, lon)) = crate::util::city_coords::city_coords(addr) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.62, scan_id);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("opencorporates");
            if let Some(sc) = crate::util::address_au::state_code(addr) {
                c.tag(format!("au-state:{sc}"));
                c.tag("country:AU");
            }
            c.add_evidence(Evidence::new(
                SRC,
                format!("Inline geocode of registered address '{addr}' → {coord_val}"),
            ));
            out.push(c);
        }
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
pub(super) struct OcResp {
    #[serde(default)]
    pub(super) results: Option<OcResults>,
}

#[derive(Deserialize)]
pub(super) struct OcResults {
    #[serde(default)]
    pub(super) companies: Vec<OcCompanyWrapper>,
    #[serde(default)]
    pub(super) total_count: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct OcCompanyWrapper {
    #[serde(default)]
    pub(super) company: Option<OcCompany>,
}

#[derive(Deserialize)]
pub(super) struct OcCompany {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) company_number: Option<String>,
    #[serde(default)]
    pub(super) jurisdiction_code: Option<String>,
    #[serde(default)]
    pub(super) incorporation_date: Option<String>,
    #[serde(default)]
    pub(super) dissolution_date: Option<String>,
    #[serde(default)]
    pub(super) company_type: Option<String>,
    #[serde(default)]
    pub(super) current_status: Option<String>,
    #[serde(default)]
    pub(super) registered_address_in_full: Option<String>,
    #[serde(default)]
    pub(super) opencorporates_url: Option<String>,
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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A company registry: it establishes the business and its officers
        // (T1591.002 Business Relationships + T1591.004 Identify Roles) and
        // geocodes the registered address to coordinates, so it also Determines
        // Physical Locations (T1591.001) — which the Corporate default omits.
        &["T1591.001", "T1591.002", "T1591.004"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
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
            .send_tagged(SRC)
            .await?;

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

        let body: OcResp = crate::util::http::json_decode(SRC, resp).await?;

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

        result.extend(
            results
                .companies
                .iter()
                .take(PER_PAGE)
                .filter_map(|wrapper| wrapper.company.as_ref())
                .flat_map(|co| build_company_entities(co, total, &ctx.scan_id)),
        );

        Ok(result)
    }
}
