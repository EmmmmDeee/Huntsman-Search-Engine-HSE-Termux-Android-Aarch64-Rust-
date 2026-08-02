//! OpenCorporates — global company and officer/director lookup (~140
//! jurisdictions), with an Australia-only restriction applied solely to
//! `AbnAcn` targets.
//!
//! Two endpoints sharing the same auth:
//!   * Company search:  `GET /v0.4/companies/search?q={name}`
//!   * Officer search:  `GET /v0.4/officers/search?q={name}`
//!
//! `jurisdiction_code=au` is appended ONLY for an `AbnAcn` target — an
//! Australian Business/Company Number is Australian by construction, so it
//! could never appear in a non-AU registry, and restricting the search saves
//! API quota. `Organisation`/`FullName` targets carry no jurisdiction signal,
//! so they search OpenCorporates' full index rather than assuming AU — the
//! entity-mapping ([`build_company_entities`]/[`build_officer_entities`]) is
//! already jurisdiction-agnostic: it mints the AU-specific `AbnAcn`/
//! `country:AU` tag only when the response itself reports
//! `jurisdiction_code == "au"`, regardless of what was searched.
//!
//! Auth:     Required API Token (`HUNTSMAN_OPENCORP_KEY`, sent as
//!           `&api_token=`). OpenCorporates withdrew its keyless public tier
//!           in late 2023 — every unauthenticated request now returns
//!           `401 {"error":{"message":"Invalid Api Token…"}}` — so the module
//!           is [`ModuleCost::KeyGated`]: an unconfigured scan is a clean
//!           "needs key" skip rather than a silent no-op.
//!
//! Company search is used for `Organisation`/`AbnAcn` targets; officer search
//! is used for `FullName` targets to find companies where the person serves as
//! a director — the correct pivot endpoint for people-to-company correlation.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
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
/// a `validated` `Address` entity when a usable registered address is present, a
/// pivotable `Url` entity for the record's own OpenCorporates profile page when
/// present, and an `AbnAcn` company-number entity for AU registrations. `total`
/// is the search's full match count, carried on the org evidence. Returns an
/// empty `Vec` for a record with no usable name.
pub(super) fn build_company_entities(co: &OcCompany, total: u64, scan_id: &str) -> Vec<Entity> {
    let Some(name) = co.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) else {
        return Vec::new();
    };

    let mut out = Vec::new();

    let mut entity = Entity::new(
        EntityKind::Organisation,
        name,
        confidence::VERY_HIGH,
        scan_id,
    );
    entity.tag("opencorporates");
    if co.jurisdiction_code.as_deref() == Some("au") {
        entity.tag("country:AU");
    }
    match co.current_status.as_deref() {
        Some("Active") => {
            entity.tag("active");
        }
        Some(s) if !s.is_empty() => {
            entity.tag("inactive");
        }
        _ => {}
    }
    if co
        .dissolution_date
        .as_deref()
        .is_some_and(|d| !d.is_empty())
    {
        entity.tag("dissolved");
        // A dissolved company is less likely to be the current operating entity;
        // pull confidence down slightly so live entities rank above it.
        entity.confidence = (entity.confidence - 0.10).max(0.10);
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
        let mut ae = Entity::new(EntityKind::Address, addr, confidence::HIGH_PLUS, scan_id);
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
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::NOTABLE,
                scan_id,
            );
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

    emit_profile_url_and_company_number(
        &mut out,
        name,
        co.opencorporates_url.as_deref(),
        co.company_number.as_deref(),
        co.jurisdiction_code.as_deref(),
        confidence::HIGH_PLUSPLUS,
        scan_id,
    );

    out
}

/// Emit the `Url` profile-page entity and, for an AU company, the `AbnAcn`
/// company-number entity — the tail every OpenCorporates result (a full
/// company record or an officer's `company`) shares regardless of which
/// search produced it. `acn_confidence` is the one genuine difference
/// between callers: a direct company search
/// ([`build_company_entities`], `confidence::HIGH_PLUSPLUS`) is a more
/// direct hit than a company reached via an officer search
/// ([`build_officer_entities`], `confidence::STRONG`).
#[allow(clippy::too_many_arguments)]
fn emit_profile_url_and_company_number(
    out: &mut Vec<Entity>,
    name: &str,
    opencorporates_url: Option<&str>,
    company_number: Option<&str>,
    jurisdiction_code: Option<&str>,
    acn_confidence: f64,
    scan_id: &str,
) {
    if let Some(url) = opencorporates_url.filter(|u| !u.is_empty()) {
        let mut ue = Entity::new(EntityKind::Url, url, 0.68, scan_id);
        ue.tag("opencorporates");
        ue.tag("profile-url");
        ue.add_evidence(Evidence::new(
            SRC,
            format!("OpenCorporates profile URL for {name}"),
        ));
        out.push(ue);
    }

    if let Some(num) = company_number
        && !num.is_empty()
        && jurisdiction_code == Some("au")
    {
        let mut acn = Entity::new(EntityKind::AbnAcn, num, acn_confidence, scan_id);
        acn.tag("opencorporates");
        acn.tag("company-number");
        acn.add_evidence(
            Evidence::new(SRC, format!("AU company number for {name}"))
                .with_attr("company_name", name),
        );
        out.push(acn);
    }
}

/// Build the OpenCorporates search URL for `target_kind`/`query` (the auth
/// token, if any, is appended separately by the caller). **Pure** — see the
/// module doc for why `jurisdiction_code=au` is appended only for an `AbnAcn`
/// target and omitted (searching all ~140 jurisdictions) for `Organisation`/
/// `FullName`.
pub(super) fn build_search_url(target_kind: TargetKind, query: &str) -> String {
    let endpoint = if target_kind == TargetKind::FullName {
        "officers"
    } else {
        "companies"
    };
    let jurisdiction_param = if target_kind == TargetKind::AbnAcn {
        "&jurisdiction_code=au"
    } else {
        ""
    };
    format!(
        "https://api.opencorporates.com/v0.4/{endpoint}/search?q={}{jurisdiction_param}&per_page={PER_PAGE}",
        urlencode(query),
    )
}

/// Whether this HTTP status means the configured key itself should be
/// reported to the pool: 401/403 (bad/expired key → `Invalid`) or 429
/// (rate-limited → `RateLimited`, its own recoverable cooldown window) —
/// `report_key_exhausted` tells the two apart from the status value itself.
/// 404 is a genuine no-match and reports nothing. Pure so this three-way
/// routing is unit-testable without a live HTTP call.
pub(super) fn should_report_key_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 429)
}

/// Officer search response: `/v0.4/officers/search`.
#[derive(Deserialize)]
pub(super) struct OcOfficerResp {
    #[serde(default)]
    pub(super) results: Option<OcOfficerResults>,
}

#[derive(Deserialize)]
pub(super) struct OcOfficerResults {
    #[serde(default)]
    pub(super) officers: Vec<OcOfficerWrapper>,
    #[serde(default)]
    pub(super) total_count: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct OcOfficerWrapper {
    #[serde(default)]
    pub(super) officer: Option<OcOfficer>,
}

#[derive(Deserialize)]
pub(super) struct OcOfficer {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) position: Option<String>,
    #[serde(default)]
    pub(super) company: Option<OcOfficerCompany>,
}

#[derive(Deserialize)]
pub(super) struct OcOfficerCompany {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) company_number: Option<String>,
    #[serde(default)]
    pub(super) jurisdiction_code: Option<String>,
    #[serde(default)]
    pub(super) current_status: Option<String>,
    #[serde(default)]
    pub(super) opencorporates_url: Option<String>,
}

/// Map one OpenCorporates officer record to entities. **Pure** (no network/IO):
/// emits the `Organisation` the person directs (if usable), a pivotable `Url`
/// entity for that company's own OpenCorporates profile page when present, an
/// `AbnAcn` for AU registrations, and a corroborating `Person` entity carrying
/// the officer name and position as evidence. `total` is the officer-search hit
/// count. Returns an empty `Vec` when neither the officer name nor the company
/// name is usable.
pub(super) fn build_officer_entities(
    officer: &OcOfficer,
    total: u64,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();

    let officer_name = officer
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| n.len() >= 2);
    let position = officer
        .position
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());

    if let Some(co) = officer.company.as_ref() {
        let co_name = co.name.as_deref().map(str::trim).filter(|n| !n.is_empty());
        if let Some(name) = co_name {
            let mut org = Entity::new(
                EntityKind::Organisation,
                name,
                confidence::ATTRIBUTED,
                scan_id,
            );
            org.tag("opencorporates");
            if co.jurisdiction_code.as_deref() == Some("au") {
                org.tag("country:AU");
            }
            if co.current_status.as_deref() == Some("Active") {
                org.tag("active");
            }
            let mut ev = Evidence::new(SRC, format!("OpenCorporates officer search: {name}"))
                .with_attr("total_matches", total.to_string());
            if let Some(p) = position {
                ev = ev.with_attr("officer_position", p);
            }
            if let Some(on) = officer_name {
                ev = ev.with_attr("officer_name", on);
            }
            if let Some(url) = co.opencorporates_url.as_deref() {
                ev = ev.with_attr("opencorporates_url", url);
            }
            if let Some(jur) = co.jurisdiction_code.as_deref() {
                ev = ev.with_attr("jurisdiction", jur);
            }
            org.add_evidence(ev);
            out.push(org);

            emit_profile_url_and_company_number(
                &mut out,
                name,
                co.opencorporates_url.as_deref(),
                co.company_number.as_deref(),
                co.jurisdiction_code.as_deref(),
                confidence::STRONG,
                scan_id,
            );
        }
    }

    // Corroborating Person entity for the officer name (confirms handle→identity).
    if let Some(name) = officer_name.filter(|n| n.contains(' ')) {
        let mut pe = Entity::new(EntityKind::Person, name, confidence::ATTRIBUTED, scan_id);
        pe.tag("opencorporates");
        pe.tag("officer");
        if let Some(p) = position {
            pe.tag(format!("role:{}", p.to_lowercase().replace(' ', "-")));
        }
        pe.add_evidence(
            Evidence::new(SRC, format!("OpenCorporates officer: {name}"))
                .with_attr("total_matches", total.to_string()),
        );
        out.push(pe);
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
        "OpenCorporates recon — enumerates global company and director records (AU-restricted for AbnAcn lookups)"
    }
    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): company registry, dispatched
        // just below abn_lookup and above the generic free modules.
        116
    }
    /// Key-gated: OpenCorporates withdrew its keyless public tier (late 2023) —
    /// every unauthenticated request now returns `401 {"error":{"message":
    /// "Invalid Api Token…"}}` (live-confirmed). While classified `Free` the
    /// module fired a doomed keyless request on every scan and swallowed the
    /// 401 into an empty result, so the operator was never told a key was
    /// required. `KeyGated` makes an unconfigured scan a clean "needs key" skip
    /// and lets `--free-only` skip it up front.
    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
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
            // Person: emitted from officer search (FullName targets only).
            EntityKind::Person,
            EntityKind::Url,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.is_empty() || query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        // Full names pivot through officer search (people → companies they direct);
        // organisation names and ABN/ACN numbers pivot through company search.
        let use_officer_search = target.kind == TargetKind::FullName;

        // Key-gated (the keyless tier was withdrawn): an unconfigured key
        // returns `Error::MissingKey`, which the dispatch finaliser renders as
        // a clean "needs key" skip with the signup hint — NOT the silent
        // 401-swallow the pre-fix `key_opt` path produced on every scan.
        let key = ctx.key(KEY_ENV)?;
        let mut url = build_search_url(target.kind, query);
        url.push_str(&format!("&api_token={}", urlencode(key)));

        let resp = ctx
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send_tagged(SRC)
            .await?;

        let status = resp.status();
        // A configured key that gets 401/403 is bad/expired, and a 429 means
        // it's rate-limited — report all three to the key pool for rotation
        // (401/403 were already reported; 429 was previously NOT, the one
        // inconsistency in this three-way handling despite
        // `is_keyed_error_status` grouping all three together — see
        // `should_report_key_status`). `report_key_exhausted` itself tells a
        // 429 (`RateLimited`, its own per-service cooldown window) apart from
        // a genuine 401/403 (`Invalid`), so the key recovers automatically
        // instead of this module silently degrading with no signal anywhere
        // that the key is currently rate-limited. 404 = a genuine no-match,
        // the only case that stays a plain empty result with no report.
        if should_report_key_status(status.as_u16()) {
            ctx.report_key_exhausted(SRC, key, status.as_u16());
            return Ok(ModuleResult::new());
        }
        if status.as_u16() == 404 {
            return Ok(ModuleResult::new());
        }
        if !status.is_success() {
            return Err(Error::module(SRC, format!("HTTP {status}")));
        }

        let mut result = ModuleResult::new();

        if use_officer_search {
            let body: OcOfficerResp = crate::util::http::json_decode(SRC, resp).await?;
            let Some(results) = body.results else {
                return Ok(result);
            };
            if results.officers.is_empty() {
                return Ok(result);
            }
            let total = results.total_count.unwrap_or(results.officers.len() as u64);
            result.extend(
                results
                    .officers
                    .iter()
                    .take(PER_PAGE)
                    .filter_map(|w| w.officer.as_ref())
                    .flat_map(|o| build_officer_entities(o, total, &ctx.scan_id)),
            );
        } else {
            let body: OcResp = crate::util::http::json_decode(SRC, resp).await?;
            let Some(results) = body.results else {
                return Ok(result);
            };
            if results.companies.is_empty() {
                return Ok(result);
            }
            let total = results
                .total_count
                .unwrap_or(results.companies.len() as u64);
            result.extend(
                results
                    .companies
                    .iter()
                    .take(PER_PAGE)
                    .filter_map(|wrapper| wrapper.company.as_ref())
                    .flat_map(|co| build_company_entities(co, total, &ctx.scan_id)),
            );
        }

        Ok(result)
    }
}
