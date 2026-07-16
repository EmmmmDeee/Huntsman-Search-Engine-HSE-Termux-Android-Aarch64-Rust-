//! ASIC Business Names register — keyless business/trading name → ABN.
//!
//! ASIC publishes the national Business Names register as open data on
//! data.gov.au, so a registered trading name can be resolved to the **ABN** of
//! the entity that holds it — its status, state, and registration date too —
//! with **no API key**. This is the keyless complement to
//! [`crate::modules::abn_lookup`] (which needs a free ABR GUID): for the
//! majority of Australian business entities it turns a business/trading name
//! into the ABN pivot that links it to the rest of the corporate stack
//! (`abn_lookup`, `asic_director`, `asic_persons`). Matched on all of the
//! target's name tokens and capped, since trading names collide. No mock: the
//! JSON is fetched live from ASIC's own dataset.

use serde_json::{Map, Value};

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{Response as CkanResp, datastore_search_url, field_str};
use crate::util::http::fetch_json;

const SRC: &str = "asic_business_names";
/// data.gov.au CKAN action base — `datastore_search` is appended by
/// [`datastore_search_url`].
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
/// ASIC – Business Names dataset (data.gov.au resource).
const RES: &str = "55ad4b1c-5eeb-44ea-8b29-d410da431be3";
/// Max matched registrations surfaced. Raised to the query `limit` so no genuine
/// business-name registration is omitted (directive: never omit an API-derived
/// AU government result).
const MAX_HITS: usize = 100;

pub struct AsicBusinessNames;

#[async_trait]
impl Module for AsicBusinessNames {
    fn name(&self) -> &'static str {
        "asic_business_names"
    }

    fn description(&self) -> &'static str {
        "ASIC Business Names register (keyless) — business/trading name → ABN, status, state, registration date"
    }

    fn priority(&self) -> u8 {
        111
    }

    fn accepts(&self, t: &Target) -> bool {
        // Kind-only; the multi-character name gate is applied in process().
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Resolves the entity behind a trading name — T1591.002 Business
        // Relationships. (No individual role/location, so the Corporate default's
        // T1591.004 is dropped.)
        &["T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let name = target.value.trim();
        let tokens = name_tokens(name);
        if name.len() < 3 || tokens.is_empty() {
            return Ok(result);
        }

        let records = ckan_query(ctx, name).await?;
        let mut seen = std::collections::HashSet::new();
        let mut matched_count = 0usize;
        for rec in records
            .iter()
            .filter(|r| record_name_matches(r, &tokens))
            .take(MAX_HITS)
        {
            matched_count += 1;
            emit_business_name(rec, &ctx.scan_id, &mut seen, &mut result);
        }

        if matched_count == 0 {
            return Ok(result);
        }

        // Signal if the matched set was truncated at the hard cap, so the
        // operator knows whether these are ALL registrations for the name or
        // just the first MAX_HITS (T2.140 — truncation-signaling pattern).
        let total_matches = records
            .iter()
            .filter(|r| record_name_matches(r, &tokens))
            .count();
        let matches_capped = total_matches > MAX_HITS;

        let mut seed = Entity::new(EntityKind::Organisation, name, 0.55, &ctx.scan_id);
        seed.tag("au");
        seed.tag("asic");
        seed.tag("search-result");
        let mut ev = Evidence::new(SRC, format!("ASIC Business Names search for `{name}`"))
            .with_attr("matched_count", matched_count.to_string())
            .with_attr("total_matches", total_matches.to_string());
        if matches_capped {
            ev = ev.with_attr("matches_capped", "true");
            seed.tag("truncated");
        }
        seed.add_evidence(ev);
        result.push(seed);

        Ok(result)
    }
}

/// Query the Business Names datastore by free-text name, via the shared CKAN
/// envelope (T2.118). Every real failure now surfaces instead of collapsing into
/// an empty `Vec` indistinguishable from "no registration by this name":
/// `fetch_json` propagates transport/status/parse failures via `?`, and a
/// `success == Some(false)` envelope (returned by CKAN with HTTP 200 on a bad
/// resource id / portal error) becomes an explicit `Error::module`. A genuine
/// empty result set is still the honest clean miss.
async fn ckan_query(ctx: &ModuleContext, name: &str) -> Result<Vec<Map<String, Value>>> {
    let url = datastore_search_url(CKAN_BASE, RES, name, MAX_HITS);
    let resp: CkanResp = fetch_json(&ctx.http, SRC, &url).await?;
    if resp.success == Some(false) {
        return Err(Error::module(
            SRC,
            "CKAN datastore_search returned success=false (bad resource id or portal error)",
        ));
    }
    Ok(resp.result.map(|r| r.records).unwrap_or_default())
}

/// Lower-cased alphanumeric name tokens (≥2 chars).
fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True if the record's `BN_NAME` contains every target token.
fn record_name_matches(rec: &Map<String, Value>, tokens: &[String]) -> bool {
    let Some(name) = field(rec, "BN_NAME") else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    tokens.iter().all(|t| lower.contains(t.as_str()))
}

/// Emit the confirmed registered name and — the prize — the holder's ABN.
fn emit_business_name(
    rec: &Map<String, Value>,
    scan_id: &str,
    seen_abn: &mut std::collections::HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(bn_name) = field(rec, "BN_NAME") else {
        return;
    };
    let status = field(rec, "BN_STATUS");

    let mut ev = Evidence::new(SRC, format!("ASIC business name `{bn_name}`"))
        .with_attr("register", "ASIC Business Names")
        .with_attr("business_name", &bn_name);
    for (key, attr) in [
        ("BN_STATUS", "status"),
        ("BN_STATE_OF_REG", "state"),
        ("BN_REG_DT", "registered"),
        ("BN_CANCEL_DT", "cancelled"),
        ("BN_ABN", "abn"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    // The confirmed registered trading name.
    let mut org = Entity::new(EntityKind::Organisation, &bn_name, 0.58, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag("business-name");
    if let Some(s) = status.as_deref() {
        org.tag(format!("status:{}", s.to_ascii_lowercase()));
    }
    org.add_evidence(ev.clone());
    result.push(org);

    // The ABN of the entity holding the name — a keyless pivot into the ABR.
    if let Some(abn) =
        field(rec, "BN_ABN").filter(|a| a.chars().filter(char::is_ascii_digit).count() == 11)
        && seen_abn.insert(abn.clone())
    {
        let mut e = Entity::new(EntityKind::AbnAcn, &abn, 0.62, scan_id);
        e.tag("au");
        e.tag("asic");
        e.tag("business-name");
        e.add_evidence(
            Evidence::new(SRC, format!("ABN holding business name `{bn_name}`"))
                .with_attr("abn", &abn)
                .with_attr("business_name", &bn_name),
        );
        result.push(e);
    }

    // The state of registration is a coarse AU jurisdiction anchor. Emit it as a
    // "{state}, Australia" Address tagged au-state — exactly as abn_lookup/acnc do
    // — so the registered jurisdiction participates in the AU geo/jurisdiction
    // correlators (AU-052/053/090) instead of dying in the evidence attr.
    if let Some(state) = field(rec, "BN_STATE_OF_REG")
        .as_deref()
        .and_then(crate::util::address_au::state_code)
    {
        let addr_value = format!("{state}, Australia");
        let mut addr = Entity::new(EntityKind::Address, &addr_value, 0.42, scan_id);
        addr.tag("au");
        addr.tag("asic");
        addr.tag("business-name");
        addr.tag("country:AU");
        addr.tag(format!("au-state:{state}"));
        addr.add_evidence(
            Evidence::new(
                SRC,
                format!("ASIC business name `{bn_name}` registered in {state}"),
            )
            .with_attr("state", state)
            .with_attr("business_name", &bn_name),
        );
        result.push(addr);
    }
}

/// A usable ASIC field value: the shared CKAN [`field_str`] stringification
/// (CONVENTIONS §4 — one stringifier, not a per-module copy) with this
/// register's `"null"` sentinel filter on top (`field_str` only drops JSON
/// null / empty, so the literal string `"null"` would otherwise pass through).
fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    field_str(rec, key).filter(|s| !s.eq_ignore_ascii_case("null"))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
