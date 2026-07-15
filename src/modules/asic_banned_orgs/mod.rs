//! ASIC Banned & Disqualified **Organisations** register — keyless. The
//! entity-side complement to [`crate::modules::asic_persons`] (banned people):
//! an organisation name → whether ASIC has banned or disqualified that company
//! from providing financial services or managing corporations, with the ban
//! type, period, and the company's **ACN**.
//!
//! A hit is a high-signal adverse finding for due diligence on any Australian
//! company. Queried by name through the data.gov.au CKAN `datastore_search`
//! API (full-text, keyless) and matched on all of the target's name tokens; the
//! ACN is emitted as an `AbnAcn` pivot into the rest of the corporate stack
//! (`abn_lookup`, `asic_director`). No mock: fetched live from ASIC's own open
//! dataset.

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

const SRC: &str = "asic_banned_orgs";
/// data.gov.au CKAN action base — `datastore_search` is appended by
/// [`datastore_search_url`].
const CKAN_BASE: &str = "https://data.gov.au/data/api/3/action";
/// ASIC – Banned and Disqualified Organisations dataset (data.gov.au resource).
const RES: &str = "ced03961-e6f7-4263-895a-0fd1d7996043";
/// Max matched records surfaced. Raised to the query `limit` so no genuine
/// banned-organisation record is omitted (directive: never omit an API-derived
/// AU government result).
const MAX_HITS: usize = 100;

pub struct AsicBannedOrgs;

#[async_trait]
impl Module for AsicBannedOrgs {
    fn name(&self) -> &'static str {
        "asic_banned_orgs"
    }

    fn description(&self) -> &'static str {
        "ASIC Banned & Disqualified Organisations register (keyless) — org name → ban status, ACN, period"
    }

    fn priority(&self) -> u8 {
        112
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Adverse status of a business entity — T1591.002 Business Relationships.
        &["T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::AbnAcn];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let name = target.value.trim();
        let tokens = name_tokens(name);
        // A national company register needs a discriminating multi-token name.
        if tokens.len() < 2 {
            return Ok(result);
        }

        let records = ckan_query(ctx, name).await?;
        for rec in records
            .iter()
            .filter(|r| record_name_matches(r, &tokens))
            .take(MAX_HITS)
        {
            emit_banned_org(rec, &ctx.scan_id, &mut result);
        }
        Ok(result)
    }
}

/// Query the Banned & Disqualified Organisations datastore by free-text name,
/// via the shared CKAN envelope (T2.118). Unlike the previous hand-rolled fetch
/// — which collapsed a transport error, a non-2xx status, a body-read failure,
/// AND a CKAN application error (`success: false`, returned with HTTP 200) all
/// into an empty `Vec` indistinguishable from a genuine "no banned org by this
/// name" — every real failure now surfaces: `fetch_json` propagates transport/
/// status/parse failures via `?`, and a `success == Some(false)` envelope
/// (bad resource id / datastore offline / rate-limit) becomes an explicit
/// `Error::module`. A genuine empty result set (no `result`, or an empty
/// `records`) is still the honest clean miss.
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

fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn record_name_matches(rec: &Map<String, Value>, tokens: &[String]) -> bool {
    let Some(name) = field(rec, "BD_ORG_NAME") else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    tokens.iter().all(|t| lower.contains(t.as_str()))
}

/// Emit the adverse-flagged organisation and its ACN.
fn emit_banned_org(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(org_name) = field(rec, "BD_ORG_NAME") else {
        return;
    };
    // ASIC stores some names with a non-breaking space; normalise for display.
    let org_name = org_name.replace('\u{a0}', " ");

    let mut ev = Evidence::new(
        SRC,
        format!("ASIC banned/disqualified organisation: {org_name}"),
    )
    .with_attr("register", "ASIC Banned & Disqualified Organisations")
    .with_attr("organisation", &org_name);
    for (key, attr) in [
        ("BD_ORG_TYPE", "ban_type"),
        ("BD_ORG_START_DT", "ban_start"),
        ("BD_ORG_END_DT", "ban_end"),
        ("BD_ORG_ACN", "acn"),
        ("BD_ORG_COMMENT", "comments"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut org = Entity::new(EntityKind::Organisation, &org_name, 0.60, scan_id);
    org.tag("au");
    org.tag("asic");
    org.tag("asic-banned");
    org.tag("regulatory-action");
    org.add_evidence(ev.clone());
    result.push(org);

    // The ACN (9 digits) — a pivot into the company register.
    if let Some(acn) =
        field(rec, "BD_ORG_ACN").filter(|a| a.chars().filter(char::is_ascii_digit).count() == 9)
    {
        let mut e = Entity::new(EntityKind::AbnAcn, &acn, 0.62, scan_id);
        e.tag("au");
        e.tag("asic");
        e.tag("asic-banned");
        e.add_evidence(
            Evidence::new(SRC, format!("ACN of banned organisation {org_name}"))
                .with_attr("acn", &acn)
                .with_attr("organisation", &org_name),
        );
        result.push(e);
    }
}

/// A usable ASIC field value: the shared CKAN [`field_str`] stringification
/// (CONVENTIONS §4 — one stringifier, not a per-module copy) with this
/// register's dataset-specific sentinel filter on top. ASIC stores an absent
/// value as the literal `"null"` or `"Not available"` text, which `field_str`
/// (which only drops JSON null / empty) would otherwise surface as a real value.
fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    field_str(rec, key)
        .filter(|s| !s.eq_ignore_ascii_case("null") && !s.eq_ignore_ascii_case("Not available"))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
