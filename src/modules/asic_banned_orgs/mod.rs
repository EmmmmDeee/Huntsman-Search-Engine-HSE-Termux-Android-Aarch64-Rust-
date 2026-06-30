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

use serde::Deserialize;
use serde_json::{Map, Value};

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text, urlencode};

const SRC: &str = "asic_banned_orgs";
const CKAN: &str = "https://data.gov.au/data/api/3/action/datastore_search";
/// ASIC – Banned and Disqualified Organisations dataset (data.gov.au resource).
const RES: &str = "ced03961-e6f7-4263-895a-0fd1d7996043";
/// Max matched records surfaced. Raised to the query `limit` so no genuine
/// banned-organisation record is omitted (directive: never omit an API-derived
/// AU government result).
const MAX_HITS: usize = 100;

pub struct AsicBannedOrgs;

#[derive(Deserialize, Default)]
#[serde(default)]
struct CkanResp {
    result: CkanResult,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CkanResult {
    records: Vec<Map<String, Value>>,
}

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

        let records = ckan_query(ctx, name).await;
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

async fn ckan_query(ctx: &ModuleContext, name: &str) -> Vec<Map<String, Value>> {
    let url = format!("{CKAN}?resource_id={RES}&limit=100&q={}", urlencode(name));
    let Ok(resp) = ctx
        .http
        .get(&url)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = read_text(SRC, resp).await else {
        return Vec::new();
    };
    serde_json::from_str::<CkanResp>(&body)
        .map(|r| r.result.records)
        .unwrap_or_default()
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

fn field(rec: &Map<String, Value>, key: &str) -> Option<String> {
    match rec.get(key)? {
        Value::String(s) => {
            let t = s.trim();
            (!t.is_empty()
                && !t.eq_ignore_ascii_case("null")
                && !t.eq_ignore_ascii_case("Not available"))
            .then(|| t.to_string())
        }
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
