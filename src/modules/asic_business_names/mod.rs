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

use crate::core::confidence;
use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{datastore_search_url, field};

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
        "ASIC Business Names recon (keyless) — pivots a business/trading name to ABN, status, state, and registration date"
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

        let (records, server_total) = ckan_query(ctx, name).await?;
        let mut seen = std::collections::HashSet::new();
        let mut matched_count = 0usize;
        for rec in records
            .iter()
            .filter(|r| record_name_matches(r, name))
            .take(MAX_HITS)
        {
            matched_count += 1;
            emit_business_name(rec, &ctx.scan_id, &mut seen, &mut result);
        }

        if matched_count == 0 {
            return Ok(result);
        }

        let matches_capped = is_truncated(server_total, records.len());

        let mut seed = Entity::new(
            EntityKind::Organisation,
            name,
            confidence::MEDIUM_HIGH,
            &ctx.scan_id,
        );
        seed.tag("au");
        seed.tag("asic");
        seed.tag("search-result");
        let mut ev = Evidence::new(SRC, format!("ASIC Business Names search for `{name}`"))
            .with_attr("matched_count", matched_count.to_string())
            .with_attr("total_matches", server_total.to_string());
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
/// helper (T2.118). Every real failure surfaces through
/// [`crate::util::ckan::validated_result`] instead of collapsing into an empty
/// `Vec` indistinguishable from "no registration by this name": `fetch_json`
/// propagates transport/status/parse failures via `?`, and a
/// `success == Some(false)` envelope (returned by CKAN with HTTP 200 on a bad
/// resource id / portal error) becomes an explicit `Error::module`. A genuine
/// empty result set is still the honest clean miss.
///
/// Returns `(records, server_total)` — `server_total` is CKAN's own reported
/// match count for the free-text query, BEFORE this module's stricter
/// whole-word `record_name_matches` filter narrows it further. `records`
/// itself is already capped at [`MAX_HITS`] by the request's own `limit=`, so
/// comparing a further-filtered subset of `records` against `MAX_HITS` (the
/// previous approach) could never detect real truncation; `server_total` is
/// the only signal CKAN actually held more rows than this page fetched.
async fn ckan_query(ctx: &ModuleContext, name: &str) -> Result<(Vec<Map<String, Value>>, u64)> {
    let url = datastore_search_url(CKAN_BASE, RES, name, MAX_HITS);
    Ok(crate::util::ckan::validated_result(&ctx.http, SRC, &url)
        .await?
        .map(|r| {
            let total = r.total.unwrap_or(r.records.len() as u64);
            (r.records, total)
        })
        .unwrap_or_default())
}

/// True when CKAN itself held more rows for this free-text query than this
/// page fetched. **Pure.** `records_len` is already capped at [`MAX_HITS`] by
/// the request's own `limit=`, so this can only ever be answered against
/// CKAN's own reported `server_total`, never against a further-filtered slice
/// of the already-capped record set (which can never exceed `MAX_HITS` by
/// construction — comparing `records_len > MAX_HITS` directly, the previous
/// approach, was a tautological `false`, so `total_matches` silently
/// ceilinged at `MAX_HITS` with no truncation warning even when CKAN's true
/// total was higher).
#[must_use]
fn is_truncated(server_total: u64, records_len: usize) -> bool {
    server_total > records_len as u64
}

/// Lower-cased alphanumeric name tokens (≥2 chars).
fn name_tokens(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True if the record's `BN_NAME` shares every whole-word token with the
/// queried business name. Whole-word, not substring — a raw `.contains()`
/// check lets a short token land inside an unrelated word (e.g. `"reef"`
/// inside `"Reeftown"`), attributing a completely different real business's
/// ABN/registration to the queried name. Same precision gate
/// `acnc_charities`/`gleif_lei` use for their own full-text CKAN search
/// results.
fn record_name_matches(rec: &Map<String, Value>, query: &str) -> bool {
    let Some(name) = field(rec, "BN_NAME") else {
        return false;
    };
    crate::util::str_util::whole_word_token_match(&name, query)
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
    let mut org = Entity::new(
        EntityKind::Organisation,
        &bn_name,
        confidence::MEDIUM_SOLID,
        scan_id,
    );
    org.tag("au");
    org.tag("asic");
    org.tag("business-name");
    if let Some(s) = status.as_deref() {
        org.tag(format!("status:{}", s.to_ascii_lowercase()));
    }
    org.add_evidence(ev.clone());
    result.push(org);

    // The ABN of the entity holding the name — a keyless pivot into the ABR,
    // kept only when it is a genuinely checksum-valid ABN rather than merely
    // 11 digits.
    if let Some(abn) = field(rec, "BN_ABN").filter(|a| crate::util::abn::is_valid_abn(a))
        && seen_abn.insert(abn.clone())
    {
        let mut e = Entity::new(EntityKind::AbnAcn, &abn, confidence::NOTABLE, scan_id);
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
        let mut addr = Entity::new(EntityKind::Address, &addr_value, confidence::LOW, scan_id);
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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
