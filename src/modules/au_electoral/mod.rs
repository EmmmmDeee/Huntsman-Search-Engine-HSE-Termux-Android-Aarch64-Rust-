//! Australian Electoral Commission (AEC) and state electoral roll lookups.
//!
//! Queries the AEC's public "Check your enrolment" tool and the equivalent
//! state commission pages (NSW, VIC, QLD) to confirm enrolment and extract
//! the electoral division (which maps to a suburb/postcode range). Electoral
//! roll enrolment in Australia is compulsory, so this is a high-confidence
//! residential-address signal orthogonal to business registers, unclaimed-money
//! records, and people-finder directories.
//!
//! Sources (all free, keyless, public HTML):
//!   * AEC — `https://electorate.aec.gov.au/NameSearch.aspx`
//!   * NSW Electoral Commission — `https://check.elections.nsw.gov.au/`
//!   * VEC (Victoria) — `https://check.vec.vic.gov.au/`
//!   * ECQ (Queensland) — `https://enrol.ecq.qld.gov.au/check`
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (electoral division → suburb)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Confidence model:
//!   * Confirmed enrolment with division + suburb: 0.72 (electoral roll is
//!     compulsory and address-verified; higher than directory sources)
//!   * Division only (no suburb resolved): 0.58
//!   * Address from division centroid lookup: 0.65 (derived, not raw)
//!
//! The module is AU-restricted: it only accepts `FullName` targets and only
//! emits when the division geography maps inside Australia.

mod division_map;
mod entity;
mod parse;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, read_body_capped};

pub(crate) use entity::build_electoral_entities;
pub(crate) use parse::extract_division;

pub(super) const SRC: &str = "au_electoral";

pub struct AuElectoral;

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuElectoral {
    fn name(&self) -> &'static str {
        "au_electoral"
    }

    fn description(&self) -> &'static str {
        "AEC and state electoral commission enrolment lookups — confirms residential \
         electoral division (suburb/state) for an AU full-name seed"
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Address, EntityKind::Coordinates]
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003"]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn priority(&self) -> u8 {
        85
    }

    fn max_timeout_ms(&self) -> u64 {
        // Four sequential EC lookups (AEC → NSW → VIC → ECQ), each ~3–5 s.
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let encoded = crate::util::http::urlencode(full_name);
        let mut all_entities: Vec<Entity> = Vec::new();

        // Records a hard failure (transport error or non-success status — most
        // importantly a 403/429 block or throttle) from the FIRST commission that
        // hits one. Electoral-roll endpoints are government registers that
        // frequently rate-limit; previously the body was read regardless of
        // status, so a block page simply yielded no division and reported a clean
        // empty result. If every commission is blocked and zero entities are
        // produced, this is surfaced as a module error so the operator can tell
        // "not enrolled / no match" from "the register blocked us". Best-effort
        // fallthrough across the commissions is preserved.
        let mut block_error: Option<crate::core::error::Error> = None;

        // ── AEC national lookup ──────────────────────────────────────────
        let (first, last) = split_name(full_name);
        if !last.is_empty() {
            let aec_url = format!(
                "https://electorate.aec.gov.au/NameSearch.aspx?surname={}&firstname={}",
                crate::util::http::urlencode(last),
                crate::util::http::urlencode(first),
            );
            match ctx
                .http
                .get(&aec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Some(body) = read_body_capped(resp, 1_000_000).await
                        && let Some((div, suburb)) = extract_division(&body)
                    {
                        all_entities.extend(build_electoral_entities(
                            &div,
                            suburb.as_deref(),
                            full_name,
                            &ctx.scan_id,
                        ));
                    }
                }
                Ok(resp) => {
                    block_error = Some(crate::util::http::http_status_error(SRC, resp).await);
                }
                Err(e) => block_error = Some(e),
            }
        }

        // ── NSW Electoral Commission ─────────────────────────────────────
        if all_entities.is_empty() {
            let nsw_url = format!("https://check.elections.nsw.gov.au/search?name={encoded}");
            match ctx
                .http
                .get(&nsw_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Some(body) = read_body_capped(resp, 1_000_000).await
                        && let Some((div, suburb)) = extract_division(&body)
                    {
                        all_entities.extend(build_electoral_entities(
                            &div,
                            suburb.as_deref(),
                            full_name,
                            &ctx.scan_id,
                        ));
                    }
                }
                Ok(resp) => {
                    if block_error.is_none() {
                        block_error = Some(crate::util::http::http_status_error(SRC, resp).await);
                    }
                }
                Err(e) => {
                    if block_error.is_none() {
                        block_error = Some(e);
                    }
                }
            }
        }

        // ── Victorian Electoral Commission ────────────────────────────────
        if all_entities.is_empty() {
            let vec_url = format!("https://check.vec.vic.gov.au/search?name={encoded}");
            match ctx
                .http
                .get(&vec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Some(body) = read_body_capped(resp, 1_000_000).await
                        && let Some((div, suburb)) = extract_division(&body)
                    {
                        all_entities.extend(build_electoral_entities(
                            &div,
                            suburb.as_deref(),
                            full_name,
                            &ctx.scan_id,
                        ));
                    }
                }
                Ok(resp) => {
                    if block_error.is_none() {
                        block_error = Some(crate::util::http::http_status_error(SRC, resp).await);
                    }
                }
                Err(e) => {
                    if block_error.is_none() {
                        block_error = Some(e);
                    }
                }
            }
        }

        // ── ECQ Queensland ───────────────────────────────────────────────
        if all_entities.is_empty() {
            let ecq_url = format!("https://enrol.ecq.qld.gov.au/check?name={encoded}");
            match ctx
                .http
                .get(&ecq_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Some(body) = read_body_capped(resp, 1_000_000).await
                        && let Some((div, suburb)) = extract_division(&body)
                    {
                        all_entities.extend(build_electoral_entities(
                            &div,
                            suburb.as_deref(),
                            full_name,
                            &ctx.scan_id,
                        ));
                    }
                }
                Ok(resp) => {
                    if block_error.is_none() {
                        block_error = Some(crate::util::http::http_status_error(SRC, resp).await);
                    }
                }
                Err(e) => {
                    if block_error.is_none() {
                        block_error = Some(e);
                    }
                }
            }
        }

        // Every commission was blocked or errored and nothing was extracted —
        // report a module error rather than a clean empty result so the engine
        // logs a distinguishable failure.
        if all_entities.is_empty()
            && let Some(err) = block_error
        {
            return Err(err);
        }

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}

/// Split `"First Last"` into `("First", "Last")`. Pure.
fn split_name(full: &str) -> (&str, &str) {
    let trimmed = full.trim();
    if let Some(pos) = trimmed.find(' ') {
        (&trimmed[..pos], trimmed[pos + 1..].trim_start())
    } else {
        (trimmed, "")
    }
}
