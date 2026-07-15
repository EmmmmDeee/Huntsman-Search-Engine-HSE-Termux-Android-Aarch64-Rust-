//! State electoral roll lookups (NSW, VIC, QLD).
//!
//! Queries the state electoral commission pages to confirm enrolment and
//! extract the electoral division (which maps to a suburb/postcode range).
//! Electoral roll enrolment in Australia is compulsory, so this is a
//! high-confidence residential-address signal orthogonal to business
//! registers, unclaimed-money records, and people-finder directories.
//!
//! Sources (all free, keyless, public HTML):
//!   * NSW Electoral Commission — `https://check.elections.nsw.gov.au/`
//!   * VEC (Victoria) — `https://check.vec.vic.gov.au/`
//!   * ECQ (Queensland) — `https://enrol.ecq.qld.gov.au/check`
//!
//! No national/AEC leg: the AEC retired the `NameSearch.aspx` name-based
//! lookup this module used to query — live-confirmed (2026-07-13) via two
//! real `GET electorate.aec.gov.au/NameSearch.aspx?surname=…&firstname=…`
//! calls, a nonsense name and a real enrolled public figure, both returning
//! the *identical* generic `"Temporarily Unavailable / System Problem"`
//! error page rather than a query-specific result. The AEC's current
//! "Check your enrolment" tool (`check.aec.gov.au`) confirmed this isn't
//! transient: it now runs an address-based multi-step lookup (postcode →
//! suburb → street, via `?handler=…` RPC calls) with no name-search
//! capability at all — a different input shape (`Address`, not `FullName`)
//! this module doesn't take, so repointing to it is a distinct future
//! capability, not a same-shape endpoint repair. Removed the dead dispatch
//! (it never returned a result and was silently swallowed) rather than
//! leave every `FullName` scan pay its request/timeout cost for nothing.
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
        // Three sequential EC lookups (NSW → VIC → ECQ), each ~3–5 s.
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let encoded = crate::util::http::urlencode(full_name);
        let mut all_entities: Vec<Entity> = Vec::new();

        // No AEC national leg: `electorate.aec.gov.au/NameSearch.aspx` no
        // longer performs a name search (see the module doc comment) — every
        // call returned the identical generic error page, live-confirmed
        // against both a nonsense name and a real enrolled public figure.

        // ── NSW Electoral Commission ─────────────────────────────────────
        if all_entities.is_empty() {
            let nsw_url = format!("https://check.elections.nsw.gov.au/search?name={encoded}");
            if let Ok(resp) = ctx
                .http
                .get(&nsw_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
                && let Some(body) = read_body_capped(resp, 1_000_000).await
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

        // ── Victorian Electoral Commission ────────────────────────────────
        if all_entities.is_empty() {
            let vec_url = format!("https://check.vec.vic.gov.au/search?name={encoded}");
            if let Ok(resp) = ctx
                .http
                .get(&vec_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
                && let Some(body) = read_body_capped(resp, 1_000_000).await
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

        // ── ECQ Queensland ───────────────────────────────────────────────
        if all_entities.is_empty() {
            let ecq_url = format!("https://enrol.ecq.qld.gov.au/check?name={encoded}");
            if let Ok(resp) = ctx
                .http
                .get(&ecq_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", crate::util::http::UA_BROWSER)
                .send_tagged(SRC)
                .await
                && let Some(body) = read_body_capped(resp, 1_000_000).await
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

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}
