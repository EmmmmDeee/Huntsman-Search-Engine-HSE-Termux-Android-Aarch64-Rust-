//! ASIC **Liquidator** register — keyless, free. A person name → whether ASIC
//! registers that individual as a liquidator / insolvency practitioner, with the
//! liquidator number, registration status, recorded locality and the firm /
//! employer the practitioner is recorded against.
//!
//! Source: the Australian Securities and Investments Commission publishes the
//! "Liquidator" register on `data.gov.au` (CKAN). Free, keyless, public. The
//! dataset rotates its datastore resources, so we resolve the current
//! datastore-active resource at runtime (mirroring
//! [`crate::modules::asic_banned_persons`]):
//!   1. `GET {ACTION_BASE}/package_show?id=asic-liquidator` to find the current
//!      datastore-active resource id (preferring one whose name contains
//!      "Current"), and
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`.
//!
//! Why it matters for OSINT: a `FullName` seed found here confirms the person is
//! a registered insolvency practitioner — a high-signal professional record. The
//! register stores the name as `"SURNAME, FIRSTNAME"`, so the name is normalised
//! order-independently and a row is a high-confidence finding only when its
//! normalised name contains **every** seed token as a whole word. The recorded
//! firm (`LIQ_FIRM`) is fanned out as a related `Organisation` (the
//! practitioner's employer), and the recorded address as a locality pivot. Loose
//! full-text hits are surfaced as sub-floor name-candidates carrying the full
//! record in evidence (no omission).

mod entity;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{PackageResponse, Response as CkanResp};
use crate::util::http::fetch_json;

pub(super) const SRC: &str = "asic_liquidators";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals, same as `asic_banned_persons` / `austender`).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the ASIC Liquidator register. Stable (it's the dataset,
/// not the per-rotation resource): the current datastore-active resource id is
/// resolved from it at runtime so a resource rotation never staledates the
/// module.
pub(super) const DATASET_ID: &str = "asic-liquidator";

/// Cap on rows turned into entities for one seed.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. A genuine whole-word all-token match is a strong
// professional-record finding; it sits at the Probable tier (above the 0.50
// expansion floor so it pivots). Candidates (loose full-text hits) stay below
// the floor: surfaced but inert.
pub(super) const PERSON_EXACT: f64 = 0.60;
pub(super) const PERSON_CANDIDATE: f64 = 0.45;
pub(super) const FIRM_CONF: f64 = 0.55;
pub(super) const ADDR_CONF: f64 = 0.58;

pub struct AsicLiquidators;

#[async_trait]
impl Module for AsicLiquidators {
    fn name(&self) -> &'static str {
        "asic_liquidators"
    }

    fn description(&self) -> &'static str {
        "ASIC Liquidator register (free, keyless) — person name → registered liquidator/insolvency practitioner, status, firm, locality"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band, alongside the other ASIC registries
        // (asic_banned_persons 113). Distinct value to avoid an awkward collision.
        110
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // A person screen: the register is keyed on the practitioner's name.
        matches!(t.kind, TargetKind::FullName)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A professional record confirming a named individual (T1589.003 Employee
        // Names) and the firm / regulator relationship it establishes (T1591.002
        // Business Relationships) — the same posture as asic_banned_persons.
        &["T1589.003", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Address,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential network calls (package_show resolve + datastore_search);
        // well above the 3s default (mirrors asic_banned_persons / agor).
        12_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // The liquidator register updates periodically (not intraday); a 24h TTL
        // avoids re-querying a slow-moving public register.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // A national register needs a discriminating multi-token name; a lone
        // given/family name is far too broad.
        let tokens: Vec<&str> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .collect();
        if tokens.len() < 2 || query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        // Step 1: resolve the current datastore-active resource id.
        let pkg: PackageResponse = fetch_json(
            &ctx.http,
            SRC,
            &crate::util::ckan::package_show_url(ACTION_BASE, DATASET_ID),
        )
        .await?;
        if pkg.success == Some(false) {
            return Err(crate::core::error::Error::module(
                SRC,
                "CKAN package_show returned success=false (bad dataset id or portal error)",
            ));
        }
        let Some(resource_id) = pkg.result.and_then(|p| entity::pick_resource(&p.resources)) else {
            return Ok(ModuleResult::new());
        };

        // Step 2: full-text search the resolved resource.
        let resp: CkanResp = fetch_json(
            &ctx.http,
            SRC,
            &crate::util::ckan::datastore_search_url(ACTION_BASE, &resource_id, query, MAX_RECORDS),
        )
        .await?;
        if resp.success == Some(false) {
            return Err(crate::core::error::Error::module(
                SRC,
                "CKAN datastore_search returned success=false (bad resource id or portal error)",
            ));
        }
        let Some(res) = resp.result else {
            return Ok(ModuleResult::new());
        };
        let total = res.total.unwrap_or(res.records.len() as u64);

        let mut out = ModuleResult::new();
        out.extend(entity::records_to_entities(
            &res.records,
            total,
            query,
            &ctx.scan_id,
        ));
        Ok(out)
    }
}
