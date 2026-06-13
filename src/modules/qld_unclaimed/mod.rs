//! Queensland Public Trustee unclaimed-money lookup (keyless, free).
//!
//! Endpoint: `GET https://www.data.qld.gov.au/api/3/action/datastore_search`
//!           `?resource_id={RESOURCE_ID}&q={name}&limit=20`
//! Auth:     none — the Queensland Government Open Data Portal (CKAN) exposes
//!           the Public Trustee's unclaimed-monies register as a public,
//!           datastore-active resource refreshed weekly.

mod helpers;
#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::Response as CkanResp;
use crate::util::http::fetch_json;

use helpers::{
    derive_query, exact_postcodes, merge_records, records_to_entities, suburbs_to_entities,
};

pub(super) const SRC: &str = "qld_unclaimed";
pub(super) const ACTION_BASE: &str = "https://www.data.qld.gov.au/api/3/action";
pub(super) const RESOURCE_ID: &str = "872065ae-ddfd-4b5f-ad15-e1935dadd883";
pub(super) const MAX_RECORDS: usize = 20;
pub(super) const POSTCODE_CAP: usize = 6;
pub(super) const SUBURB_CAP: usize = 8;

pub struct QldUnclaimed;

#[async_trait]
impl Module for QldUnclaimed {
    fn name(&self) -> &'static str {
        "qld_unclaimed"
    }

    fn description(&self) -> &'static str {
        "Queensland Public Trustee unclaimed-money register lookup (free, keyless)"
    }

    fn priority(&self) -> u8 {
        114
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003", "T1591.002"]
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full = target.value.trim();
        if full.len() < 3 {
            return Ok(ModuleResult::new());
        }
        let surname = derive_query(target);

        let broad: CkanResp = fetch_json(&ctx.http, SRC, &helpers::query_url(surname)).await?;
        if broad.success == Some(false) {
            return Err(crate::core::error::Error::module(
                SRC,
                "CKAN datastore_search returned success=false (bad resource id or portal error)",
            ));
        }
        let Some(broad_res) = broad.result else {
            return Ok(ModuleResult::new());
        };
        let total = broad_res.total.unwrap_or(broad_res.records.len() as u64);
        let mut records = broad_res.records;

        if surname != full
            && let Ok(exact) =
                fetch_json::<CkanResp>(&ctx.http, SRC, &helpers::query_url(full)).await
            && let Some(exact_res) = exact.result
        {
            records = merge_records(exact_res.records, records);
        }

        let broadened = surname != full;

        let mut pc_localities = Vec::new();
        for pc in exact_postcodes(&records, full, broadened) {
            let locs = crate::util::postcode_au::localities(&ctx.http, &pc).await;
            if !locs.is_empty() {
                pc_localities.push((pc, locs));
            }
        }

        let mut out = ModuleResult::new();
        out.extend(records_to_entities(
            &records,
            total,
            full,
            broadened,
            &ctx.scan_id,
        ));
        out.extend(suburbs_to_entities(&pc_localities, &ctx.scan_id));
        Ok(out)
    }
}
