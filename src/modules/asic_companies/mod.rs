//! ASIC **Company** register — the full Australian registered-company dataset
//! (company name → ACN), keyless and free. A company name / ACN seed → the
//! registered company with its ACN, type, class, status and registration dates.
//!
//! Source: the Australian Securities and Investments Commission publishes the
//! "ASIC - Company Dataset" on `data.gov.au` (CKAN). Free, keyless, public. The
//! dataset rotates its datastore resources, so we resolve the current
//! datastore-active resource at runtime (mirroring
//! [`crate::modules::asic_registered_auditors`]):
//!   1. `GET {ACTION_BASE}/package_show?id=asic-companies` to find the current
//!      datastore-active resource id, **preferring one whose name contains
//!      "Current"** — this is critical: the package also exposes a
//!      datastore-active "Company Dataset - Help File" (a 27-row PDF help table)
//!      that must never be selected over the real 4.4M-row "Company Dataset -
//!      Current" CSV; the pick-resource helper's "Current" preference guarantees
//!      that, and
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`.
//!
//! Why it matters for OSINT: this is the flagship corporate-identity registry —
//! it links a named organisation to its registered `ACN`, the master pivot into
//! the whole corporate stack (`abn_lookup`, `asic_director`, `opencorporates`,
//! `au_business_id`). Matching is conservative and whole-word: a row is a
//! high-confidence finding only when its company name contains every seed token
//! as a whole word, or when its recorded ACN equals the digits of an `AbnAcn`
//! seed exactly. The 4.4M-row full-text search returns many loose hits; those are
//! surfaced as sub-floor name-candidates carrying the full record in evidence (no
//! omission), so a common token never promotes unrelated companies.

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

pub(super) const SRC: &str = "asic_companies";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals, same as `asic_registered_auditors`).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the ASIC Company register. Stable (it's the dataset, not
/// the per-rotation resource): the current datastore-active resource id is
/// resolved from it at runtime so a resource rotation never staledates the
/// module.
pub(super) const DATASET_ID: &str = "asic-companies";

/// Cap on rows turned into entities for one seed.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. A genuine whole-word all-token (or exact ACN) match is a
// strong public-register finding; it sits above the 0.50 expansion floor so it
// pivots. Candidates (loose full-text hits) stay below the floor: surfaced but
// inert.
pub(super) const ORG_EXACT: f64 = 0.62;
pub(super) const ORG_CANDIDATE: f64 = 0.45;
pub(super) const ACN_CONF: f64 = 0.60;

pub struct AsicCompanies;

#[async_trait]
impl Module for AsicCompanies {
    fn name(&self) -> &'static str {
        "asic_companies"
    }

    fn description(&self) -> &'static str {
        "ASIC Company register (free, keyless) — the full Australian registered-company dataset: company name / ACN → ACN, type, class, status, registration dates"
    }

    fn priority(&self) -> u8 {
        // Core corporate registry — the master name→ACN register, just above the
        // niche ASIC sub-registers (asic_credit_licensees 108, asic_afs_licensees
        // 109, asic_registered_auditors 107). Shares the government/public-records
        // band; priority is not required to be unique.
        111
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // A company name (the usual "... PTY LTD"), a full name (the dataset also
        // carries individually-named registered companies), or an ACN seed (the
        // exact register pivot).
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::FullName | TargetKind::AbnAcn
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A business-identity registry establishes a Business Relationship between
        // a company and its registration (T1591.002). It surfaces no coordinates
        // or address, so no geo technique is claimed — the same posture as
        // asic_registered_auditors.
        &["T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // No address/coordinates in this dataset — only the organisation and its
        // ACN pivot.
        const KINDS: &[EntityKind] = &[EntityKind::Organisation, EntityKind::AbnAcn];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential network calls (package_show resolve + datastore_search)
        // against a very large datastore; well above the 3s default (mirrors
        // asic_registered_auditors).
        12_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // The register updates periodically (not intraday); a 24h TTL avoids
        // re-querying a slow-moving public register.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        let abn_query = matches!(target.kind, TargetKind::AbnAcn);
        // A national register needs a discriminating query: a multi-token name, or
        // an ACN of plausible length. A lone short token sweeps the register.
        let tokens: Vec<&str> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .collect();
        let digit_len = query.chars().filter(char::is_ascii_digit).count();
        if !abn_query && tokens.len() < 2 {
            return Ok(ModuleResult::new());
        }
        if abn_query && digit_len < 9 {
            return Ok(ModuleResult::new());
        }
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        // Step 1: resolve the current datastore-active resource id (preferring the
        // "Current" resource, never the "Help File").
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
            abn_query,
            &ctx.scan_id,
        ));
        Ok(out)
    }
}
