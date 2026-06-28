//! ASIC **Self-Managed Super Fund (SMSF) Auditor** register — keyless, free. A
//! person name / firm / ABN seed → whether ASIC records that individual as an
//! approved SMSF auditor, with the auditor number (`SMSF_NUM`), registration
//! status, the firm they audit under, recorded locality, and any registration
//! conditions imposed on them.
//!
//! Source: the Australian Securities and Investments Commission publishes the
//! "ASIC – Self-Managed Super Fund Auditor Dataset" on `data.gov.au` (CKAN).
//! Free, keyless, public (≈30k rows). The dataset rotates its datastore
//! resources, so we resolve the current datastore-active resource at runtime
//! (mirroring [`crate::modules::asic_afs_representatives`]):
//!   1. `GET {ACTION_BASE}/package_show?id=asic-smsf` to find the current
//!      datastore-active resource id (preferring one whose name contains
//!      "Current"), and
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`.
//!
//! Why it matters for OSINT: an SMSF-auditor record confirms a named individual
//! is an ASIC-approved auditor — a high-signal professional record — and surfaces
//! the firm they act under plus any regulatory conditions on their registration.
//!
//! Name format: unlike the AFS representative register, `SMSF_NAME` is a plain
//! `"First Last"` person name (e.g. `"Benjamin Jenkins"`), **not** comma-reversed.
//! A row is a high-confidence finding only when its name contains **every** seed
//! token as a whole word (so `"Ben"` does not match `"Benjamin"`), or when its
//! recorded `SMSF_PERSON_ABN` equals an `AbnAcn` seed exactly. The dataset stores
//! one row per registration condition, so the same auditor appears on multiple
//! rows; each matched row is emitted (same-UID entities merge, accumulating
//! conditions in evidence — nothing is dropped). Loose full-text hits are
//! surfaced as sub-floor name-candidates carrying the full record in evidence.

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

pub(super) const SRC: &str = "asic_smsf_auditors";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals, same as `asic_afs_representatives` / `austender`).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the ASIC SMSF Auditor register. Stable (it's the
/// dataset, not the per-rotation resource): the current datastore-active
/// resource id is resolved from it at runtime so a resource rotation never
/// staledates the module.
pub(super) const DATASET_ID: &str = "asic-smsf";

/// Cap on rows turned into entities for one seed.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. A genuine whole-word all-token (or exact ABN) match is a
// strong professional-record finding; it sits above the 0.50 expansion floor so
// it pivots. Candidates (loose full-text hits) stay below the floor: surfaced
// but inert.
pub(super) const PERSON_EXACT: f64 = 0.60;
pub(super) const PERSON_CANDIDATE: f64 = 0.45;
pub(super) const ABN_CONF: f64 = 0.58;
pub(super) const ORG_CONF: f64 = 0.56;
pub(super) const ADDR_CONF: f64 = 0.58;

pub struct AsicSmsfAuditors;

#[async_trait]
impl Module for AsicSmsfAuditors {
    fn name(&self) -> &'static str {
        "asic_smsf_auditors"
    }

    fn description(&self) -> &'static str {
        "ASIC Self-Managed Super Fund (SMSF) Auditor register (free, keyless) — person name / firm / ABN → auditor number, registration status, the auditing firm, locality and any registration conditions"
    }

    fn priority(&self) -> u8 {
        // Free, AU public-records band alongside the other ASIC registries; a
        // distinct value (104) to avoid colliding with sibling ASIC modules.
        104
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // A person screen (the auditor's name), a firm name, or an ABN seed
        // (exact register pivot against SMSF_PERSON_ABN).
        matches!(
            t.kind,
            TargetKind::FullName | TargetKind::Organisation | TargetKind::AbnAcn
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A professional record confirming a named individual (T1589.003 Employee
        // Names) and the firm / regulator relationship it establishes (T1591.002
        // Business Relationships) — same posture as asic_afs_representatives.
        &["T1589.003", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential network calls (package_show resolve + datastore_search);
        // well above the 3s default (mirrors asic_afs_representatives).
        12_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // The auditor register updates periodically (not intraday); a 24h TTL
        // avoids re-querying a slow-moving public register.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        let abn_query = matches!(target.kind, TargetKind::AbnAcn);
        // A ~30k-row national register still needs a discriminating query: a
        // multi-token name/firm, or an ABN of plausible length.
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
            abn_query,
            &ctx.scan_id,
        ));
        Ok(out)
    }
}
