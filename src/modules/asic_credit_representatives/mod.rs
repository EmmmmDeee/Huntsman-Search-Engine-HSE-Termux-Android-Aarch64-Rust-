//! ASIC **Credit Representative** register — keyless, free. A person name,
//! organisation name or ABN/ACN seed → whether ASIC records that party as a
//! credit representative acting under a credit licensee, with the representative
//! number, the credit licence number it acts under (a pivot to the licensee),
//! status (derived from start/end dates), ABN/ACN, authorisations, EDRS and
//! recorded locality.
//!
//! Source: the Australian Securities and Investments Commission publishes the
//! "ASIC – Credit Representative Dataset" on `data.gov.au` (CKAN). Free, keyless,
//! public (≈47,739 records). The dataset rotates its datastore resources, so we
//! resolve the current datastore-active resource at runtime (mirroring
//! [`crate::modules::asic_afs_representatives`]):
//!   1. `GET {ACTION_BASE}/package_show?id=asic-credit-representative` to find
//!      the current datastore-active resource id (preferring one whose name
//!      contains "Current"), and
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`.
//!
//! Why it matters for OSINT: a credit-representative record confirms a named
//! party (a **mix** of organisations e.g. `"THINK TANK GROUP PTY LIMITED"` and
//! persons e.g. `"WEAVER, BRUCE"` in `"SURNAME, FIRSTNAME"` form) is appointed to
//! engage in credit activities under a specific credit licensee — a high-signal
//! professional record plus a direct pivot to the licence number
//! (`CRED_LIC_NUM`, feeding [`crate::modules::asic_credit_licensees`]).
//!
//! Person register names are normalised order-independently so the register's
//! `"SURNAME, FIRSTNAME"` matches a `"Firstname Surname"` seed; a row is a
//! high-confidence finding only when its normalised name contains **every** seed
//! token as a whole word (or its recorded ABN/ACN equals an `AbnAcn` seed
//! exactly). Loose full-text hits are surfaced as sub-floor name-candidates
//! carrying the full record in evidence (no omission).

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

pub(super) const SRC: &str = "asic_credit_representatives";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals, same as `asic_afs_representatives` / `austender`).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the ASIC Credit Representative register. Stable (it's the
/// dataset, not the per-rotation resource): the current datastore-active resource
/// id is resolved from it at runtime so a resource rotation never staledates the
/// module.
pub(super) const DATASET_ID: &str = "asic-credit-representative";

/// Cap on rows turned into entities for one seed.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. A genuine whole-word all-token (or exact ABN/ACN) match is a
// strong professional-record finding; it sits above the 0.50 expansion floor so
// it pivots. Candidates (loose full-text hits) stay below the floor: surfaced but
// inert.
pub(super) const NAME_EXACT: f64 = 0.60;
pub(super) const NAME_CANDIDATE: f64 = 0.45;
pub(super) const ABN_CONF: f64 = 0.58;
pub(super) const ADDR_CONF: f64 = 0.58;

pub struct AsicCreditRepresentatives;

#[async_trait]
impl Module for AsicCreditRepresentatives {
    fn name(&self) -> &'static str {
        "asic_credit_representatives"
    }

    fn description(&self) -> &'static str {
        "ASIC Credit Representative register (free, keyless) — person/organisation name or ABN/ACN → representative number, the credit licence it acts under, status, ABN/ACN, authorisations, locality"
    }

    fn priority(&self) -> u8 {
        // Free, non-colliding, AU public-records band alongside the other ASIC
        // registries (asic_afs_representatives 106, asic_afs_licensees 109).
        105
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // A person screen, an organisation name (credit reps are a mix of both),
        // or an ABN/ACN seed (exact register pivot).
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
        // Names) and the licensee / regulator relationship it establishes
        // (T1591.002 Business Relationships) — same posture as
        // asic_afs_representatives.
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
        // The representative register updates periodically (not intraday); a 24h
        // TTL avoids re-querying a slow-moving public register.
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        let abn_query = matches!(target.kind, TargetKind::AbnAcn);
        // A ~48k-row national register needs a discriminating query: a multi-token
        // name, or an ABN/ACN of plausible length. A lone short token sweeps it.
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
