//! ASIC **Registered Auditor** register — keyless, free. An auditor name (company
//! or person) / ACN seed → whether the entity is a registered auditor, with its
//! registration number, ACN, status and recorded address.
//!
//! Source: the Australian Securities and Investments Commission publishes the
//! "ASIC - Registered Auditor Dataset" on `data.gov.au` (CKAN). Free, keyless,
//! public. The dataset rotates its datastore resources, so we resolve the current
//! datastore-active resource at runtime (mirroring
//! [`crate::modules::agor`]):
//!   1. `GET {ACTION_BASE}/package_show?id=asic-registered-auditor` to find the
//!      current datastore-active resource id (preferring one whose name contains
//!      "Current"), and
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`.
//!
//! Why it matters for OSINT: registration as an auditor is a regulated
//! business/professional relationship (most registrants are "... PTY LTD" audit
//! firms). The row links a named organisation to its registered `ACN` (a pivot
//! into the whole corporate stack — `au_business_id`, `abn_lookup`,
//! `asic_director`, `opencorporates`) and a recorded address. Matching is
//! conservative and whole-word: a row is a high-confidence finding only when its
//! auditor name contains every seed token as a whole word, or when its recorded
//! ACN equals the digits of an `AbnAcn` seed exactly. Loose full-text hits are
//! surfaced as sub-floor name-candidates carrying the full record in evidence (no
//! omission).

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

pub(super) const SRC: &str = "asic_registered_auditors";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals, same as `agor` / `asic_afs_licensees`).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the ASIC Registered Auditor register. Stable (it's the
/// dataset, not the per-rotation resource): the current datastore-active resource
/// id is resolved from it at runtime so a resource rotation never staledates the
/// module.
pub(super) const DATASET_ID: &str = "asic-registered-auditor";

/// Cap on rows turned into entities for one seed.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. A genuine whole-word all-token (or exact ACN) match is a
// strong public-register finding; it sits above the 0.50 expansion floor so it
// pivots. Candidates (loose full-text hits) stay below the floor: surfaced but
// inert.
pub(super) const ORG_EXACT: f64 = 0.62;
pub(super) const ORG_CANDIDATE: f64 = 0.45;
pub(super) const ACN_CONF: f64 = 0.60;
pub(super) const ADDR_CONF: f64 = 0.58;

pub struct AsicRegisteredAuditors;

#[async_trait]
impl Module for AsicRegisteredAuditors {
    fn name(&self) -> &'static str {
        "asic_registered_auditors"
    }

    fn description(&self) -> &'static str {
        "ASIC Registered Auditor register (free, keyless) — auditor name / ACN → registration number, ACN, status, address"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band, alongside the other ASIC registries
        // (asic_credit_licensees 108, asic_afs_licensees 109).
        107
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // An organisation name (the usual "... PTY LTD" audit firm), a full name
        // (individual registered auditors), or an ACN seed (exact register pivot).
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::FullName | TargetKind::AbnAcn
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A business/professional registry establishes a Business Relationship
        // between an auditor and its registration (T1591.002). It surfaces no
        // coordinates, so T1591.001 (physical location) is not claimed — the same
        // posture as agor minus the geo.
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
        // Two sequential network calls (package_show resolve + datastore_search);
        // well above the 3s default (mirrors agor / asic_afs_licensees).
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

        // Step 1: resolve the current datastore-active resource id.
        // Reuse the shared TTL cache so a warm `serve`/`live` process skips the
        // `package_show` round-trip — one request per slug per window instead of
        // one per scan.
        let now = crate::core::entity::unix_now();
        let resource_id = if let Some(id) = crate::util::ckan::cached_resource(DATASET_ID, now) {
            id
        } else {
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
            let Some(id) = pkg.result.and_then(|p| entity::pick_resource(&p.resources)) else {
                return Ok(ModuleResult::new());
            };
            crate::util::ckan::cache_resource(
                DATASET_ID,
                &id,
                now,
                crate::util::ckan::RESOURCE_TTL_SECS,
            );
            id
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
