//! ASIC Banned & Disqualified **Persons** register — keyless, free. The
//! person-side complement to [`crate::modules::asic_banned_orgs`] (banned
//! organisations): a person name → whether ASIC has banned or disqualified that
//! individual from providing financial services or managing corporations, with
//! the ban type, period, and the individual's recorded locality.
//!
//! Source: the Australian Securities and Investments Commission publishes the
//! "Banned and Disqualified Persons" register on `data.gov.au` (CKAN). Free,
//! keyless, public. The dataset rotates its datastore resources, so we resolve
//! the current datastore-active resource at runtime (mirroring [`crate::modules::agor`]):
//!   1. `GET {ACTION_BASE}/package_show?id=asic-banned-disqualified-per` to find
//!      the current datastore-active resource id (preferring one whose name
//!      contains "Current"), and
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`.
//!
//! Why it matters for OSINT: a `FullName` seed screened against this register is
//! a high-signal adverse finding — an ASIC regulatory ban / disqualification is a
//! serious adverse regulatory record on a person. Matching is conservative and
//! whole-word: the register stores the name as `"SURNAME, FIRSTNAME"`, so the
//! name is normalised order-independently and a row is a high-confidence adverse
//! finding only when its normalised name contains **every** seed token as a whole
//! word. Other loose full-text hits are surfaced as sub-floor name-candidates
//! carrying the full record in evidence (no omission) — a false ASIC-ban
//! attribution is harmful, so only a genuine all-token whole-word match is
//! emitted at full confidence.
//!
//! Adverse-finding semantics mirror [`crate::modules::dfat_sanctions`]: a matched
//! person is a first-class `Person` tagged `asic-banned` / `disqualified` /
//! `adverse-record`, with the full listed record (ban type, document number,
//! start/end dates, comments, register name) in evidence, plus an `Address`
//! locality pivot assembled from the recorded address parts.

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

pub(super) const SRC: &str = "asic_banned_persons";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals, same as `agor` / `austender`).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the ASIC Banned & Disqualified Persons register. Stable
/// (it's the dataset, not the per-rotation resource): the current
/// datastore-active resource id is resolved from it at runtime so a resource
/// rotation never staledates the module.
pub(super) const DATASET_ID: &str = "asic-banned-disqualified-per";

/// Cap on rows turned into entities for one seed — a generic name query can match
/// many people; we keep the highest-ranked handful so a single seed doesn't flood
/// the graph.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. A genuine whole-word all-token match is a strong adverse
// finding but a seed name might collide with a namesake, so the exact hit sits at
// the Probable tier (above the 0.50 expansion floor so it pivots, below Verified
// so it isn't asserted as the subject without corroboration). Candidates (loose
// full-text hits) stay below the floor: surfaced but inert.
pub(super) const PERSON_EXACT: f64 = 0.60;
pub(super) const PERSON_CANDIDATE: f64 = 0.45;
pub(super) const ADDR_CONF: f64 = 0.58;

pub struct AsicBannedPersons;

#[async_trait]
impl Module for AsicBannedPersons {
    fn name(&self) -> &'static str {
        "asic_banned_persons"
    }

    fn description(&self) -> &'static str {
        "ASIC Banned & Disqualified Persons register (free, keyless) — person name → ban/disqualification type, period, locality"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band, alongside the other ASIC registries
        // (asic_business_names 111, asic_banned_orgs / asic_persons 112).
        113
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Primarily a person screen; an Organisation seed is also accepted because
        // ASIC occasionally records a name in a person-like form and a
        // distinctive org name can still surface a ban (mirrors dfat_sanctions).
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // An adverse regulatory record confirming a named individual's identity
        // (T1589.003 Employee Names) and the regulator relationship the ban
        // establishes (T1591.002 Business Relationships) — the same adverse /
        // sanctions-screening posture as dfat_sanctions.
        &["T1589.003", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential network calls (package_show resolve + datastore_search);
        // well above the 3s default so a slow-but-connected fetch isn't killed
        // mid-request (the non-passive-budget CI guard). Mirrors agor (12s).
        12_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // The register updates periodically (not intraday); a 24h TTL avoids
        // re-querying a slow-moving adverse register (mirrors dfat_sanctions/agor
        // TTL posture).
        86_400
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // A national adverse register needs a discriminating multi-token name; a
        // lone given/family name is far too broad and a 1-2 char query sweeps the
        // whole register.
        let tokens: Vec<&str> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .collect();
        if tokens.len() < 2 || query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        // Step 1: resolve the current datastore-active resource id (the dataset
        // rotates its resources; prefer the "...- Current" one).
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
                // No datastore-active resource to search — nothing to do.
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
            &ctx.scan_id,
        ));
        Ok(out)
    }
}
