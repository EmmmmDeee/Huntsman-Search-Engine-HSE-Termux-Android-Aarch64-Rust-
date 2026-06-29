//! AGOR — Australian Government Organisations Register (keyless, free).
//!
//! Endpoint: a two-step CKAN resolve + search on `data.gov.au` (note the extra
//!           `/data` path segment vs. other portals, same as `austender`):
//!   1. `GET {ACTION_BASE}/package_show?id=australian-government-organisations-register`
//!      to find the *current* datastore-active resource (AGOR rotates the
//!      resource id every quarter — the resources are named `AGOR YYYY-MM-DD` —
//!      so a single pinned id would go stale within a quarter).
//!   2. `GET {ACTION_BASE}/datastore_search?resource_id={resolved}&q={query}&limit=20`
//!
//! Auth: none — the Department of Finance publishes the register as a public,
//! datastore-active resource. Each row is a Commonwealth body: its name,
//! portfolio, classification, ABN, head-office address, website, parent
//! organisation and establishing instrument.
//!
//! Why it matters for OSINT: AGOR is the authoritative map of *who is who* in the
//! Commonwealth. An organisation / ABN seed that is a government body surfaces
//! here with its registered ABN (a pivot into the whole corporate stack —
//! `au_business_id`, `abn_lookup`, `asic_director`, `opencorporates`), its
//! head-office address (geocoded into Coordinates), its website (a pivot into web
//! intel), and its portfolio department / parent organisation as
//! `Business Relationship`s (ATT&CK T1591.002) — the body's place in the
//! machinery-of-government hierarchy.
//!
//! Matching is conservative, mirroring `austender`. CKAN's `q` is a *ranked*
//! full-text search (not a strict AND), so it returns loosely-related rows
//! alongside true hits. We classify each row: a Title that contains every seed
//! token as a whole word is an `exact-name-match` (high confidence, fanned out
//! into the ABN / address / website / portfolio pivots); the rest are surfaced as
//! low-confidence `name-candidate` Organisations carrying the full record in
//! evidence — nothing the API returned is dropped — but kept below the expansion
//! floor so a generic query can't pivot government-name noise. An `AbnAcn` seed
//! matches on the exact ABN digits of a row, which is unambiguous.

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

pub(super) const SRC: &str = "agor";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN dataset slug of the Australian Government Organisations Register. Stable
/// (it's the dataset, not the per-quarter resource): we resolve the current
/// datastore-active resource id from it at runtime so a quarterly resource
/// rotation never staledates the module.
pub(super) const DATASET_ID: &str = "australian-government-organisations-register";

/// Cap on rows turned into entities for one seed — a generic single-word query
/// can match many bodies; we keep the highest-ranked handful so a single seed
/// doesn't flood the graph.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. Exact hits (Title contains every seed token, or an exact ABN
// match) are authoritative registry matches and sit above the 0.50 expansion
// floor so they pivot; candidates (loose full-text hits) stay below it so they're
// surfaced but inert.
pub(super) const ORG_EXACT: f64 = 0.82;
pub(super) const ORG_CANDIDATE: f64 = 0.45;
pub(super) const ABN_CONF: f64 = 0.88;
pub(super) const PORTFOLIO_CONF: f64 = 0.60;
pub(super) const PARENT_CONF: f64 = 0.62;
pub(super) const ADDR_CONF: f64 = 0.58;
pub(super) const DOMAIN_CONF: f64 = 0.60;

pub struct Agor;

#[async_trait]
impl Module for Agor {
    fn name(&self) -> &'static str {
        "agor"
    }

    fn description(&self) -> &'static str {
        "Australian Government Organisations Register (free, keyless) — gov body/ABN → portfolio, parent, ABN, address, website"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): the authoritative
        // machinery-of-government register, dispatched with the other AU gov
        // corporate sources (austender 110, acnc_charities 112, gleif_lei 111).
        110
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Organisation / FullName: Title full-text search (a body is occasionally
        // referred to by a person-like name, e.g. an Office of a named role).
        // AbnAcn: an exact ABN match on the body's row — the unambiguous pivot.
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::FullName | TargetKind::AbnAcn
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A government-organisations register establishes a Business Relationship
        // between a body and its portfolio department / parent (T1591.002) and
        // geocodes the body's head-office address to coordinates, so it also
        // Determines Physical Locations (T1591.001) — which the Corporate default
        // omits. It surfaces no individual officer/role, so the default's
        // T1591.004 (Identify Roles) is dropped (cf. austender / acnc_charities).
        &["T1591.001", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Organisation,
            EntityKind::AbnAcn,
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Domain,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential network calls (package_show resolve + datastore_search);
        // well above the 3s default so a slow-but-connected fetch isn't killed
        // mid-request (the non-passive-budget CI guard). Mirrors austender (12s).
        12_000
    }

    fn cache_ttl_secs(&self) -> u64 {
        // The register is re-published quarterly, so a result is fresh for a long
        // time — a 7-day TTL avoids re-querying a register that barely changes.
        604_800
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // For a name/org query, a 1-2 char term would match noise across the
        // whole register; an ABN query is normalised to its digits and length-gated.
        let abn_query = matches!(target.kind, TargetKind::AbnAcn);
        let q = if abn_query {
            let digits = crate::util::str_util::ascii_digits(query);
            if digits.len() != 11 {
                // Only an 11-digit ABN identifies a body row; a bare 9-digit ACN
                // is not the column AGOR indexes on, so don't query.
                return Ok(ModuleResult::new());
            }
            digits
        } else {
            if query.len() < 3 {
                return Ok(ModuleResult::new());
            }
            query.to_string()
        };

        // Step 1: resolve the current datastore-active resource id for the
        // register (it rotates every quarter).
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
            &crate::util::ckan::datastore_search_url(ACTION_BASE, &resource_id, &q, MAX_RECORDS),
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
            &q,
            abn_query,
            &ctx.scan_id,
        ));
        Ok(out)
    }
}
