//! Australian Charities and Not-for-profits Commission (ACNC) register lookup
//! (keyless, free).
//!
//! Endpoint: `GET https://data.gov.au/data/api/3/action/datastore_search`
//!           `?resource_id={RESOURCE_ID}&q={name}&limit=100`
//! Auth:     none — the ACNC publishes the full national Register of Australian
//!           charities on `data.gov.au` (CKAN) as a public, datastore-active
//!           resource (~65k charities, refreshed regularly).
//!
//! This is the authoritative federal registry of not-for-profit *organisations*:
//! each row carries the charity's legal name, any other/trading names, its ABN,
//! registered address (street + town/state/postcode), website, size and number
//! of responsible persons. For an `Organisation` seed we full-text search the
//! register and, for every row whose name actually matches the seed, emit a web
//! of cross-correlating entities:
//!
//!   * `Organisation` — the charity (+ its other/trading names),
//!   * `AbnAcn` — the ABN, pivoted into `abn_lookup` / `opencorporates`,
//!   * `Address` — the registered locality (geocode → `Coordinates`),
//!   * `Domain` — the charity website (→ the DNS/web modules).
//!
//! The register's `q` is a *ranked* full-text search (not a strict AND), so it
//! returns loosely-related rows alongside true hits. We therefore classify each
//! row: rows whose name contains every seed token as a whole word are
//! `exact-name-match` (high confidence, fanned out into the pivots above); the
//! rest are surfaced as low-confidence `name-candidate` Organisations that carry
//! the full record (ABN, address, website, …) in their evidence — nothing the
//! API returned is dropped — but stay below the expansion floor so a generic
//! query can't pivot state-wide name noise.

use async_trait::async_trait;

use crate::core::{confidence, 
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::Response as CkanResp;
use crate::util::http::fetch_json;

mod entity;
#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "acnc_charities";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN resource id of the "ACNC Register of Australian charities" CSV datastore
/// on `data.gov.au`. Stable per-resource; if the ACNC ever re-publishes the
/// register under a new resource this is the single value to update.
pub(super) const RESOURCE_ID: &str = "8fb32972-24e9-4c95-885e-7140be51be8a";

/// Cap on rows turned into entities for one seed — bounds both the CKAN `limit`
/// and the rows emitted. Raised so a charity-name search surfaces its full set of
/// genuine matches (directive: never omit an API-derived AU government result);
/// the per-row whole-word classifier still keeps loosely-related rows out.
pub(super) const MAX_RECORDS: usize = 100;

/// Max other/trading names fanned out per charity.
pub(super) const MAX_TRADING_NAMES: usize = 25;

// Confidence tiers. Exact hits (name contains every seed token) are authoritative
// federal-registry matches and sit above the confidence::MEDIUM expansion floor so they pivot;
// candidates (loose full-text hits) stay below it so they're surfaced but inert.
pub(super) const ORG_EXACT: f64 = confidence::HIGH_PLUSPLUS_PLUS;
pub(super) const ORG_CANDIDATE: f64 = confidence::LOW_MEDIUM;
pub(super) const ABN_CONF: f64 = confidence::VERY_HIGH_PLUS;
pub(super) const TRADING_NAME_CONF: f64 = confidence::HIGH_PLUS;
pub(super) const ADDR_CONF: f64 = confidence::MEDIUM_PLUS;
pub(super) const DOMAIN_CONF: f64 = confidence::MEDIUM_HIGH;

pub struct AcncCharities;

#[async_trait]
impl Module for AcncCharities {
    fn name(&self) -> &'static str {
        "acnc_charities"
    }

    fn description(&self) -> &'static str {
        "ACNC charities recon — sweeps the Australian Charities & Not-for-profits Commission register for an entity (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): an authoritative federal
        // registry, dispatched with the other AU gov sources (abn_lookup 118,
        // au_unclaimed 114) and above the generic free band. Narrower than ABR
        // (charities only) so it sits just below au_unclaimed.
        112
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Organisation only: ACNC's unit is the not-for-profit org. A FullName
        // would full-text-match any charity containing that token (high noise,
        // and a person is not a row here), so we leave person→charity links to
        // the org entities this module feeds back into the graph.
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A charity/entity registry: it establishes the organisation
        // (T1591.002 Business Relationships) and geocodes its registered address
        // to coordinates, so it also Determines Physical Locations (T1591.001) —
        // which the Corporate default omits. It surfaces no individual
        // officer/role, so the default's T1591.004 (Identify Roles) is dropped
        // (cf. au_people / oathnet_pro).
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
        // A single datastore_search over the ~65k-row register on data.gov.au;
        // well under the default would risk killing a slow-but-connected fetch.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // A 1-2 char query would match noise across the whole register.
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let resp: CkanResp = fetch_json(&ctx.http, SRC, &entity::query_url(query)).await?;
        // Surface an application-level CKAN failure (success=false) as a module
        // error rather than masquerading as "no findings".
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
