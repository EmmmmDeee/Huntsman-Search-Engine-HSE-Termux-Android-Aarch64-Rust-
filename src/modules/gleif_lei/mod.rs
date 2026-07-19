//! Global Legal Entity Identifier (GLEIF) lookup (keyless, free).
//!
//! Endpoint: `GET https://api.gleif.org/api/v1/lei-records`
//!           `?filter[entity.legalName]={name}&page[size]=100`
//! Auth:     none — GLEIF publishes the global LEI index as a public,
//!           keyless JSON:API (the authoritative ISO 17442 registry of legal
//!           entities that trade in financial markets, ~2.7M records).
//!
//! For an `Organisation` seed we search the LEI index by legal name and, for
//! every row whose name matches the seed, emit cross-correlating entities:
//!
//!   * `Organisation` — the legal entity (authoritative legal name),
//!   * `AbnAcn` — for AU entities, GLEIF's `registeredAs` is the local registry
//!     id (the ACN/ABN), pivoted into `abn_lookup` / `opencorporates` / `acnc`,
//!   * `Address` — the registered (HQ / legal) address (geocode → `Coordinates`).
//!
//! This is an *independent* corroborator of the corporate graph: an org/ABN that
//! GLEIF confirms from a different authority than ABR/ACNC drives `c_effective`
//! up via the noisy-OR agreement model, so genuinely multi-sourced entities
//! cross the expansion floor and pivot. The LEI itself, the entity status,
//! jurisdiction and any foreign `registeredAs` are carried in evidence so
//! nothing the API returns is dropped, even for loose matches that don't pivot.

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

mod helpers;
mod transform;
mod types;

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "gleif_lei";

/// Cap on rows turned into entities for one seed — bounds both the GLEIF
/// `page[size]` and the rows emitted. Raised so every genuine LEI name match
/// surfaces (directive: never omit an API-derived result); LEI name search is
/// precise, so this is a generous ceiling a real query stays well under.
pub(super) const MAX_RECORDS: usize = 100;

// Confidence tiers, aligned with the gov/corporate band and the noisy-OR
// expansion floor (confidence::MEDIUM): exact name matches pivot immediately; loose candidates
// stay below the floor so they're surfaced but inert unless independently
// corroborated.
pub(super) const ORG_EXACT: f64 = confidence::HIGH_PLUSPLUS_PLUS;
pub(super) const ORG_CANDIDATE: f64 = confidence::LOW_MEDIUM;
pub(super) const ABN_CONF: f64 = confidence::EXPERT;
pub(super) const ADDR_CONF: f64 = confidence::MEDIUM_PLUS;

pub struct GleifLei;

#[async_trait]
impl Module for GleifLei {
    fn name(&self) -> &'static str {
        "gleif_lei"
    }

    fn description(&self) -> &'static str {
        "GLEIF recon (free, keyless) — resolves a Global Legal Entity Identifier (LEI) to its registered entity"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): a global authoritative
        // registry, dispatched with the corporate sources (abn_lookup 118,
        // opencorporates 116, au_unclaimed 114, acnc_charities 112) and above the
        // generic free band. Global/cross-walk, so just below the AU-specific ones.
        111
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Organisation only: GLEIF's unit is the legal entity. The reverse
        // ABN->LEI filter is unreliable, so we feed off the Organisation entities
        // the graph produces (incl. from abn_lookup / opencorporates / acnc).
        matches!(t.kind, TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A legal-entity (LEI) registry: it establishes the organisation
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
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A single name search against api.gleif.org; beat the 3s default so a
        // slow-but-connected response isn't killed.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // A 1-2 char query would match noise across the global index.
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let resp: types::GleifResp = fetch_json(&ctx.http, SRC, &helpers::query_url(query)).await?;
        let mut out = ModuleResult::new();
        out.extend(transform::records_to_entities(&resp, query, &ctx.scan_id));
        Ok(out)
    }
}
