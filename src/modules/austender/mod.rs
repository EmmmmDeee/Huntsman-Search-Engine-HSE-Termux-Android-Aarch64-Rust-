//! AusTender — Australian Government contract notices (keyless, free).
//!
//! Endpoint: `GET https://data.gov.au/data/api/3/action/datastore_search`
//!           `?resource_id={RESOURCE_ID}&q={query}&limit=20`
//! Auth:     none — the Department of Finance publishes the AusTender contract
//!           notice export (`tenders.gov.au`) on `data.gov.au` (CKAN) as a
//!           public, datastore-active resource. Each row is a published contract
//!           notice: the awarded **supplier** (name + ABN + address), the
//!           **agency** that awarded it, the contract value, description and
//!           dates.
//!
//! Why it matters for OSINT: AusTender links a person or organisation to
//! *government business*. A supplier-name / ABN seed that wins Commonwealth work
//! surfaces here with its registered ABN (a pivot into the whole corporate stack
//! — `au_business_id`, `abn_lookup`, `asic_director`, `opencorporates`), its
//! business address (geocoded into Coordinates), and the procuring agency as a
//! `Business Relationship` (ATT&CK T1591.002). A `FullName` seed catches sole
//! traders and named individuals who contract to government.
//!
//! Matching is conservative. CKAN's `q` is a *ranked* full-text search (not a
//! strict AND), so it returns loosely-related rows alongside true hits. We
//! therefore classify each row: a supplier name that contains every seed token
//! as a whole word is an `exact-name-match` (high confidence, fanned out into the
//! ABN / address pivots); the rest are surfaced as low-confidence
//! `name-candidate` Organisations carrying the full record in evidence — nothing
//! the API returned is dropped — but kept below the expansion floor so a generic
//! query can't pivot national contract-name noise. An `AbnAcn` seed matches on
//! the exact ABN digits of the supplier row, which is unambiguous.

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
use crate::util::ckan::Response as CkanResp;
use crate::util::http::fetch_json;

pub(super) const SRC: &str = "austender";

/// CKAN action-endpoint base for `data.gov.au` (note the extra `/data` path
/// segment vs. other portals).
pub(super) const ACTION_BASE: &str = "https://data.gov.au/data/api/3/action";

/// CKAN resource id of the most recent datastore-active AusTender contract-notice
/// export on `data.gov.au` (Department of Finance, "Historical Australian
/// Government Contract Data" — 2017-18 financial year, the newest financial-year
/// resource the portal keeps datastore-active for `datastore_search`). Stable
/// per-resource; field names (`Supplier Name`, `Supplier ABN`, `Agency Name`, …)
/// are pinned by the module's test fixtures so a column rename can't silently break
/// extraction. If Finance re-publishes the export under a newer datastore-active
/// resource this is the single value to update.
pub(super) const RESOURCE_ID: &str = "bc2097b7-8116-4e9d-9953-98813635892a";

/// Cap on rows turned into entities for one seed — a generic single-word query
/// can match thousands of contract notices; we keep the highest-ranked handful
/// so a single seed doesn't flood the graph.
pub(super) const MAX_RECORDS: usize = 20;

// Confidence tiers. Exact hits (supplier name contains every seed token, or an
// exact ABN match) are authoritative federal-procurement matches and sit above
// the 0.50 expansion floor so they pivot; candidates (loose full-text hits) stay
// below it so they're surfaced but inert.
pub(super) const ORG_EXACT: f64 = 0.82;
pub(super) const ORG_CANDIDATE: f64 = 0.45;
pub(super) const ABN_CONF: f64 = 0.88;
pub(super) const AGENCY_CONF: f64 = 0.60;
pub(super) const ADDR_CONF: f64 = 0.58;

pub struct AusTender;

#[async_trait]
impl Module for AusTender {
    fn name(&self) -> &'static str {
        "austender"
    }

    fn description(&self) -> &'static str {
        "AusTender Australian Government contract notices (free, keyless) — supplier/ABN → awarded contracts, agency, ABN, address"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): an authoritative federal
        // procurement registry, dispatched with the other AU gov corporate
        // sources (acnc_charities 112, gleif_lei 111). Sits at 110, just below
        // the ASIC/ACNC registers — a contract notice is supporting corporate
        // intel rather than a primary registration record.
        110
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        // Organisation / FullName: supplier-name full-text search (companies and
        // sole-trader individuals who contract to government). AbnAcn: an exact
        // ABN match on the supplier row — the unambiguous pivot.
        matches!(
            t.kind,
            TargetKind::Organisation | TargetKind::FullName | TargetKind::AbnAcn
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A government-procurement registry establishes a Business Relationship
        // between the supplier and the awarding agency (T1591.002) and geocodes
        // the supplier's registered business address to coordinates, so it also
        // Determines Physical Locations (T1591.001) — which the Corporate default
        // omits. It surfaces no individual officer/role, so the default's
        // T1591.004 (Identify Roles) is dropped (cf. acnc_charities / gleif_lei).
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
        // A single datastore_search over the multi-hundred-thousand-row contract
        // export on data.gov.au; well above the 3s default so a slow-but-connected
        // fetch isn't killed mid-request (the non-passive-budget CI guard).
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        // For a name/org query, a 1-2 char term would match noise across the
        // whole export; an ABN query is normalised to its digits and length-gated.
        let abn_query = matches!(target.kind, TargetKind::AbnAcn);
        let q = if abn_query {
            let digits = crate::util::str_util::ascii_digits(query);
            if digits.len() != 11 {
                // Only an 11-digit ABN identifies a supplier row; a bare 9-digit
                // ACN is not the column AusTender indexes on, so don't query.
                return Ok(ModuleResult::new());
            }
            digits
        } else {
            if query.len() < 3 {
                return Ok(ModuleResult::new());
            }
            query.to_string()
        };

        let resp: CkanResp = fetch_json(&ctx.http, SRC, &entity::query_url(&q)).await?;
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
            &q,
            abn_query,
            &ctx.scan_id,
        ));
        Ok(out)
    }
}
