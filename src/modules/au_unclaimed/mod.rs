//! Australian unclaimed money register — the Queensland Public Trustee dataset
//! on `data.qld.gov.au`, the **only** Australian jurisdiction that publishes its
//! unclaimed-money register as a record-level CKAN datastore (queryable via
//! `datastore_search`).
//!
//! The QLD pass (folded in from the former standalone `qld_unclaimed` module)
//! keeps its full, richer pipeline: surname-broadened search merged with an
//! exact-name pass, joint / associated owner parsing into first-class `Person`
//! nodes, company-owner `Organisation` ABN pivots, postcode-derived owner state,
//! and suburb-level locality enumeration. Its evidence is tagged with the
//! `qld_unclaimed` source so the correlator / relation / geo-family rules that
//! key on the Queensland register keep firing.
//!
//! ## Why Queensland only
//!
//! The other states and territories do **not** expose an unclaimed-money
//! register that `datastore_search` can query — verified against each portal's
//! live CKAN API (2026-06):
//!   * **NSW** (`data.nsw.gov.au`) — publishes only non-datastore artefacts (an
//!     external-link landing page, PDFs, summary spreadsheets); every unclaimed
//!     package has `datastore_active=false`, so there is no record-level resource.
//!   * **VIC** (`data.vic.gov.au`) — exposes no CKAN `/api/3/action` endpoint at
//!     all (the portal migrated off CKAN); every action returns HTTP 404.
//!   * **WA** (`catalogue.data.wa.gov.au`) — has no unclaimed-money dataset
//!     (`package_search` returns zero hits).
//!   * **SA** (`data.sa.gov.au`) — the national aggregator; its only
//!     datastore-active "unclaimed monies" resource is the *harvested QLD*
//!     dataset (the same resource id, which 404s on SA's own datastore), not an
//!     SA register.
//!
//! Earlier revisions carried fabricated resource IDs for these four states that
//! returned HTTP 404 on every scan — phantom coverage that spent network budget
//! and surfaced no data. They have been removed. If a jurisdiction later
//! publishes a real CKAN datastore, reintroduce it with an empirically-verified
//! resource id and its true field names (the QLD pass is the working template).
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (address/postcode from records)
//!   * T1589.003 — Employee Names (confirms legal name variant)
//!   * T1591.002 — Business Relationships (unclaimed from employer/estate)

mod qld_helpers;

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::Response as CkanResp;
use crate::util::http::fetch_json;

const SRC: &str = "au_unclaimed";

pub struct AuUnclaimed;

#[async_trait]
impl Module for AuUnclaimed {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Australian unclaimed-money register recon (QLD Public Trustee) — pivots a name to address, owner, and organisation leads"
    }

    fn priority(&self) -> u8 {
        // Authoritative government register band (inherited from the folded-in
        // QLD Public Trustee source, formerly `qld_unclaimed` at 114): a
        // government unclaimed-money register must outrank the generic free
        // name-intel band and sit alongside the other AU registries
        // (abn_lookup 118, opencorporates 116, acnc_charities 112).
        114
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
            && t.value.trim().len() >= 3
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1589.003", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        // Address/Coordinates from the register's postcode records; Organisation
        // (company owners) and Person (joint/associated owners) from the QLD
        // owner-parsing pass folded in from the former `qld_unclaimed` module.
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
            EntityKind::Person,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        // Queensland Public Trustee register — the only AU jurisdiction with a
        // queryable CKAN unclaimed-money datastore (see the module docs for the
        // empirical per-state verification). Because QLD is the *sole* source,
        // a genuine failure of its primary query (transport error, non-2xx
        // status, unparseable body, or a CKAN `success:false` application
        // error) is propagated as a real module error rather than swallowed
        // into an empty result (T2.119) — a real data.qld.gov.au outage must
        // not read as "no unclaimed money found for this person."
        process_qld(target, ctx, &mut result).await?;

        Ok(result)
    }
}

/// Queensland Public Trustee register pass — the full pipeline carried over from
/// the former standalone `qld_unclaimed` module (surname-broadened search merged
/// with an exact-name pass, owner Person/Organisation extraction, and
/// suburb-level locality enumeration restricted to the seed's own postcodes).
///
/// Extends `out` in place. QLD is the *only* pass (see the module docs for why
/// every other state/territory lacks a queryable datastore), so a genuine
/// failure of its **primary** query — a transport error, non-2xx status, or
/// unparseable body (propagated by `fetch_json` via `?`), or a CKAN
/// `success:false` application error — is returned as a real `Error` (T2.119)
/// rather than swallowed into an empty result; [`AuUnclaimed::process`]
/// surfaces it so a real outage of the last QLD source is visible instead of
/// masquerading as "no unclaimed money found." A genuinely empty result set
/// (no `result`, or no matching records) stays the honest clean miss, and the
/// *secondary* exact-name fetch + per-postcode locality lookups remain
/// best-effort enrichment layered on the primary records already in hand.
async fn process_qld(target: &Target, ctx: &ModuleContext, out: &mut ModuleResult) -> Result<()> {
    use qld_helpers::{
        derive_query, exact_postcodes, merge_records, query_url, records_to_entities,
        suburbs_to_entities,
    };

    let full = target.value.trim();
    if full.len() < 3 {
        return Ok(());
    }
    let surname = derive_query(target);

    let broad: CkanResp = fetch_json(&ctx.http, qld_helpers::SRC, &query_url(surname)).await?;
    // A `success:false` (bad resource id / portal error) is a genuine
    // application-level failure of the sole QLD source, not a "no data" result —
    // surface it as a module error (mirrors `acnc_charities`/the ASIC modules).
    if broad.success == Some(false) {
        return Err(Error::module(
            qld_helpers::SRC,
            "CKAN datastore_search returned success=false (bad resource id or portal error)",
        ));
    }
    let Some(broad_res) = broad.result else {
        return Ok(());
    };
    let total = broad_res.total.unwrap_or(broad_res.records.len() as u64);
    let mut records = broad_res.records;

    if surname != full
        && let Ok(exact) =
            fetch_json::<CkanResp>(&ctx.http, qld_helpers::SRC, &query_url(full)).await
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

    out.extend(records_to_entities(
        &records,
        total,
        full,
        surname,
        broadened,
        &ctx.scan_id,
    ));
    out.extend(suburbs_to_entities(&pc_localities, &ctx.scan_id));
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
