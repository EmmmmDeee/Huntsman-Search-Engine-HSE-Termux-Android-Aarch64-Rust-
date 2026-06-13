//! Australian property and land title register searches.
//!
//! Queries publicly-accessible property and land title portals to find
//! registered ownership records for a full-name seed. Property title
//! registration is compulsory in Australia; ownership records are public
//! and freely searchable through state portals and their data services.
//!
//! Sources (all free, keyless):
//!   * NSW Spatial — `https://maps.six.nsw.gov.au/` (owner name search via
//!     ELVIS cadastral API — free, no key required for basic lookups)
//!   * VIC MapShare — `https://mapshare.vic.gov.au/` (parcel/owner search)
//!   * QLD Globe — `https://qldglobe.information.qld.gov.au/` (lot/plan owner)
//!   * data.gov.au Geocoded National Address File (GNAF) — suburb/postcode
//!     from lot/plan references, open-data, no key required
//!
//! MITRE ATT&CK:
//!   * T1591.001 — Determine Physical Locations (property address + suburb)
//!   * T1591.002 — Business Relationships (co-owners, trusts, companies)
//!   * T1589.003 — Employee Names (confirms legal registered name)
//!
//! Confidence model:
//!   * Registered owner with suburb + state: 0.74 (title register is
//!     government-maintained, higher than directory or electoral sources)
//!   * Suburb + postcode only (no street address exposed): 0.62
//!   * Coordinates from suburb centroid: 0.60 (derived, not raw)
//!
//! Orthogonal to `au_electoral` (electoral roll), `au_people` (residential
//! directories), `abn_lookup` (business register), `asic_director` (company
//! directors) — property ownership is a distinct legal record class.

mod parse;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

use parse::{
    dedup_entities, parse_nsw_response, parse_qld_response, parse_vic_response, record_to_entities,
    split_name, surname, SRC,
};

pub struct AuProperty;

// ─── Module impl ──────────────────────────────────────────────────────────

#[async_trait]
impl Module for AuProperty {
    fn name(&self) -> &'static str {
        "au_property"
    }

    fn description(&self) -> &'static str {
        "Australian property and land title register searches — finds registered \
         ownership records (suburb/state/postcode) for a full-name seed via NSW, \
         VIC, and QLD public cadastral portals"
    }

    fn accepts(&self, t: &Target) -> bool {
        t.kind == TargetKind::FullName
    }

    fn produces(&self) -> &'static [EntityKind] {
        &[EntityKind::Address, EntityKind::Coordinates]
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1591.001", "T1591.002", "T1589.003"]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn priority(&self) -> u8 {
        84
    }

    fn max_timeout_ms(&self) -> u64 {
        // Three sequential state portal requests, each ~3–5 s.
        18_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full_name = target.value.trim();
        if full_name.is_empty() {
            return Ok(ModuleResult::new());
        }

        let (first, last) = split_name(full_name);
        if last.is_empty() {
            return Ok(ModuleResult::new());
        }
        let sname = surname(full_name);
        let encoded_full = crate::util::http::urlencode(full_name);
        let encoded_sname = crate::util::http::urlencode(sname);
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        let mut all_entities: Vec<Entity> = Vec::new();

        // ── NSW Spatial / ELVIS cadastral ─────────────────────────────────
        // ELVIS name search endpoint — surname + given name query.
        let nsw_url = format!(
            "https://maps.six.nsw.gov.au/services/public/Property_Name_Address?surname={}&givenname={}&maxRows=10",
            crate::util::http::urlencode(last),
            crate::util::http::urlencode(first),
        );
        if let Ok(resp) = ctx
            .http
            .get(&nsw_url)
            .header("Accept", "application/json,text/html")
            .header("User-Agent", ua)
            .send_tagged(SRC)
            .await
            && resp.status().is_success()
            && let Ok(body) = resp.text().await
        {
            all_entities.extend(
                parse_nsw_response(&body, full_name)
                    .iter()
                    .flat_map(|rec| record_to_entities(rec, &ctx.scan_id)),
            );
        }

        // ── VIC MapShare ──────────────────────────────────────────────────
        if all_entities.is_empty() {
            let vic_url = format!(
                "https://mapshare.vic.gov.au/mapsharevic/ows?service=WFS&version=1.0.0\
                 &request=GetFeature&typeName=CADASTRE:PARCEL&outputFormat=application/json\
                 &CQL_FILTER=OWNER_NAME+LIKE+%27{}%25%27&maxFeatures=10",
                encoded_sname
            );
            if let Ok(resp) = ctx
                .http
                .get(&vic_url)
                .header("Accept", "application/json,text/html")
                .header("User-Agent", ua)
                .send_tagged(SRC)
                .await
                && resp.status().is_success()
                && let Ok(body) = resp.text().await
            {
                all_entities.extend(
                    parse_vic_response(&body, full_name)
                        .iter()
                        .flat_map(|rec| record_to_entities(rec, &ctx.scan_id)),
                );
            }
        }

        // ── QLD Globe / titles ────────────────────────────────────────────
        if all_entities.is_empty() {
            let qld_url = format!(
                "https://www.qld.gov.au/environment/land/title/searching/owners?owner={}",
                encoded_full
            );
            if let Ok(resp) = ctx
                .http
                .get(&qld_url)
                .header("Accept", "text/html,application/xhtml+xml")
                .header("User-Agent", ua)
                .send_tagged(SRC)
                .await
                && resp.status().is_success()
                && let Ok(body) = resp.text().await
            {
                all_entities.extend(
                    parse_qld_response(&body, full_name)
                        .iter()
                        .flat_map(|rec| record_to_entities(rec, &ctx.scan_id)),
                );
            }
        }

        // Dedup by (kind, value) — different portals may agree on the same suburb.
        dedup_entities(&mut all_entities);

        let mut result = ModuleResult::new();
        result.entities = all_entities;
        Ok(result)
    }
}
