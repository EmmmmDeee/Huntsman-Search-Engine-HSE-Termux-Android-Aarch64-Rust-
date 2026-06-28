//! DFAT Consolidated List — Australian autonomous sanctions / PEP screening
//! (keyless, free).
//!
//! Source: the Department of Foreign Affairs and Trade publishes the
//! **Consolidated List** — every person and entity targeted by Australia's
//! autonomous and UN-derived sanctions regimes — as a free, public CSV export at
//! a stable canonical URL ([`LIST_URL`]). No API key, no auth.
//!
//! Why it matters for OSINT: a `FullName` or `Organisation` seed screened
//! against the Consolidated List is a high-signal adverse finding for any
//! name-based investigation — sanctions exposure and politically-exposed-person
//! (PEP) risk. A hit emits a first-class `Person` (individual) or `Organisation`
//! (entity) tagged `sanctions` / `pep`, carrying the full listed record (listing
//! reference, designation regime/committees, date & place of birth, citizenship,
//! address, additional information) verbatim in its evidence — nothing the export
//! returned is dropped.
//!
//! Matching is conservative and whole-word: a row is a hit only when the listed
//! name contains **every** seed token as a whole word (case-insensitive), so a
//! single common token can't drag in unrelated listings. A multi-token seed is
//! required for individuals (a lone given/family name is too broad against a
//! global watchlist); a distinctive single-token organisation name is allowed.
//!
//! Implementation note: the Consolidated List is distributed only as a flat CSV
//! (DFAT exposes no record-level query API and no `data.gov.au` datastore for
//! it), so this module fetches and parses the whole export once per matching
//! seed with a dependency-free RFC 4180 reader ([`csv`]). The body is size-capped
//! ([`MAX_BODY`]) to stay within Termux memory limits, and any transport/parse
//! failure degrades to an empty result rather than erroring the scan.
//!
//! MITRE ATT&CK Reconnaissance:
//!   * T1589.003 — Employee Names (confirms a listed individual's identity),
//!   * T1591.002 — Business Relationships (a sanctioned organisation/regime tie).

mod csv;
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
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_body_capped};

pub(super) const SRC: &str = "dfat_sanctions";

/// Canonical DFAT Consolidated List CSV export. Stable, documented public URL;
/// the single value to update if DFAT relocates the export.
pub(super) const LIST_URL: &str =
    "https://www.dfat.gov.au/sites/default/files/regulation8_consolidated.csv";

/// Upper bound on the export body we will buffer (~12 MB). The Consolidated List
/// is a few MB; the cap protects a low-memory Termux device from a hostile or
/// misconfigured upstream returning an unbounded body. The shared reqwest client
/// has no decompression feature, so this bounds the raw on-the-wire bytes.
pub(super) const MAX_BODY: usize = 12 * 1024 * 1024;

/// Cap on rows turned into entities for one seed.
pub(super) const MAX_HITS: usize = 10;

// Confidence tiers. A sanctions hit is a strong adverse finding but the seed
// name might collide with a namesake on a global watchlist, so it sits at the
// Probable tier (above the 0.50 expansion floor so it pivots, below Verified so
// it isn't asserted as the subject without corroboration).
pub(super) const PERSON_CONF: f64 = 0.60;
pub(super) const ORG_CONF: f64 = 0.62;

pub struct DfatSanctions;

#[async_trait]
impl Module for DfatSanctions {
    fn name(&self) -> &'static str {
        "dfat_sanctions"
    }

    fn description(&self) -> &'static str {
        "DFAT Consolidated List — Australian autonomous sanctions / PEP screening (free, keyless) for a name or organisation"
    }

    fn priority(&self) -> u8 {
        // People/adverse-screening band, alongside the other AU people sources
        // (au_people 88, ahpra 86). A sanctions screen is high-value context for
        // a name seed, dispatched with the people-registry cluster.
        87
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        // A name/PEP screen targeting individuals and entities — People is the
        // closest functional bucket (it also screens organisations, captured by
        // the explicit T1591.002 in attack_techniques()).
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Confirms a listed individual's identity (T1589.003 Employee Names) and,
        // for a listed entity, a sanctioned Business Relationship (T1591.002).
        // The People default also claims T1591.004 (Identify Roles) — a
        // Consolidated List row carries no organisational role, so it's dropped.
        &["T1589.003", "T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A single multi-MB CSV download over a possibly-mobile link; well above
        // the 3s default so a slow-but-connected fetch isn't killed mid-stream
        // (the non-passive-budget CI guard).
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        let seed_is_person = matches!(target.kind, TargetKind::FullName);

        // A national/global watchlist needs a discriminating query. Individuals
        // require ≥2 name tokens (a lone given/family name is far too broad); an
        // organisation may match on a distinctive single token but must clear a
        // minimum length so a 1-2 char query can't sweep the list.
        let token_count = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 2)
            .count();
        if seed_is_person && token_count < 2 {
            return Ok(ModuleResult::new());
        }
        if !seed_is_person && (token_count == 0 || query.len() < 3) {
            return Ok(ModuleResult::new());
        }

        let resp = ctx
            .http
            .get(LIST_URL)
            .header("User-Agent", UA_BROWSER)
            .send_tagged(SRC)
            .await?;
        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }
        let Some(body) = read_body_capped(resp, MAX_BODY).await else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.extend(self.match_rows(&body, query, seed_is_person, &ctx.scan_id));
        Ok(result)
    }
}

impl DfatSanctions {
    /// Pure transform: a CSV export body + a seed → the matched adverse-finding
    /// entities. Split out from [`Module::process`] so the matching/extraction
    /// logic is unit-testable against a fixture without any network.
    pub(super) fn match_rows(
        &self,
        body: &str,
        query: &str,
        seed_is_person: bool,
        scan_id: &str,
    ) -> Vec<crate::core::entity::Entity> {
        let rows = csv::parse(body);
        let Some((header, data)) = rows.split_first() else {
            return Vec::new();
        };
        let index = csv::header_index(header);
        // No name column → the export shape changed; emit nothing rather than
        // guess (a visible no-op the live test and fixtures guard against).
        if !index.contains_key(entity::COL_NAME) {
            return Vec::new();
        }

        let mut out = Vec::new();
        for row in data {
            if out.len() >= MAX_HITS {
                break;
            }
            let Some(name) = entity::cell(row, &index, entity::COL_NAME) else {
                continue;
            };
            if !entity::name_matches(name, query) {
                continue;
            }
            if let Some(e) = entity::row_to_entity(row, &index, seed_is_person, scan_id) {
                out.push(e);
            }
        }
        out
    }
}
