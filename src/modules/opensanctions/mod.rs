//! OpenSanctions sanctions / politically-exposed-person (PEP) / watchlist
//! screening — aggregates 400+ global sources behind one fuzzy name-matching
//! API, including OFAC's SDN list, the UN Security Council list, the EU
//! consolidated list, UK OFSI, and — the reason this module exists —
//! Australia's own DFAT Consolidated List, which otherwise has no public
//! real-time API of its own (only a periodically-updated XLSX download). One
//! query against OpenSanctions' `default` dataset scope screens a subject
//! against all of these at once rather than requiring a bespoke scraper per
//! jurisdiction.
//!
//! Endpoint: `POST https://api.opensanctions.org/match/default`
//! Auth: `Authorization: ApiKey <key>` header. Key-gated
//! (`HUNTSMAN_OPENSANCTIONS_KEY`) — OpenSanctions issues free trial and
//! nonprofit/journalism keys via self-serve signup; see
//! <https://www.opensanctions.org/docs/api/>.
//!
//! Query-by-example: the seed `FullName` is submitted as a `Person`-schema
//! query (`properties.name`). OpenSanctions' own fuzzy matcher scores
//! candidates from its aggregated entity graph and sets `match: true` once a
//! candidate clears its confidence threshold (left at the API's own default,
//! 0.7, rather than second-guessed here). **Only `match: true` results are
//! escalated into a `Person` entity** — a fuzzy candidate below that bar is
//! not turned into a sanctions/PEP claim about a real person, since a false
//! positive here is a serious, reputationally consequential mistake (this
//! codebase's evidentiary-honesty doctrine: a false positive is worse than
//! missing coverage).
//!
//! Each escalated match carries: the `datasets` it was sourced from (with
//! Australia's `au_dfat_sanctions` tagged distinctly), `topics` (`sanction`,
//! `role.pep`, `debarment`, …) mapped to the corresponding tag, the PEP's
//! official `position` where listed (a genuine role field — see
//! `attack_techniques()` for why this isn't a category-default over-claim),
//! `birth_date`, `nationality`/`country`, and the specific `program_id`.
//!
//! Scoped to `Person`/`FullName` screening only this cycle — OpenSanctions'
//! `/match` endpoint equally supports a `Company`/`Organization` schema for
//! corporate sanctions/debarment screening, deliberately deferred to a
//! follow-up (one target-kind surface per cycle; see `PROBLEM_TREE` T2.17).
//!
//! Pure entity construction lives in [`entity_builders::build_entities`],
//! unit-tested without a live API; `process()` owns only transport.

mod entity_builders;
mod types;

#[cfg(test)]
mod tests;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

use entity_builders::build_entities;
use types::MatchResp;

pub(crate) const KEY_ENV: &str = "HUNTSMAN_OPENSANCTIONS_KEY";
pub(crate) const SRC: &str = "opensanctions";

/// Base confidence for an escalated (`match: true`) Person entity — a
/// corroborated fuzzy-identity match from an authoritative aggregator, but
/// not independently confirmed by this scan (a same-name different person is
/// possible without corroborating DOB/nationality on our side), so pitched
/// at the same single-source-directory tier as `hlr_cnam`'s CNAM `Person`
/// pivot (confidence::MEDIUM_HIGH) / `au_people`'s directory confirmations (0.62) — not
/// hibp/dehashed's direct-identity-confirmation tier, since the subject here
/// isn't the literal seed value but an aggregator's best-scoring candidate.
pub(super) const MATCH_CONF: f64 = confidence::MEDIUM_PLUS;

/// A match this strong (name plus corroborating detail essentially exact)
/// earns an extra tag distinguishing it from a borderline hit that only just
/// cleared the API's own match threshold.
pub(super) const HIGH_CONFIDENCE_SCORE: f64 = confidence::VERY_HIGH_PLUS;

pub struct OpenSanctions;

#[async_trait]
impl Module for OpenSanctions {
    fn name(&self) -> &'static str {
        "opensanctions"
    }

    fn description(&self) -> &'static str {
        "OpenSanctions screening — cross-checks sanctions/PEP/watchlist exposure across OFAC, UN, EU, DFAT (AU), and 400+ global sources"
    }

    fn priority(&self) -> u8 {
        // Government-list-aggregating identity-risk band: below hibp/dehashed
        // (direct breach-identity confirmation) but above the general
        // public-records band (asic_persons 112) — sanctions/PEP status is a
        // high-severity, authoritative regulatory-risk signal.
        115
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        // A single-token value can't be meaningfully name-matched — require
        // at least two tokens, mirroring au_people's identical gate.
        t.kind == TargetKind::FullName && t.value.trim().contains(' ')
    }

    /// `accepts()` value-gates (a name must have ≥2 tokens), so the default
    /// probe-based `consumes()` would silently omit `FullName` from the
    /// dispatch index — the identical fix `au_people` already needed for the
    /// same shape of gate.
    fn consumes(&self) -> Vec<TargetKind> {
        vec![TargetKind::FullName]
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Matches the People category default exactly, declared explicitly
        // (rather than silently inherited) so it's self-documented and
        // immune to a future default change silently altering this module's
        // claimed coverage. T1589.003 (Employee Names): confirms/
        // canonicalises a person's legal name via an authoritative caption.
        // T1591.004 (Identify Roles): genuinely earned, not a category-
        // default over-claim — PEP records carry a real `position` field
        // (e.g. "Minister of Foreign Affairs"), unlike the identical-looking
        // claim already corrected for `seon` this session.
        &["T1589.003", "T1591.004"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            None => return Ok(ModuleResult::new()),
        };

        let name = target.value.trim();

        let resp = ctx
            .http
            .post("https://api.opensanctions.org/match/default")
            .header("Authorization", format!("ApiKey {key}"))
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "queries": {
                    "q": {
                        "schema": "Person",
                        "properties": { "name": [name] }
                    }
                }
            }))
            .send_tagged(SRC)
            .await?;

        // 401/403/429 → note_keyed_error + Err; 404 → empty; other non-2xx → Err.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        let body: MatchResp = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        result.extend(build_entities(name, &body.responses.q, &ctx.scan_id));
        Ok(result)
    }
}
