//! Wikidata knowledge-graph lookup (keyless, free).
//!
//! Endpoints (MediaWiki Action API, public, keyless):
//!   * search: `…/w/api.php?action=wbsearchentities&search={q}&type=item`
//!   * claims: `…/w/api.php?action=wbgetentities&ids={Qid}&props=claims|labels|descriptions`
//!
//! For a `FullName` or `Organisation` seed we resolve the entity in Wikidata and,
//! for the best name-matching item, emit the directly-usable cross-correlation
//! pivots its structured claims carry:
//!
//!   * `Person` / `Organisation` — classified from P31 (`Q5` = human),
//!   * `Domain` — the official website (P856 → DNS/web modules),
//!   * `Username` — social-media handles (GitHub/X/Instagram/… → username_search).
//!
//! Precision over recall: Wikidata only holds *notable* entities and a name-only
//! seed has namesakes, so a false match is costly. We therefore require the
//! item's label to contain every seed token as a whole word (the same gate as
//! `acnc_charities`/`gleif_lei`); the top such match is fanned out, further
//! same-name items are surfaced as low-confidence candidates (with their Wikidata
//! id + description in evidence — nothing dropped) that stay below the expansion
//! floor so a namesake can't pivot. Single-source findings keep base confidence
//! until another module independently corroborates them.

mod builder;
mod claims;
mod classify;
#[cfg(test)]
mod tests;
mod types;
mod urls;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;

use self::builder::{candidate_entity, primary_entities};
use self::classify::{name_matches_query, seed_kind};
use self::types::{EntitiesResp, SearchResp};
use self::urls::{entities_url, search_url};

pub(super) const SRC: &str = "wikidata";
const API: &str = "https://www.wikidata.org/w/api.php";

/// Max same-name items surfaced (1 primary + the rest as candidates).
const MAX_CANDIDATES: usize = 6;
/// Max social handles fanned out from the primary item.
pub(super) const MAX_HANDLES: usize = 12;

// Confidence tiers vs the 0.50 noisy-OR expansion floor. The primary pivots;
// candidates stay sub-floor. People are kept a touch lower than orgs because a
// name-only seed is more ambiguous than an organisation name.
pub(super) const PERSON_PRIMARY: f64 = 0.72;
pub(super) const ORG_PRIMARY: f64 = 0.80;
pub(super) const CANDIDATE: f64 = 0.40;
pub(super) const DOMAIN_CONF: f64 = 0.58;
pub(super) const HANDLE_CONF: f64 = 0.55;
/// Confidence for the Wikidata P18 image URL. Moderate: the image authentically
/// depicts the matched subject, but the URL is a derived pointer, not a direct
/// finding about the subject's accounts.
pub(super) const IMAGE_CONF: f64 = 0.60;

/// Wikidata properties whose value is *itself* a social handle/username (a plain
/// string, no entity-id resolution needed) → emitted as `Username` for
/// `username_search` to enumerate. Curated to platforms whose id is a genuine
/// *handle* — opaque channel ids (e.g. YouTube P2397, `UC…`) are excluded since
/// they aren't searchable usernames and would only add noise.
pub(super) const HANDLE_PROPS: &[(&str, &str)] = &[
    ("P2002", "twitter"),
    ("P2003", "instagram"),
    ("P2037", "github"),
    ("P6634", "linkedin"),
    ("P3789", "telegram"),
    ("P4033", "mastodon"),
    ("P2013", "facebook"),
    ("P11245", "tiktok"),
];

pub struct Wikidata;

#[async_trait]
impl Module for Wikidata {
    fn name(&self) -> &'static str {
        "wikidata"
    }

    fn description(&self) -> &'static str {
        "Wikidata knowledge-graph entity resolution (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // People-enrichment band: an authoritative resolver of notable people /
        // orgs to their official site + social handles, just below name_intel.
        96
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Beyond the People default (T1589.003 Employee Names + T1591.004
        // Identify Roles), Wikidata's structured claims yield social-media
        // handles (T1593.001) and a P625 physical-location coordinate
        // (T1591.001). Superset of the default — coverage cannot regress.
        &["T1589.003", "T1591.004", "T1593.001", "T1591.001"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Domain,
            EntityKind::Username,
            EntityKind::Url,
            EntityKind::Coordinates,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // Two sequential MediaWiki calls (search + claims); beat the 3s default.
        12_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if query.len() < 3 {
            return Ok(ModuleResult::new());
        }

        let search: SearchResp = fetch_json(&ctx.http, SRC, &search_url(query)).await?;

        // Eligible = items whose label matches every seed token (precision gate).
        let eligible: Vec<&self::types::SearchHit> = search
            .search
            .iter()
            .filter(|h| {
                h.label
                    .as_deref()
                    .is_some_and(|l| name_matches_query(l, query))
            })
            .take(MAX_CANDIDATES)
            .collect();

        let Some((primary, rest)) = eligible.split_first() else {
            return Ok(ModuleResult::new());
        };

        let mut out = ModuleResult::new();
        let primary_label = primary.label.clone().unwrap_or_else(|| primary.id.clone());

        // Fetch the primary item's claims (non-fatal: candidates still surface).
        if let Ok(ents) =
            fetch_json::<EntitiesResp>(&ctx.http, SRC, &entities_url(&primary.id)).await
            && let Some(body) = ents.entities.get(&primary.id)
        {
            out.extend(primary_entities(
                &primary.id,
                &primary_label,
                body,
                target.kind,
                &ctx.scan_id,
            ));
        } else {
            // Claims unavailable — still surface the primary as a plain entity.
            let mut e = Entity::new(
                seed_kind(target.kind),
                &primary_label,
                CANDIDATE,
                &ctx.scan_id,
            );
            e.tag(SRC);
            e.tag("wikidata");
            e.tag(&primary.id);
            e.add_evidence(
                Evidence::new(SRC, format!("Wikidata {}: {primary_label}", primary.id))
                    .with_attr("wikidata_id", &primary.id),
            );
            out.push(e);
        }

        out.extend(
            rest.iter()
                .map(|hit| candidate_entity(hit, target.kind, &ctx.scan_id)),
        );

        Ok(out)
    }
}
