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
//! `acnc_charities`/`gleif_lei`); the top such match is fanned out, and up to
//! [`MAX_CANDIDATES`] further same-name items are surfaced as low-confidence
//! candidates (with their Wikidata id + description in evidence) that stay
//! below the expansion floor so a namesake can't pivot. When more than
//! `MAX_CANDIDATES` items match the name (the search API's own `limit=10`
//! bounds how many can), the surplus IS dropped — the primary/head entity is
//! tagged `truncated` with the true match count so an operator knows the
//! candidate list isn't exhaustive. Single-source findings keep base
//! confidence until another module independently corroborates them.

mod builder;
mod claims;
mod classify;
#[cfg(test)]
mod tests;
mod types;
mod urls;

use async_trait::async_trait;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::fetch_json;
use crate::util::mediawiki::MwError;

use self::builder::{candidate_entity, mark_shared_labels, primary_entities};
use self::classify::{name_matches_query, seed_kind};
use self::types::{EntitiesResp, SearchResp};
use self::urls::{entities_url, search_url};

pub(super) const SRC: &str = "wikidata";
const API: &str = "https://www.wikidata.org/w/api.php";

/// Max same-name items surfaced (1 primary + the rest as candidates).
const MAX_CANDIDATES: usize = 6;

/// The search API's page size: the `limit=` [`urls::search_url`] requests, and
/// the size a full page is measured against. One constant, so the request and
/// the check cannot drift apart (REQ-ZOOMEYE-002's surviving mutation was a
/// caller passing the wrong cap).
const SEARCH_LIMIT: usize = 10;

// Confidence tiers vs the confidence::MEDIUM noisy-OR expansion floor. The primary pivots;
// candidates stay sub-floor. People are kept a touch lower than orgs because a
// name-only seed is more ambiguous than an organisation name.
pub(super) const PERSON_PRIMARY: f64 = confidence::ATTRIBUTED;
pub(super) const ORG_PRIMARY: f64 = confidence::HIGH_PLUSPLUS;
pub(super) const CANDIDATE: f64 = confidence::LOW;
pub(super) const DOMAIN_CONF: f64 = confidence::MEDIUM_SOLID;
pub(super) const HANDLE_CONF: f64 = confidence::MEDIUM_HIGH;
/// Confidence for the Wikidata P18 image URL. Moderate: the image authentically
/// depicts the matched subject, but the URL is a derived pointer, not a direct
/// finding about the subject's accounts.
pub(super) const IMAGE_CONF: f64 = confidence::MEDIUM_PLUS;

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
    // P4479 = Reddit username (stable Wikidata property).
    ("P4479", "reddit"),
    // P2397 excluded (YouTube channel ID starts with "UC" — not a searchable handle).
    // P7085 = TikTok creative profile ID (alternative to P11245).
    // P3553 = YouTube channel (handle form "@alice") — worth extracting when present.
    ("P3553", "youtube"),
];

pub struct Wikidata;

#[async_trait]
impl Module for Wikidata {
    fn name(&self) -> &'static str {
        "wikidata"
    }

    fn description(&self) -> &'static str {
        "Wikidata recon — resolves an entity against the open knowledge graph (free, keyless)"
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
            return Err(crate::core::error::Error::query_too_weak(
                crate::core::event::SkipClass::Scoped,
                query,
                "a 1-2 character query matches noise across every Wikidata label",
            ));
        }

        let search: SearchResp = fetch_json(&ctx.http, SRC, &search_url(query)).await?;
        // A MediaWiki HTTP-200 error envelope (maxlag, backend error, bad
        // params) decodes to an empty `search` list; without this gate that
        // reads as a clean "no matching item" negative. Fail closed instead.
        // (The later `wbgetentities` claims call stays intentionally non-fatal —
        // the candidate items already found still surface.)
        MwError::check(&search.error, SRC)?;

        // Eligible = items whose label matches every seed token (precision gate).
        // The filter is split from the cap so `total_name_matches` recovers the
        // pre-cap count — the search API's own `search` array (limit=10) can
        // hold more name-matching items than MAX_CANDIDATES surfaces.
        let name_matched: Vec<&self::types::SearchHit> = search
            .search
            .iter()
            .filter(|h| {
                h.label
                    .as_deref()
                    .is_some_and(|l| name_matches_query(l, query))
            })
            .collect();
        let total_name_matches = name_matched.len();
        let eligible = &name_matched[..total_name_matches.min(MAX_CANDIDATES)];

        let mut out = ModuleResult::new();
        let Some((primary, rest)) = eligible.split_first() else {
            // No label on this page is the name — which is a clean negative
            // only if the page held everything. See `declare_search_truncation`.
            declare_search_truncation(&mut out, search.search.len(), total_name_matches);
            return Ok(out);
        };

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

        finish_answer(
            &mut out,
            target.kind,
            query,
            &name_matched,
            search.search.len(),
        );
        Ok(out)
    }
}

/// Everything `process` does to its answer once the primary (always
/// `out.entities[0]`: both of `process`'s branches push it first) and the
/// surfaced candidates are built. **Pure**, so the order below is testable
/// without the network round trip `process` hardcodes. `name_matched` is every
/// search hit whose label passed the name gate, in rank order — more than
/// [`MAX_CANDIDATES`] when the cap cut the answer; `returned` is the size of
/// the search page.
///
/// 1. The truncation note goes on the head FIRST. `mark_ambiguous` (inside
///    [`mark_shared_labels`]) stamps every record the entity carries at the
///    time it runs `Unverified`, and its contract is to be called after the
///    evidence is attached. Appending the note afterwards left it the one
///    countable record on an ambiguous head, and the head fuses onto the
///    subject's same-named anchor: scan 7258fc07 ("Ian Thorpe", more than six
///    matches, the NZ-soldier head) counted `wikidata` as a corroborating
///    source of the swimmer. The note is also an annotation in its own right
///    (see [`mark_candidate_truncation`]), so it cannot corroborate in either
///    order — the ordering keeps `mark_ambiguous`'s contract whole anyway.
/// 2. Shared labels are judged over EVERY name-matched hit, not only the
///    surfaced ones: a label the primary shares with an item ranked 7th–10th
///    still means the name does not identify one item, and judging only the
///    first [`MAX_CANDIDATES`] left that primary's office, dates and handles
///    reaching the subject unmarked (REQ-WIKIDATA-001's rule, applied to the
///    whole page).
/// 3. The coverage layer is told what was cut ([`declare_search_truncation`]).
fn finish_answer(
    out: &mut ModuleResult,
    seed: TargetKind,
    query: &str,
    name_matched: &[&self::types::SearchHit],
    returned: usize,
) {
    let total_name_matches = name_matched.len();
    if let Some(head) = out.entities.first_mut() {
        mark_candidate_truncation(head, query, total_name_matches);
    }
    // A label this same answer holds more than once does not identify one
    // item; see `mark_shared_labels` for what the engine's merge does with
    // that if nothing intervenes (REQ-WIKIDATA-001).
    let labels: Vec<&str> = name_matched
        .iter()
        .filter_map(|h| h.label.as_deref())
        .collect();
    mark_shared_labels(&mut out.entities, seed, &labels);
    declare_search_truncation(out, returned, total_name_matches);
}

/// Declare the answer incomplete to the coverage layer when it was cut short.
/// **Pure.** Two cuts, in order of how much they hide:
///
/// - the search page came back FULL (`returned >= SEARCH_LIMIT`): the API holds
///   more hits than it sent, any of which may carry the name, and it reports no
///   total — so this also covers a page with NO matching label, which returned
///   a clean "no such item" before, the one outcome that settles an absence;
/// - more name-matching items were on the page than [`MAX_CANDIDATES`]
///   surfaced.
///
/// The head-entity tag [`mark_candidate_truncation`] writes was the only
/// signal before, and nothing outside this file reads it.
fn declare_search_truncation(out: &mut ModuleResult, returned: usize, total_name_matches: usize) {
    if returned >= SEARCH_LIMIT {
        out.mark_truncated(
            returned,
            None,
            &format!("the search API's `limit={SEARCH_LIMIT}` page, which came back full"),
        );
    } else if total_name_matches > MAX_CANDIDATES {
        out.mark_truncated(
            MAX_CANDIDATES,
            Some(total_name_matches),
            &format!("the cap of {MAX_CANDIDATES} surfaced candidates"),
        );
    }
}

/// Signal on the primary/head entity when more items matched the seed name
/// than [`MAX_CANDIDATES`] surfaced. **Pure**. No-op when the match count is
/// within the cap.
///
/// The note names the SEARCH it describes (`query`): an evidence record's
/// identity is `(source, summary)`, and the GEXF co-occurrence edge keys on
/// it. Without the query, the note for "Ian Thorpe" and the note for "John
/// Thorpe" were the same text whenever the counts agreed, so the two
/// namesakes' head entities read as named together by one Wikidata record
/// (scan 7258fc07).
///
/// The note is an ANNOTATION ([`Evidence::as_annotation`]): it is a fact about
/// the search, not an observation of the party the head names, so it never
/// corroborates the entity it sits on — whatever order it is attached in
/// relative to `mark_ambiguous`. As a countable record it made `wikidata` a
/// corroborating source of the subject once the head fused onto the seed
/// anchor, though the only records that spoke about the party were
/// `Unverified` (see [`finish_answer`]).
fn mark_candidate_truncation(head: &mut Entity, query: &str, total_name_matches: usize) {
    if total_name_matches <= MAX_CANDIDATES {
        return;
    }
    head.tag("truncated");
    head.add_evidence(
        Evidence::new(
            SRC,
            format!(
                "Wikidata name search for '{query}' matched {total_name_matches} item(s); only {MAX_CANDIDATES} surfaced"
            ),
        )
        .with_attr("total_name_matches", total_name_matches.to_string())
        .with_attr("candidates_capped", "true")
        .as_annotation(),
    );
}
