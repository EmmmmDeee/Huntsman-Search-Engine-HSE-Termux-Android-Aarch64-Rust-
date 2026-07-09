//! OFAC Specially Designated Nationals (SDN) sanctions screening — keyless.
//!
//! A `FullName`/`Organisation` target → whether the U.S. Treasury's Office of
//! Foreign Assets Control has that name on its sanctions list, with the
//! sanctions program and remarks (often carrying DOB/POB/aliases/passport
//! numbers for individuals). The highest-signal due-diligence register a
//! lawful OSINT tool can query: a sanctions hit is precisely the kind of
//! adverse finding `asic_banned_orgs`/`asic_persons` already surface for
//! Australia, extended here to a global, official U.S. government list.
//!
//! # Data source
//! `GET https://sanctionslistservice.ofac.treas.gov/api/download/SDN.CSV` —
//! OFAC's Sanctions List Service. No auth, no API key, no published rate
//! limit; bulk/automated download is the OFFICIAL intended use (Treasury
//! recommends pulling the whole file and refreshing wholesale, not polling
//! per query). A U.S. federal government work — not subject to domestic
//! copyright (17 U.S.C. §105) — published specifically for third-party
//! compliance/screening tools to consume programmatically. The endpoint
//! redirects (302) to a time-limited, pre-signed S3 URL; the shared HTTP
//! client follows redirects automatically (see `util::http::ssrf`), so no
//! special handling is needed here.
//!
//! There is no per-name search API, unlike the CKAN-backed AU registers
//! (`asic_persons`/`asic_banned_orgs`), so the whole file is downloaded once
//! and cached in-process ([`CACHE`]), then matched against locally per query
//! — see [`parse`] for the CSV format and [`SdnKind`] classification.
//!
//! # Misattribution risk (deliberately mitigated, not left implicit)
//! OFAC's list is dominated by common transliterated names, so a bare name
//! match against a global, several-thousand-row list carries a real
//! false-positive risk — wrongly implying a person is sanctioned is a serious
//! harm. Mitigations:
//!   1. Confidence is **0.50** — deliberately BELOW the 0.60 the AU registers
//!      use for an equivalent single-source adverse-register hit
//!      (`asic_persons`/`asic_banned_orgs`), because this source's collision
//!      risk is objectively higher (a global name pool vs. a national
//!      register) — a bare hit here must read as a weaker lead, not an
//!      equally-confident one.
//!   2. Every hit's evidence carries an explicit `caution` attribute telling
//!      the operator to verify identity (DOB/nationality/passport in
//!      `Remarks`) before treating it as confirmed.
//!   3. Entities are tagged `needs-identity-verification` in addition to
//!      `sanctions`/`ofac`/`regulatory-action`, so any downstream UI/report
//!      can visually flag "unconfirmed" rather than "confirmed sanctioned".
//!   4. Name matching requires ALL tokens of length >= 3 present
//!      (`parse::name_tokens`/`parse::record_name_matches`) — stricter than
//!      the AU registers' >= 2-character floor, to reduce spurious
//!      single-token collisions on a global name pool.
//!
//! `Vessel`/`Aircraft`-typed rows are not emitted as entities at all — HSE
//! has no matching `EntityKind`, and mapping a ship/plane to `Person` or
//! `Organisation` would misrepresent it.

use std::sync::{LazyLock, RwLock};
use std::time::Instant;

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, UA_BROWSER, read_text};

mod parse;
use parse::{SdnKind, SdnRecord, humanise_name, name_tokens, parse_sdn_csv, record_name_matches};

const SRC: &str = "sanctions_ofac";
const SDN_URL: &str = "https://sanctionslistservice.ofac.treas.gov/api/download/SDN.CSV";

/// How long the in-process parsed-list cache is trusted before a re-download.
/// OFAC updates the SDN list irregularly (typically at most a few times a
/// week), so a half-day TTL is generous headroom against staleness while
/// avoiding a multi-thousand-row re-fetch on every query. This is the
/// module's OWN raw-list cache — distinct from the engine's persisted
/// per-(module, target) entity cache (`ModuleContext`/`cache_ttl_secs`),
/// which caches the mapped *entities* for one exact target, not the shared
/// underlying list every target query filters.
const LIST_CACHE_TTL_SECS: u64 = 12 * 60 * 60;

/// Confidence for a bare, single-source name-hit — see the module doc's
/// misattribution-risk section for why this is deliberately below the AU
/// registers' 0.60 precedent.
const HIT_CONFIDENCE: f64 = 0.50;
// Compile-time pin: a careless future edit must not silently raise this back
// to (or above) the AU registers' 0.60 without revisiting the rationale above.
const _: () = assert!(HIT_CONFIDENCE < 0.60);

/// Cap on emitted hits per query — a very common name could match dozens of
/// distinct SDN entries; beyond this it reads as noise rather than a lead
/// (mirrors the bounded-emission discipline used throughout this codebase,
/// e.g. `web_crawler`'s `CONTACT_DUMP_LIMIT`).
const MAX_HITS: usize = 20;

/// Timestamp + the parsed list it was fetched with.
type SdnCache = Option<(Instant, Vec<SdnRecord>)>;

/// Process-global cache of the parsed SDN list, refreshed at most once per
/// [`LIST_CACHE_TTL_SECS`]. `Instant`-keyed (monotonic, no wall-clock skew
/// concerns) — same `LazyLock<RwLock<Option<T>>>` shape as
/// `search_engines::health`'s liveness-sweep cache.
static CACHE: LazyLock<RwLock<SdnCache>> = LazyLock::new(|| RwLock::new(None));

async fn fetch_sdn_list(ctx: &ModuleContext) -> Vec<SdnRecord> {
    if let Ok(guard) = CACHE.read()
        && let Some((fetched_at, records)) = guard.as_ref()
        && fetched_at.elapsed().as_secs() < LIST_CACHE_TTL_SECS
    {
        return records.clone();
    }

    let Ok(resp) = ctx
        .http
        .get(SDN_URL)
        .header("User-Agent", UA_BROWSER)
        .send_tagged(SRC)
        .await
    else {
        // A network failure degrades to the previous cached list (even if
        // stale) rather than an empty result, so a transient outage doesn't
        // silently blind sanctions screening for the rest of this TTL window.
        return CACHE
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|(_, r)| r.clone()))
            .unwrap_or_default();
    };
    if !resp.status().is_success() {
        return CACHE
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|(_, r)| r.clone()))
            .unwrap_or_default();
    }
    let Ok(body) = read_text(SRC, resp).await else {
        return CACHE
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|(_, r)| r.clone()))
            .unwrap_or_default();
    };

    let records = parse_sdn_csv(&body);
    if let Ok(mut w) = CACHE.write() {
        *w = Some((Instant::now(), records.clone()));
    }
    records
}

/// Map one matched SDN record to its entity, if its kind has a matching
/// `EntityKind` — `Vessel`/`Aircraft` rows return `None` (see module doc).
/// **Pure** — no network/IO.
fn build_entity(rec: &SdnRecord, scan_id: &str) -> Option<Entity> {
    let (kind, display_name) = match rec.kind {
        SdnKind::Individual => (EntityKind::Person, humanise_name(&rec.name)),
        SdnKind::Organisation => (EntityKind::Organisation, rec.name.clone()),
        SdnKind::Vessel | SdnKind::Aircraft => return None,
    };
    if display_name.trim().is_empty() {
        return None;
    }

    let mut e = Entity::new(kind, &display_name, HIT_CONFIDENCE, scan_id);
    e.tag("sanctions");
    e.tag("ofac");
    e.tag("regulatory-action");
    e.tag("needs-identity-verification");

    let mut ev = Evidence::new(SRC, format!("OFAC SDN list match: {display_name}"))
        .with_attr("register", "OFAC Specially Designated Nationals (SDN) List")
        .with_attr("ent_num", rec.ent_num.to_string())
        .with_attr(
            "caution",
            "Name-only match against a global sanctions list — verify identity \
             (DOB, nationality, passport/ID) via the remarks before treating this \
             as a confirmed match; common transliterated names collide.",
        );
    if !rec.program.is_empty() {
        ev = ev.with_attr("program", &rec.program);
    }
    if !rec.remarks.is_empty() {
        ev = ev.with_attr("remarks", &rec.remarks);
    }
    e.add_evidence(ev);
    Some(e)
}

pub struct SanctionsOfac;

#[async_trait]
impl Module for SanctionsOfac {
    fn name(&self) -> &'static str {
        "sanctions_ofac"
    }

    fn description(&self) -> &'static str {
        "OFAC Specially Designated Nationals sanctions list (keyless) — name → sanctions hit, program, remarks"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): a global authoritative
        // register, alongside gleif_lei (111) rather than the AU-specific
        // registers (112-118) — both are global/cross-jurisdiction sources.
        111
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Corporate
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // A government adverse-finding register on a person/organisation —
        // T1591.002 Business Relationships (for the org side) and identifying
        // roles/associations for the person side.
        &["T1591.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Organisation];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // A cold cache means a multi-MB download; a warm cache is instant.
        20_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let name = target.value.trim();
        let tokens = name_tokens(name);
        if tokens.len() < 2 {
            // A single-token query against a global list is far too weak a
            // discriminator (see the module doc's misattribution-risk note).
            return Ok(result);
        }

        let records = fetch_sdn_list(ctx).await;
        for rec in records
            .iter()
            .filter(|r| record_name_matches(&r.name, &tokens))
            .take(MAX_HITS)
        {
            if let Some(e) = build_entity(rec, &ctx.scan_id) {
                result.push(e);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
