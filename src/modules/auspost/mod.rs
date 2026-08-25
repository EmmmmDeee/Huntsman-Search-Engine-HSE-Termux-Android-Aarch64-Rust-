//! Australia Post postcode/locality lookup — an authoritative government
//! postal registry, keyed.
//!
//! Ported from the sibling `Huntsman-` repository during consolidation. The
//! parsing judgement — combining `locality`/`state`/`postcode` into one
//! human-readable place marker and deduplicating case-insensitively across
//! the localities a query returns — is the part worth carrying over
//! verbatim; the trait wrapper is rewritten against this crate's `Module`
//! contract (`accepts`/`process`/`produces`/`cost`), which the source
//! repository's simpler `is_enabled`/`execute` shape has no equivalent of.
//!
//! # What it does
//!
//! The source module gates on `EntityType::Geolocation` — confirmed (against
//! the source repository's own model and several of its other modules, e.g.
//! `ipinfo`/`wigle`, which populate that type with literal `"lat,lon"`
//! strings such as `"38.0088,-122.1175"`) to be the source repository's exact
//! analogue of this crate's [`TargetKind::Coordinates`] / [`EntityKind::Coordinates`],
//! **not** a free-text place-name type. This is a direct 1:1 mapping, not a
//! missing-kind substitution.
//!
//! So: given a `Coordinates` target, this module sends the target's literal
//! value as the AusPost `/postcode/search.json?q=` query string and, for
//! every locality match, emits ONE combined `"Locality State Postcode"`
//! [`EntityKind::Address`] entity — a place descriptor corroborated by
//! Australia's national postal registry.
//!
//! **Preserved faithfully, not fixed:** sending a raw `"lat,lon"` string as a
//! postcode/suburb-name search query is an odd shape for that endpoint — it
//! is very unlikely to be what AusPost's fuzzy locality search actually
//! matches against. This is the source module's own design (it takes
//! whatever string reached it as `input` and forwards it verbatim), carried
//! over unchanged rather than redesigned into a real reverse-geocode; see
//! `self_check_notes` in the port record.
//!
//! What it deliberately does NOT do:
//!
//! * **No coordinates are emitted.** AusPost's postcode-search endpoint
//!   returns locality/state/postcode text only — no lat/lon field — so this
//!   module never mints a `Coordinates` entity from the response, matching
//!   the source module's own test assertion that a `Geolocation` entity is
//!   never produced. The output kind is [`EntityKind::Address`] — this
//!   crate's own `geocode` module already establishes exactly this
//!   `Coordinates → Address` pairing for a reverse-lookup place descriptor,
//!   which is the closest existing fit (this crate has no generic
//!   `Metadata` catch-all the way the source repository does).
//! * **No cap on locality count.** AusPost's own endpoint already bounds how
//!   many localities it returns for one query (a handful, for an ambiguous
//!   postcode/suburb name), so no additional client-side cap is applied
//!   here — unlike, say, `bitcoin`'s `MAX_COSPEND_ADDRESSES`.
//!
//! Requires an AusPost Developer Centre API key
//! (<https://developers.auspost.com.au>), sent as the `AUTH-KEY` header —
//! this module is [`ModuleCost::KeyGated`] and produces nothing without one.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "auspost";

/// Env var carrying the AusPost Developer Centre API key, sent as the
/// `AUTH-KEY` header. Named to match the source repository's
/// `HUNTSMAN_AUSPOST_KEY` so an operator's existing key-file entry keeps
/// working unchanged after this port.
const ENV_AUSPOST_KEY: &str = "HUNTSMAN_AUSPOST_KEY";

/// Confidence for an AusPost-verified locality/state/postcode marker — an
/// authoritative government postal registry. Carried over unchanged from the
/// source module's calibration (`ADDRESS_CONFIDENCE = 0.85`).
const ADDRESS_CONFIDENCE: f64 = confidence::HIGH_PLUSPLUS_PLUS;

#[derive(Debug, Default, Deserialize)]
pub(super) struct AusPostAddress {
    #[serde(default)]
    pub(super) locality: Option<String>,
    #[serde(default)]
    pub(super) postcode: Option<String>,
    #[serde(default)]
    pub(super) state: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AusPostResponse {
    #[serde(default)]
    pub(super) localities: Vec<AusPostAddress>,
}

/// Project the postcode-search response onto entities.
///
/// Pure, network-free, deterministic and deduplicated: all parsing judgement
/// lives here so it is tested directly against captured responses rather
/// than through `process`.
///
/// For each locality, `locality`/`state`/`postcode` are trimmed, filtered for
/// emptiness, and joined with a space into one combined marker (e.g.
/// `"Melbourne VIC 3000"`); a locality contributing no non-empty component is
/// skipped entirely rather than emitting a blank/partial entity. Dedup is
/// **case-insensitive** on the combined string — mirroring the source
/// module's `push_deduped` dedup key (`value.to_lowercase()`), so two
/// localities differing only by case describe the same place and collapse to
/// one entity. This is the opposite judgement from `bitcoin`'s deliberately
/// case-SENSITIVE base58 dedup: there, case is data; here, it is not.
pub(super) fn build_entities(resp: &AusPostResponse, scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for address in &resp.localities {
        let parts: Vec<&str> = [
            address.locality.as_deref(),
            address.state.as_deref(),
            address.postcode.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

        if parts.is_empty() {
            continue;
        }
        let combined = parts.join(" ");

        // Case-insensitive dedup key — see the function doc comment.
        if !seen.insert(combined.to_lowercase()) {
            continue;
        }

        let mut e = Entity::new(EntityKind::Address, &combined, ADDRESS_CONFIDENCE, scan_id);
        e.tag("auspost");
        e.tag("postal-registry");

        let mut ev = Evidence::new(
            SRC,
            format!("Australia Post locality match: \"{combined}\""),
        );
        // A plain `fn` item (not a closure) so each call below infers its own
        // borrow lifetime independently — a closure bound to `non_empty` would
        // be pinned to a single concrete lifetime and reject the second/third
        // call site, since `locality`/`state`/`postcode` are distinct borrows.
        fn non_empty(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|s| !s.is_empty())
        }
        if let Some(loc) = non_empty(address.locality.as_deref()) {
            ev = ev.with_attr("locality", loc);
        }
        if let Some(st) = non_empty(address.state.as_deref()) {
            ev = ev.with_attr("state", st);
        }
        if let Some(pc) = non_empty(address.postcode.as_deref()) {
            ev = ev.with_attr("postcode", pc);
        }
        e.add_evidence(ev);

        out.push(e);
    }
    out
}

/// Australia Post postcode/locality lookup — see the module docs for what is
/// (and is not) modelled from the upstream response.
pub struct AusPost;

impl AusPost {
    /// Whether this module can act on a value. An empty value can never
    /// match anything, so it is declined up front rather than sent upstream
    /// as an empty query parameter.
    fn handles_value(value: &str) -> bool {
        !value.trim().is_empty()
    }
}

#[async_trait]
impl Module for AusPost {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Australia Post postcode/locality lookup (keyed) — resolves a coordinate query to its matched locality/state/postcode via the national postal registry"
    }

    fn priority(&self) -> u8 {
        48
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Coordinates) && Self::handles_value(&t.value)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Geo
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Address];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let query = target.value.trim();
        if !Self::handles_value(query) {
            return Ok(ModuleResult::new());
        }

        // `query` is the target's literal Coordinates value (e.g.
        // "38.0088,-122.1175"), forwarded verbatim as the search string — see
        // the module docs on why this is preserved as-is from the source
        // module rather than rewritten into a real reverse-geocode.
        let url = format!(
            "https://digitalapi.auspost.com.au/postcode/search.json?q={}",
            crate::util::http::urlencode(query)
        );

        let Some(resp) = crate::util::http::fetch_keyed_json::<AusPostResponse>(
            ctx,
            SRC,
            &url,
            ENV_AUSPOST_KEY,
            "AUTH-KEY",
        )
        .await?
        else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(&resp, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
