//! psbdmp.ws paste-dump search — free, no-credential exposure lookup.
//!
//! psbdmp.ws indexes public Pastebin (and similar) dumps. Searching an email,
//! username, or domain returns the paste IDs it appears in, with dates — a free
//! corroboration of public exposure that feeds the multi-source breach
//! correlator alongside the keyed `intelx`/`leakix` and the free `hudsonrock`/
//! `xposed_or_not`, with no API key.
//!
//! Endpoint: `https://psbdmp.ws/api/v3/search/<term>` →
//! `{ "count": N, "data": [ { "id": "...", "date": "...", "tags": "..." }, … ] }`.
//! Each `id` maps to `https://pastebin.com/<id>` — emitted as a `Url` the
//! `web_crawler` can then fetch and re-scan.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json, urlencode};

const SRC: &str = "psbdmp";

pub struct Psbdmp;

#[derive(Deserialize, Default)]
#[serde(default)]
struct SearchResp {
    count: u64,
    data: Vec<Paste>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Paste {
    id: String,
    date: String,
    tags: String,
}

#[async_trait]
impl Module for Psbdmp {
    fn name(&self) -> &'static str {
        "psbdmp"
    }

    fn description(&self) -> &'static str {
        "psbdmp.ws paste-dump exposure search (email/username/domain → pastes)"
    }

    fn priority(&self) -> u8 {
        // Breach/exposure tier, just under the free breach lookups.
        125
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::Domain
        )
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn max_timeout_ms(&self) -> u64 {
        // Live scan: psbdmp.ws averaged 14.8 s dispatch-to-done at 0/152 ok
        // (consistently unreachable from DC IPs). The API is a single fetch;
        // 6 s is enough for a healthy response and fails fast from DC.
        6_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        // The paste `Url`s, plus the SEED identity re-emitted as paste-exposed so
        // the exposure attaches to the subject's own email/username/domain entity.
        const KINDS: &[EntityKind] = &[
            EntityKind::Url,
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let term = target.value.trim();
        // Too-short terms produce noisy, non-specific paste matches.
        if term.len() < 4 {
            return Ok(result);
        }
        let url = format!("https://psbdmp.ws/api/v3/search/{}", urlencode(term));
        let resp: SearchResp = match fetch_json(&ctx.http, SRC, &url).await {
            Ok(r) => r,
            Err(_) => return Ok(result),
        };
        extract(&resp, term, target.kind, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// The identity [`EntityKind`] for a paste-exposed seed of the given target kind.
/// [`Psbdmp::accepts`] only admits these three, so a real seed always maps; the
/// `None` arm is a defensive fallback that simply skips the seed-identity emission.
fn seed_entity_kind(kind: TargetKind) -> Option<EntityKind> {
    match kind {
        TargetKind::Email => Some(EntityKind::Email),
        TargetKind::Username => Some(EntityKind::Username),
        TargetKind::Domain => Some(EntityKind::Domain),
        _ => None,
    }
}

/// Turn a psbdmp search response into entities. Pure of I/O (unit-tested).
///
/// Emits one `Url` per distinct paste (tagged [`tags::PASTE_EXPOSED`]) AND — the
/// piece the Url-only emission left implicit — the SEED IDENTITY itself
/// (email/username/domain), tagged paste-exposed + breach and carrying the paste
/// count and earliest paste date. Because entities merge by value, that seed
/// entity folds into the target, so the subject's own record shows the exposure
/// and its temporal anchor and identity-level breach correlation can see it — not
/// just the orphan paste URLs AU-043 counts. The module doc-comment's "marks the
/// seed as paste-exposed" promise is now actually fulfilled.
fn extract(
    resp: &SearchResp,
    term: &str,
    kind: TargetKind,
    scan_id: &str,
    result: &mut ModuleResult,
) {
    if resp.data.is_empty() {
        return;
    }
    let mut seen = std::collections::HashSet::new();
    // Earliest paste date by lexical min over the API's `YYYY-MM-DD …` strings —
    // deterministic, no clock; lexical order is chronological for that ISO form.
    let mut earliest: Option<&str> = None;
    for paste in &resp.data {
        if paste.id.is_empty() || !seen.insert(paste.id.as_str()) {
            continue;
        }
        if !paste.date.is_empty() {
            earliest = Some(earliest.map_or(paste.date.as_str(), |e| e.min(paste.date.as_str())));
        }
        let url = format!("https://pastebin.com/{}", paste.id);
        let ev = [
            (
                "date",
                (!paste.date.is_empty()).then_some(paste.date.as_str()),
            ),
            (
                "tags",
                (!paste.tags.is_empty()).then_some(paste.tags.as_str()),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(
            Evidence::new(SRC, format!("{term} found in paste {}", paste.id))
                .with_attr("paste_id", &paste.id)
                .with_attr("search_term", term),
            |ev, (key, v)| ev.with_attr(key, v),
        );
        let mut e = Entity::new(EntityKind::Url, &url, 0.55, scan_id);
        e.tag(SRC);
        e.tag(tags::PASTE_EXPOSED);
        e.add_evidence(ev);
        result.push(e);
    }

    let paste_count = seen.len();
    if paste_count == 0 {
        return;
    }
    // The seed identity itself, re-emitted paste-exposed so the exposure attaches
    // to the subject (merges by value into the target entity), carrying the count
    // and the temporal anchor that the Url-only emission discarded.
    if let Some(seed_kind) = seed_entity_kind(kind) {
        let summary = match earliest {
            Some(d) => format!("{term} appears in {paste_count} public paste(s); earliest {d}"),
            None => format!("{term} appears in {paste_count} public paste(s)"),
        };
        let mut ev = Evidence::new(SRC, summary)
            .with_attr("search_term", term)
            .with_attr("paste_count", paste_count.to_string());
        if let Some(d) = earliest {
            ev = ev.with_attr("earliest_paste", d);
        }
        let mut seed = Entity::new(seed_kind, term, 0.55, scan_id);
        seed.tag(SRC);
        seed.tag(tags::PASTE_EXPOSED);
        seed.tag(tags::BREACH);
        seed.add_evidence(ev);
        result.push(seed);
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
