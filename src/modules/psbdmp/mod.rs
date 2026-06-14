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
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Url];
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
        extract(&resp, term, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// Turn a psbdmp search response into entities. Pure of I/O (unit-tested).
fn extract(resp: &SearchResp, term: &str, scan_id: &str, result: &mut ModuleResult) {
    if resp.data.is_empty() {
        return;
    }
    // Mark the seed as paste-exposed so the correlator can corroborate it
    // against the other breach sources.
    let mut seen = std::collections::HashSet::new();
    result.extend(resp.data.iter().filter_map(|paste| {
        if paste.id.is_empty() || !seen.insert(paste.id.clone()) {
            return None;
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
        Some(e)
    }));
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
