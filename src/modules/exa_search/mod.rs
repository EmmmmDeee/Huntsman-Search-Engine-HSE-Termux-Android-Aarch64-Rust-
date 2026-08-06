//! Exa AI semantic web search — finds entities by meaning, not keyword.
//!
//! <https://exa.ai> charges ~$1 per 1000 searches with neural-embedding
//! search across the web. For OSINT this is uniquely valuable because
//! it can resolve queries like:
//!
//!   "personal website of someone named `<fullname>` in Australia"
//!   "`<username>`'s most recent online activity"
//!   "`<email>` mentioned in news, forums, or paste sites"
//!   "company employees named `<fullname>`"
//!
//! These produce URL → Domain → web_crawler chain inputs that
//! traditional keyword search engines miss.
//!
//! Endpoint: POST <https://api.exa.ai/search>
//! Auth:     `x-api-key: <key>`
//! Body:     {"query": "...", "num_results": 10, "type": "neural"}
//!
//! Configure: `export HUNTSMAN_EXA_KEY=<your-key>` or `hse set-key
//! HUNTSMAN_EXA_KEY <value>`.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::extract::EMAIL_RE;

const SRC: &str = "exa_search";
const KEY_ENV: &str = "HUNTSMAN_EXA_KEY";
const BASE_URL: &str = "https://api.exa.ai/search";
const NUM_RESULTS: u32 = 10;

#[derive(Deserialize)]
struct ExaResponse {
    #[serde(default)]
    results: Vec<ExaResult>,
}

#[derive(Deserialize)]
struct ExaResult {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    score: Option<f64>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    published_date: Option<String>,
}

pub struct ExaSearch;

#[async_trait]
impl Module for ExaSearch {
    fn name(&self) -> &'static str {
        "exa_search"
    }

    fn description(&self) -> &'static str {
        "Exa AI neural search — semantic web sweep for entity discovery and lead surfacing"
    }

    fn priority(&self) -> u8 {
        // Below identity modules (hudsonrock 130 etc), above DNS modules
        // so its URL output feeds dns_intel + cert_intel + web_crawler.
        87
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::FullName
                | TargetKind::Domain
                | TargetKind::Organisation
                | TargetKind::Phone
                | TargetKind::TrackingId
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Search
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Url,
            EntityKind::Domain,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Person,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = match ctx.key_opt(KEY_ENV) {
            Some(k) if !k.is_empty() => k,
            _ => return Ok(ModuleResult::new()),
        };

        // Per-target query templates — phrased to maximise semantic match
        // recall for OSINT-relevant pages.
        let query = match target.kind {
            TargetKind::Email => {
                format!(
                    "mentions of email address {} in news, forums, social posts, or leaks",
                    target.value
                )
            }
            TargetKind::Username => {
                format!(
                    "online profiles, social posts, and bio pages for username \"{}\"",
                    target.value
                )
            }
            TargetKind::FullName => {
                format!(
                    "personal website, LinkedIn, or biographical pages about {}",
                    target.value
                )
            }
            TargetKind::Domain => {
                format!(
                    "company information, news, and ownership records for {}",
                    target.value
                )
            }
            TargetKind::Organisation => {
                format!("employees, offices, and news about {}", target.value)
            }
            TargetKind::Phone => {
                format!(
                    "online listings or directories containing phone number {}",
                    target.value
                )
            }
            TargetKind::TrackingId => {
                format!(
                    "websites embedding Google Analytics or Tag Manager ID \"{}\"",
                    target.value.to_ascii_uppercase()
                )
            }
            _ => return Ok(ModuleResult::new()),
        };

        let body = json!({
            "query": query,
            "num_results": NUM_RESULTS,
            "type": "neural",
            "use_autoprompt": true,
            "contents": { "text": { "max_characters": 1000 } }
        });

        // A transport failure to the Exa API is a real outage, not "no results
        // for this query" — propagate it instead of silently reporting an empty
        // search. (A genuine zero-hit search still arrives as a 2xx with an empty
        // `results` array, handled below.)
        let resp = ctx
            .http
            .post(BASE_URL)
            .header("x-api-key", key)
            .header("Content-Type", "application/json")
            .json(&body)
            .timeout(Duration::from_secs(15))
            .send()
            .await?;

        // 401/403/429 → note_keyed_error + Err; 404 → clean miss; other
        // non-2xx → Err via http_status_error. Previously a 500 (server error)
        // would incorrectly mark the key exhausted — fixed by this helper.
        let Some(resp) = crate::util::http::keyed_ok_or_404(SRC, key, ctx, resp).await? else {
            return Ok(ModuleResult::new());
        };

        // The status is already validated 2xx, so a JSON parse failure here is a
        // malformed body from a live endpoint (an error/HTML page behind a 200) —
        // a real outage, not an empty result set. Propagate it.
        let parsed: ExaResponse = crate::util::http::json_scanned(resp, SRC)
            .await
            .map_err(|e| crate::core::error::Error::module(SRC, e))?;

        let mut result = ModuleResult::new();
        let mut seen_domains = std::collections::HashSet::new();

        for r in parsed.results.iter().take(NUM_RESULTS as usize) {
            if r.url.is_empty() {
                continue;
            }

            // Emit the URL as its own entity — feeds web_crawler.
            let mut url_entity =
                Entity::new(EntityKind::Url, &r.url, confidence::HIGH_PLUS, &ctx.scan_id);
            url_entity.tag("exa-search");
            url_entity.tag(tags::EXTERNAL);
            let mut ev = Evidence::new(
                SRC,
                format!(
                    "Exa neural-match for {}={}",
                    target.kind.canonical_str(),
                    target.value
                ),
            );
            if let Some(title) = &r.title {
                ev = ev.with_attr("title", title);
            }
            if let Some(score) = r.score {
                ev = ev.with_attr("relevance", format!("{score:.3}"));
            }
            if let Some(date) = &r.published_date {
                ev = ev.with_attr("published", date);
            }
            if let Some(author) = &r.author {
                ev = ev.with_attr("author", author);
            }
            url_entity.add_evidence(ev);
            result.push(url_entity);

            // Author name → Person lead (multi-word names only, low confidence
            // since byline attribution is often a pen name or org).
            if let Some(author) = r
                .author
                .as_deref()
                .map(str::trim)
                .filter(|a| a.chars().count() >= 4 && a.contains(' ') && !a.contains('@'))
            {
                let mut pe = Entity::new(
                    EntityKind::Person,
                    author,
                    confidence::TENTATIVE,
                    &ctx.scan_id,
                );
                pe.tag("exa-search");
                pe.tag("byline");
                pe.tag("derived");
                pe.add_evidence(
                    Evidence::new(
                        SRC,
                        format!("Author byline from Exa result for {}", target.value),
                    )
                    .with_attr("source_url", &r.url),
                );
                result.push(pe);
            }

            // Extract the host as a Domain entity (feeds dns_intel,
            // cert_intel, web_crawler/probe_config_leaks chain).
            if let Some(host) = crate::util::url_util::host_from_url(&r.url)
                && seen_domains.insert(host.clone())
            {
                let mut d = Entity::new(EntityKind::Domain, &host, confidence::HIGH, &ctx.scan_id);
                d.tag("exa-search");
                d.tag(tags::EXTERNAL);
                d.add_evidence(
                    Evidence::new(SRC, format!("Domain from Exa result for {}", target.value))
                        .with_attr("source_url", &r.url),
                );
                result.push(d);
            }

            // Mine the snippet text for emails + phones — Exa returns up
            // to 1000 chars per result.
            if let Some(text) = &r.text {
                mine_snippet(text, &ctx.scan_id, &r.url, &mut result);
            }
        }

        Ok(result)
    }
}

/// Lightweight email + phone extraction from snippet text. Re-uses HSE's
/// existing entity emitters indirectly by producing the standard kinds.
fn mine_snippet(text: &str, scan_id: &str, source_url: &str, result: &mut ModuleResult) {
    // Email regex — same shape as web_crawler::extract_emails.
    for cap in EMAIL_RE.find_iter(text) {
        let email = cap.as_str().to_lowercase();
        let mut e = Entity::new(EntityKind::Email, &email, confidence::MEDIUM_PLUS, scan_id);
        e.tag("exa-search");
        e.tag("web-scraped");
        e.add_evidence(
            Evidence::new(SRC, "Email extracted from Exa snippet")
                .with_attr("source_url", source_url),
        );
        result.push(e);
    }
    // International phone — at least 7 digits with optional + prefix.
    for cap in PHONE_RE.find_iter(text) {
        let raw = cap.as_str();
        let digits: String = raw
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect();
        if digits.chars().filter(char::is_ascii_digit).count() < 7 {
            continue;
        }
        let mut p = Entity::new(EntityKind::Phone, &digits, confidence::MEDIUM_HIGH, scan_id);
        p.tag("exa-search");
        p.tag("web-scraped");
        p.add_evidence(
            Evidence::new(SRC, "Phone extracted from Exa snippet")
                .with_attr("source_url", source_url),
        );
        result.push(p);
    }
}

static PHONE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"\+?\d[\d\s\-().]{6,18}\d").expect("constant phone regex")
});

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
