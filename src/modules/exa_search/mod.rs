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
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};

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
        "Exa AI neural search — semantic web search for entity discovery"
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
            _ => return Ok(ModuleResult::new()),
        };

        let body = json!({
            "query": query,
            "num_results": NUM_RESULTS,
            "type": "neural",
            "use_autoprompt": true,
            "contents": { "text": { "max_characters": 1000 } }
        });

        let resp = match ctx
            .http
            .post(BASE_URL)
            .header("x-api-key", key)
            .header("Content-Type", "application/json")
            .json(&body)
            .timeout(Duration::from_secs(15))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "exa_search request failed");
                return Ok(ModuleResult::new());
            }
        };

        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            if code == 401 || code == 403 || code == 429 {
                ctx.report_key_exhausted(SRC, key, code);
            }
            return Ok(ModuleResult::new());
        }

        let parsed: ExaResponse = match crate::util::http::json_scanned(resp, SRC).await {
            Ok(v) => v,
            Err(_) => return Ok(ModuleResult::new()),
        };

        let mut result = ModuleResult::new();
        let mut seen_domains = std::collections::HashSet::new();

        for r in parsed.results.iter().take(NUM_RESULTS as usize) {
            if r.url.is_empty() {
                continue;
            }

            // Emit the URL as its own entity — feeds web_crawler.
            let mut url_entity = Entity::new(EntityKind::Url, &r.url, 0.70, &ctx.scan_id);
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

            // Extract the host as a Domain entity (feeds dns_intel,
            // cert_intel, web_crawler/probe_config_leaks chain).
            if let Some(host) = crate::util::url_util::host_from_url(&r.url)
                && seen_domains.insert(host.clone())
            {
                let mut d = Entity::new(EntityKind::Domain, &host, 0.65, &ctx.scan_id);
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
    for cap in EMAIL_RE.find_iter(text).take(5) {
        let email = cap.as_str().to_lowercase();
        let mut e = Entity::new(EntityKind::Email, &email, 0.60, scan_id);
        e.tag("exa-search");
        e.tag("web-scraped");
        e.add_evidence(
            Evidence::new(SRC, "Email extracted from Exa snippet")
                .with_attr("source_url", source_url),
        );
        result.push(e);
    }
    // International phone — at least 7 digits with optional + prefix.
    for cap in PHONE_RE.find_iter(text).take(5) {
        let raw = cap.as_str();
        let digits: String = raw
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect();
        if digits.chars().filter(|c| c.is_ascii_digit()).count() < 7 {
            continue;
        }
        let mut p = Entity::new(EntityKind::Phone, &digits, 0.55, scan_id);
        p.tag("exa-search");
        p.tag("web-scraped");
        p.add_evidence(
            Evidence::new(SRC, "Phone extracted from Exa snippet")
                .with_attr("source_url", source_url),
        );
        result.push(p);
    }
}

static EMAIL_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
});
static PHONE_RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\+?\d[\d\s\-().]{6,18}\d").unwrap());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_identity_and_org_kinds() {
        let m = ExaSearch;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::FullName,
            TargetKind::Domain,
            TargetKind::Organisation,
            TargetKind::Phone,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
        // Not for IPs, coords, ASNs.
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn cost_is_keygated() {
        assert!(matches!(ExaSearch.cost(), ModuleCost::KeyGated));
    }

    #[test]
    fn email_regex_matches_standard_addresses() {
        assert!(EMAIL_RE.is_match("contact alice@example.com please"));
        assert!(EMAIL_RE.is_match("bob.smith+tag@sub.example.co.uk"));
    }

    #[test]
    fn phone_regex_matches_intl_format() {
        assert!(PHONE_RE.is_match("+44 20 7946 0958"));
        assert!(PHONE_RE.is_match("+1-555-123-4567"));
    }
}
