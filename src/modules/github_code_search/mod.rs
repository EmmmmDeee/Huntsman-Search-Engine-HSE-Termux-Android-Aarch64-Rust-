//! GitHub code search — mine public repositories for email/username seeds.
//!
//! Endpoint: `GET https://api.github.com/search/code?q={seed}&per_page=100`
//! Auth:     GitHub Personal Access Token (`HUNTSMAN_GITHUB_TOKEN`, the pooled
//!           `github` key) — REQUIRED. GitHub's code search answers every
//!           unauthenticated request `401 Requires authentication` (the live
//!           sweep recorded exactly that on every keyless scan), so the module
//!           is key-gated: without a token it is a clean `MissingKey` skip, not
//!           a module error on every scan. 30 req/min with a token.
//!
//! The search page is the API maximum (100) so a single request surfaces as
//! many repositories — hence owner accounts and repo URLs — as GitHub will
//! return. The follow-up per-repo commit-email harvest hits the separate core
//! rate limit, so it is bounded to the first `COMMIT_FETCH_CAP` repositories
//! per seed to keep request volume flat regardless of the wider result page.
//!
//! MITRE ATT&CK: T1593.003 — Search: Code Repositories.
//!
//! For an Email or Username seed, searches GitHub code for literal occurrences
//! and fans out from each matching repository:
//!
//!   * Repository owner → `Username` (confirms the account hosts content
//!     matching the seed — a strong cross-correlation pivot).
//!   * Repository URL → `Url` tagged `code-repo` (for `social_location` +
//!     `exif_geo` downstream).
//!   * Commit author emails from the repo's recent commits → `Email` entities
//!     (T1589.002 — low confidence since repos can have many contributors).
//!
//! Precision gate: only repositories whose `full_name` or `description` contain
//! the search term as a substring, OR whose owner login matches a username seed
//! exactly, are fanned out at PROBABLE tier; the rest are surfaced as
//! low-confidence candidates. This avoids false-positives from incidental
//! string matches in large codebases.

use async_trait::async_trait;

use crate::core::{
    entity::EntityKind,
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

mod types;
use types::{CodeItem, CommitItem, CommitsResp, SearchResp};

mod build;
use build::{build_commit_emails, build_repo_entities};

#[cfg(test)]
mod tests;

pub(super) const SRC: &str = "github_code_search";
const API: &str = "https://api.github.com";

pub struct GithubCodeSearch;

#[async_trait]
impl Module for GithubCodeSearch {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "GitHub code search — surfaces repositories bearing the seed email/username and pivots to owner accounts and commit emails"
    }

    fn priority(&self) -> u8 {
        85
    }

    fn cost(&self) -> ModuleCost {
        // GitHub's code search is authenticated-only (401 without a token):
        // declaring it Free made the dispatcher run it keyless on every scan
        // and record a ModuleError each time (`docs/PROVIDER_SWEEP_BACKLOG.md`,
        // "Free-but-401").
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Username)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Social
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        &["T1593.003", "T1589.002"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Url,
            EntityKind::Username,
            EntityKind::Email,
            EntityKind::Person,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let seed = target.value.trim();
        if seed.is_empty() {
            return Ok(ModuleResult::new());
        }

        // `MissingKey` when unset — dispatch records a clean skip. GitHub's code
        // search cannot be queried without it (401), so there is no keyless path.
        let token = ctx.key("HUNTSMAN_GITHUB_TOKEN")?;
        // Request the API's maximum page size: the search itself is ONE request
        // regardless of `per_page`, so widening it from 10 to 100 yields up to
        // 10× more repositories — and therefore owner `Username` pivots and repo
        // URLs (all built with no extra network call by `build_repo_entities`) —
        // at zero additional search-request or rate-limit cost.
        let url = format!(
            "{API}/search/code?q={}&per_page=100",
            crate::util::http::urlencode(seed),
        );

        let req = ctx
            .http
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header(
                "X-GitHub-Api-Version",
                crate::modules::github_api::API_VERSION,
            )
            .header("User-Agent", "huntsman-search-engine/1.4")
            .bearer_auth(token);

        let resp = req.send_tagged(SRC).await?;
        let status = resp.status();
        if !status.is_success() {
            // The key pool must learn a 401/403/429 happened, or a dead or
            // throttled token silently degrades every future scan with no
            // operator-visible signal and no chance to rotate to another
            // pooled token.
            crate::util::http::note_keyed_error(status.as_u16(), "github", token, ctx);
            // 422 is GitHub's "unprocessable query" — a search term it cannot
            // index (too short, only punctuation, unsupported qualifier). Nothing
            // was searched, so nothing was found OR ruled out: a typed skip,
            // not the clean-negative empty result it used to be.
            if status.as_u16() == 422 {
                return Err(crate::core::error::Error::skipped(
                    crate::core::event::SkipClass::NotApplicable,
                    format!(
                        "GitHub cannot index this seed as a code-search query (HTTP 422: {})",
                        crate::util::http::error_snippet(resp).await
                    ),
                ));
            }
            let remaining = resp
                .headers()
                .get("x-ratelimit-remaining")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let snippet = crate::util::http::error_snippet(resp).await;
            // A throttle is the typed RateLimited: the breaker backs the module
            // off and the scan records a throttled provider — before this a
            // 403/429 was an empty result, "no code matched", on every throttled
            // scan.
            if crate::modules::github_api::throttled(
                status.as_u16(),
                remaining.as_deref(),
                &snippet,
            ) {
                return Err(crate::core::error::Error::RateLimited(format!(
                    "{SRC}: GitHub code search throttled (HTTP {status}): {snippet}"
                )));
            }
            // Any other non-2xx (a 401 on a revoked token, a 5xx outage) is a
            // real failure of the search, not "no code matched".
            return Err(crate::core::error::Error::module(
                SRC,
                format!("HTTP {status}: {snippet}"),
            ));
        }

        // Status is a validated 2xx here, so a parse failure is a malformed body
        // from a live endpoint — an outage, not an empty result set.
        let body: SearchResp = crate::util::http::json_scanned(resp, SRC).await?;

        if body.items.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let mut seen_repos: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Every discovered repo gets its owner/URL entities for free, but the
        // per-repo commit-email harvest below is a SEPARATE request against
        // GitHub's core rate limit (60/hr unauthenticated). Widening the search
        // page to 100 must not fan that out to 100 commit calls per seed and
        // exhaust the limit for the rest of the scan — so the commit harvest is
        // bounded to the first `COMMIT_FETCH_CAP` distinct repos (the most
        // relevant, since the search returns best-match order), keeping per-seed
        // request volume the same as before the page widened.
        const COMMIT_FETCH_CAP: usize = 10;
        let mut commit_fetches = 0usize;

        for item in &body.items {
            let full_name = item
                .repository
                .as_ref()
                .and_then(|r| r.full_name.as_deref())
                .unwrap_or("")
                .to_string();
            if full_name.is_empty() || !seen_repos.insert(full_name.clone()) {
                continue;
            }

            result.extend(build_repo_entities(item, seed, target.kind, &ctx.scan_id));

            // Fetch recent commits for the repo to harvest author emails.
            // Best-effort: skip on any error (rate limit, private repo). Bounded
            // to COMMIT_FETCH_CAP repos per seed to hold the core-API rate-limit
            // cost flat as the search page widened.
            if commit_fetches >= COMMIT_FETCH_CAP {
                continue;
            }
            commit_fetches += 1;
            let commits_url = format!("{API}/repos/{full_name}/commits?per_page=5");
            let creq = ctx
                .http
                .get(&commits_url)
                .header("Accept", "application/vnd.github+json")
                .header(
                    "X-GitHub-Api-Version",
                    crate::modules::github_api::API_VERSION,
                )
                .header("User-Agent", "huntsman-search-engine/1.4")
                .bearer_auth(token);
            if let Ok(cr) = creq.send_tagged(SRC).await {
                let cstatus = cr.status();
                if cstatus.as_u16() == 403 || cstatus.as_u16() == 429 {
                    // Same key-pool feedback as the primary search request above.
                    // The commit fetch hits GitHub's separate CORE rate limit, so a
                    // token exhausted here (but fine for search) would otherwise
                    // silently no-op every commit-fetch for the rest of the scan
                    // with no operator-visible signal and no chance to rotate.
                    crate::util::http::note_keyed_error(cstatus.as_u16(), "github", token, ctx);
                } else if cstatus.is_success()
                    // Capped decode (32 MiB) — a raw `bytes()` would buffer an
                    // unbounded body on the low-RAM Termux target.
                    && let Ok(arr) =
                        crate::util::http::json_decode::<Vec<CommitItem>>(SRC, cr).await
                {
                    let wrapped = CommitsResp { commits: arr };
                    result.extend(build_commit_emails(&wrapped, &full_name, &ctx.scan_id));
                }
            }
        }

        Ok(result)
    }
}
