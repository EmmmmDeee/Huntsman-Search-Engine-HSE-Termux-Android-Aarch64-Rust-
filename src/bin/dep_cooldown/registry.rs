//! Crates.io publish-date lookups: one HTTP GET per `(name, version)` against
//! the public API, sequential and paced per
//! [crates.io's stated crawler policy](https://crates.io/data-access) (at
//! most one request per second, a descriptive User-Agent, and the
//! provider's own `Retry-After` honored on a 429/5xx when it sends one) —
//! reusing this crate's shared `build_client()` (which already sets a
//! compliant `name/version (+repo-url)` User-Agent), `BackoffPolicy` retry
//! primitive, `read_text` (the same size-capped body read every other
//! external HTTP response in this codebase goes through), and
//! `retry_after_secs`, rather than reimplementing any of them.

use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use huntsman_search_engine::util::backoff::BackoffPolicy;

use crate::lockfile::RegistryPackage;
use crate::policy::PackagePublish;

/// Floor between successive requests — crates.io's documented crawler policy
/// asks for at most one request per second; 1.1s leaves headroom.
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(1100);

/// Retry ladder for a transient failure (429/5xx/timeout): up to 3 retries,
/// 500ms initial backoff doubling to an 8s cap, jittered so a run against a
/// large lockfile doesn't hammer crates.io in lockstep after a shared outage.
const RETRY_POLICY: BackoffPolicy = BackoffPolicy::new(4, 500, 8_000, true);

#[derive(Debug, Deserialize)]
struct VersionResponse {
    version: VersionField,
}

#[derive(Debug, Deserialize)]
struct VersionField {
    created_at: String,
}

/// One crates.io lookup that did not resolve to a usable publish date — kept
/// distinct from a [`crate::policy::Violation`] so the caller (`--strict`)
/// decides whether an unreachable registry blocks the gate or only warns,
/// matching this repo's other supply-chain gates (`cargo audit`/`cargo deny`
/// in scripts/gate.sh), which are advisory-quality and must not fail a PR on
/// a transient network hiccup.
#[derive(Debug)]
pub struct FetchError {
    pub name: String,
    pub version: String,
    pub message: String,
}

/// Look up the publish timestamp of every `(name, version)` pair, one at a
/// time with [`MIN_REQUEST_INTERVAL`] between requests. Returns the packages
/// that resolved successfully and the ones that did not, separately — a
/// partial result is still useful (report what could be verified) rather
/// than discarding everything because one lookup failed.
pub async fn fetch_publish_dates(
    client: &reqwest::Client,
    packages: &[RegistryPackage],
) -> (Vec<PackagePublish>, Vec<FetchError>) {
    let mut resolved = Vec::with_capacity(packages.len());
    let mut errors = Vec::new();

    for (i, pkg) in packages.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(MIN_REQUEST_INTERVAL).await;
        }
        match fetch_one(client, &pkg.name, &pkg.version).await {
            Ok(published_at) => resolved.push(PackagePublish {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                published_at,
            }),
            Err(message) => errors.push(FetchError {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                message,
            }),
        }
    }

    (resolved, errors)
}

/// Stable module-name tag this tool presents to the shared HTTP layer's
/// error messages and, more importantly here, `read_text`'s capped body
/// read — the same defense this codebase applies to every other body read
/// of external input (`util::http::JSON_BODY_CAP`, guarding against "a
/// hostile or misconfigured upstream returning a multi-GB payload"), so a
/// compromised registry mirror or a TLS-inspecting egress proxy can't OOM
/// this process either.
const HTTP_MODULE_TAG: &str = "dep-cooldown";

/// Parse the crates.io publish timestamp out of an already-capped-and-read
/// response body. Split from [`fetch_one`] so the JSON/timestamp parsing is
/// directly unit-testable against a fixture string, without a live request.
fn parse_publish_date(body_text: &str) -> Result<OffsetDateTime, String> {
    let body: VersionResponse = serde_json::from_str(body_text)
        .map_err(|e| format!("unparseable crates.io response body: {e}"))?;
    OffsetDateTime::parse(&body.version.created_at, &Rfc3339).map_err(|e| {
        format!(
            "unparseable publish timestamp {:?}: {e}",
            body.version.created_at
        )
    })
}

async fn fetch_one(
    client: &reqwest::Client,
    name: &str,
    version: &str,
) -> Result<OffsetDateTime, String> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}");
    let mut attempt = 0u32;
    loop {
        let resp = match client.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                if RETRY_POLICY.should_retry(attempt) {
                    tokio::time::sleep(RETRY_POLICY.delay(attempt)).await;
                    attempt += 1;
                    continue;
                }
                return Err(format!(
                    "request failed after {} attempts: {e}",
                    attempt + 1
                ));
            }
        };

        let status = resp.status();

        if status.is_success() {
            // Capped read (not a raw `resp.json()`/`resp.text()`): every other body read of
            // external input in this codebase goes through this same bound — see this
            // function's own module-tag doc comment above.
            let text = huntsman_search_engine::util::http::read_text(HTTP_MODULE_TAG, resp)
                .await
                .map_err(|e| format!("reading crates.io response body: {e}"))?;
            return parse_publish_date(&text);
        }

        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            if RETRY_POLICY.should_retry(attempt) {
                // Honor crates.io's own `Retry-After` when it sends one, rather than always
                // guessing with our own ladder; falls back to the ladder's own delay (in
                // whole seconds, floored at 1) when the header is absent or unparseable.
                let ladder_secs = (RETRY_POLICY.delay(attempt).as_millis() as u64 / 1000).max(1);
                let wait_secs = huntsman_search_engine::util::http::retry_after_secs(
                    resp.headers(),
                    ladder_secs,
                    RETRY_POLICY.max_backoff_ms / 1000,
                );
                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                attempt += 1;
                continue;
            }
            return Err(format!(
                "crates.io returned {status} after {} attempts",
                attempt + 1
            ));
        }

        // Every other non-success status (404 included: crates.io has no record of this
        // exact (name, version), so a publish date cannot be confirmed) is a deterministic
        // refusal — retrying cannot succeed differently the second time.
        return Err(format!("crates.io returned {status}"));
    }
}

#[cfg(test)]
mod tests {
    include!("registry_tests.rs");
}
