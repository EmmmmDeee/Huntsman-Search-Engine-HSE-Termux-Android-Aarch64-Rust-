//! Shared binding for the GitHub REST API modules — a `pub(crate)` HELPER (no
//! `Module` impl), so `github_user`, `github_code_search`, and `github_commits`
//! pin the same API version from one place. A version bump becomes a one-line
//! change here instead of a seven-site hunt in which one call is easily missed
//! and left sending a stale schema header.
//!
//! Like `breach_rich`, this stays `pub(crate)` so it is not caught by the
//! `every_declared_module_is_registered` architecture guard (which flags an
//! unregistered `pub mod` as dead-at-runtime).

/// The pinned GitHub REST API version, sent as the `X-GitHub-Api-Version`
/// header on every request so responses stay on one stable, tested schema.
pub(crate) const API_VERSION: &str = "2022-11-28";

/// A git commit-author `name` that plausibly names a real person: multi-word,
/// reasonable length, and not a `git`/CI/bot placeholder. Shared by
/// `github_commits` and `github_code_search` so both extract a `Person` from
/// a commit author under the exact same rule — one used to carry its own,
/// narrower inline copy that missed `"unknown"` / `"unknown user"` / `"your
/// name"`, letting a placeholder reach the graph as a confident-looking name.
pub(crate) fn is_real_name(name: &str) -> bool {
    const PLACEHOLDERS: &[&str] = &[
        "your name",
        "first last",
        "unknown",
        "unknown user",
        "github action",
        "github actions",
        "dependabot",
        "semantic-release-bot",
    ];
    let lower = name.to_ascii_lowercase();
    name.len() >= 3
        && name.len() <= 80
        && name.contains(' ')
        && !PLACEHOLDERS.contains(&lower.as_str())
        && !lower.ends_with("[bot]")
        && !lower.contains("bot]")
}

/// Whether a non-2xx from GitHub is a throttle — the typed `RateLimited`
/// outcome — rather than an ordinary failure. `429` always is. `403` is the
/// status GitHub uses for BOTH its primary/secondary rate limits and for plain
/// refusals (a token without the scope, an IP block), so a `403` counts only
/// when the response says so: `X-RateLimit-Remaining: 0`, or a body that names
/// the rate limit. Shared by `github_commits` and `github_code_search` so the
/// two search modules classify a throttle identically.
pub(crate) fn throttled(status: u16, ratelimit_remaining: Option<&str>, body: &str) -> bool {
    match status {
        429 => true,
        403 => {
            ratelimit_remaining.is_some_and(|v| v.trim() == "0")
                || body.to_ascii_lowercase().contains("rate limit")
        }
        _ => false,
    }
}

/// The error for a non-2xx GitHub answer, judged once for every GitHub caller:
/// a throttle ([`throttled`] — a `429`, or a `403` that names the rate limit or
/// carries `X-RateLimit-Remaining: 0`) is the typed `Error::RateLimited`, so
/// the breaker benches the module under its cooldown reason and `hse doctor`,
/// the capabilities API and the live-drift sweep read `rate-limited`; anything
/// else is `Error::Module` with the status and the redacted body snippet.
/// `github_commits` and `github_code_search` each carried a copy of this
/// judgement and `github_user`'s profile fetch carried none — its throttle was
/// a module fault (observed from the sandbox on 2026-09-15: `HTTP 403
/// Forbidden: {"message":"API rate limit exceeded for …"}`). The key-pool note
/// for a present token stays at the call site, which holds the token.
pub(crate) async fn status_error(
    module: &str,
    resp: reqwest::Response,
) -> crate::core::error::Error {
    let status = resp.status();
    let remaining = resp
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let snippet = crate::util::http::error_snippet(resp).await;
    if throttled(status.as_u16(), remaining.as_deref(), &snippet) {
        return crate::core::error::Error::RateLimited(format!(
            "{module}: GitHub throttled this client (HTTP {status}): {snippet}"
        ));
    }
    crate::core::error::Error::module(module, format!("HTTP {status}: {snippet}"))
}

#[cfg(test)]
mod tests {
    use super::is_real_name;

    #[test]
    fn is_real_name_gates_placeholders_and_bots() {
        assert!(is_real_name("Linus Torvalds"));
        assert!(is_real_name("Ada P Lovelace"));
        assert!(!is_real_name("Your Name")); // git default placeholder
        assert!(!is_real_name("Unknown User")); // GitHub API placeholder
        assert!(!is_real_name("torvalds")); // single word — likely a handle
        assert!(!is_real_name("dependabot[bot]"));
        assert!(!is_real_name("github-actions[bot]"));
        assert!(!is_real_name(""));
    }

    #[test]
    fn throttled_reads_429_always_and_403_only_when_github_names_the_limit() {
        assert!(super::throttled(429, None, ""));
        assert!(super::throttled(403, Some("0"), ""));
        assert!(super::throttled(
            403,
            None,
            r#"{"message":"API rate limit exceeded for 1.2.3.4."}"#
        ));
        assert!(super::throttled(
            403,
            None,
            r#"{"message":"You have exceeded a secondary rate limit."}"#
        ));
        // A refusal that is not a throttle stays an ordinary failure.
        assert!(!super::throttled(
            403,
            Some("4999"),
            r#"{"message":"Resource not accessible by personal access token"}"#
        ));
        assert!(!super::throttled(403, None, r#"{"message":"Forbidden"}"#));
        assert!(!super::throttled(500, Some("0"), "rate limit"));
        assert!(!super::throttled(
            401,
            None,
            r#"{"message":"Requires authentication"}"#
        ));
    }

    /// The one judgement every GitHub caller shares: GitHub's `403` throttle —
    /// the body naming the rate limit, or `X-RateLimit-Remaining: 0` — is the
    /// typed `RateLimited`; a `403` refusal and a `5xx` stay the module's
    /// fault. Observed from the sandbox on 2026-09-15 as `HTTP 403 Forbidden:
    /// {"message":"API rate limit exceeded for 35.226.34.3 …"}` on
    /// `github_user`, which typed it `Error::Module`.
    #[tokio::test]
    async fn status_error_types_githubs_403_throttle_and_keeps_a_plain_403_a_fault() {
        use crate::core::error::Error;
        let answer = |status: u16, remaining: Option<&str>, body: &str| {
            let mut b = http::Response::builder().status(status);
            if let Some(r) = remaining {
                b = b.header("x-ratelimit-remaining", r);
            }
            reqwest::Response::from(b.body(body.to_string()).expect("should succeed"))
        };
        let err = super::status_error(
            "github_user",
            answer(
                403,
                None,
                r#"{"message":"API rate limit exceeded for 203.0.113.9."}"#,
            ),
        )
        .await;
        assert!(matches!(err, Error::RateLimited(_)), "{err}");
        assert!(
            err.to_string().contains("github_user") && err.to_string().contains("403"),
            "{err}"
        );
        let err = super::status_error(
            "github_user",
            answer(403, Some("0"), r#"{"message":"Forbidden"}"#),
        )
        .await;
        assert!(matches!(err, Error::RateLimited(_)), "{err}");
        let err = super::status_error(
            "github_user",
            answer(
                403,
                Some("4999"),
                r#"{"message":"Resource not accessible by personal access token"}"#,
            ),
        )
        .await;
        assert!(matches!(err, Error::Module { .. }), "{err}");
        let err = super::status_error("github_user", answer(500, None, "Server Error")).await;
        assert!(
            matches!(err, Error::Module { .. }) && err.to_string().contains("500"),
            "{err}"
        );
    }
}
