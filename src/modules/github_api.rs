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
}
