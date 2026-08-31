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
}
