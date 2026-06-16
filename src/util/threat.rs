//! Threat-intelligence utilities shared across collection modules.

/// Returns `true` if `t` is a clean, human-readable threat category tag
/// rather than noise — hash strings, path snippets, metadata lines, and
/// single-character noise that OTX stuffs into `tags`.
///
/// Heuristic: 3–32 chars, starts with a letter, ≥50% alphabetic, at most four
/// words, and free of path/metadata punctuation or an explicit "hash" marker.
pub fn is_meaningful_tag(t: &str) -> bool {
    let len = t.len();
    (3..=32).contains(&len)
        && t.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && t.chars().filter(|c| c.is_ascii_alphabetic()).count() * 2 >= len
        && !t.contains(['/', '\\', ':', '|', '=', '(', ')'])
        && !t.to_ascii_lowercase().contains("hash")
        && t.split_whitespace().count() <= 4
}
