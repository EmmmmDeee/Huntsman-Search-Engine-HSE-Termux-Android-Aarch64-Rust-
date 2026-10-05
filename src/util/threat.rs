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
        && t.chars().filter(char::is_ascii_alphabetic).count() * 2 >= len
        && !t.contains(['/', '\\', ':', '|', '=', '(', ')'])
        && !t.to_ascii_lowercase().contains("hash")
        && t.split_whitespace().count() <= 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_clean_threat_tags() {
        assert!(is_meaningful_tag("malware"));
        assert!(is_meaningful_tag("ransomware"));
        assert!(is_meaningful_tag("phishing kit"));
        assert!(is_meaningful_tag("apt group"));
    }

    #[test]
    fn rejects_too_short_and_too_long() {
        assert!(!is_meaningful_tag("ab")); // 2 chars, below minimum
        assert!(!is_meaningful_tag(&"a".repeat(33))); // 33 chars, above maximum
    }

    #[test]
    fn rejects_path_punctuation() {
        assert!(!is_meaningful_tag("path/traversal"));
        assert!(!is_meaningful_tag("cmd:exec"));
        assert!(!is_meaningful_tag("key=value"));
    }

    #[test]
    fn rejects_hash_strings() {
        assert!(!is_meaningful_tag("md5hash"));
        assert!(!is_meaningful_tag("sha256_hash"));
    }

    #[test]
    fn rejects_more_than_four_words() {
        assert!(!is_meaningful_tag("one two three four five"));
    }

    #[test]
    fn rejects_non_alpha_start() {
        assert!(!is_meaningful_tag("123malware"));
        assert!(!is_meaningful_tag("_botnet"));
    }
}
