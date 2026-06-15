//! LinkedIn slug generation from a display name.
//!
//! LinkedIn slugs are lowercase ASCII with hyphens, typically
//! `firstname-lastname` or `firstname-lastname-N` for collisions.

/// Generate candidate LinkedIn URL slugs from a name string.
///
/// For a person: `"John Smith"` → `["john-smith", "johnsmith"]`
/// For an org:   `"Acme Corp"` → `["acme-corp", "acmecorp", "acme"]`
pub(super) fn generate_slugs(name: &str, is_org: bool) -> Vec<String> {
    let normalised: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' {
                c
            } else {
                ' '
            }
        })
        .collect();

    let words: Vec<&str> = normalised.split_whitespace().collect();
    if words.is_empty() {
        return Vec::new();
    }

    let mut slugs: Vec<String> = Vec::new();

    // Primary: hyphen-joined
    let hyphen = words.join("-");
    slugs.push(hyphen.clone());

    // Secondary: concatenated (no separator)
    let joined = words.join("");
    if joined != hyphen {
        slugs.push(joined);
    }

    if is_org {
        // First word alone (common for well-known brands)
        if words.len() > 1 {
            slugs.push(words[0].to_string());
        }
        // Acronym (first letter of each word)
        let acronym: String = words.iter().filter_map(|w| w.chars().next()).collect();
        if acronym.len() >= 2 {
            slugs.push(acronym);
        }
    } else if words.len() >= 2 {
        // First + Last only (skip middle names)
        let first_last = format!("{}-{}", words[0], words[words.len() - 1]);
        if first_last != hyphen {
            slugs.push(first_last);
        }
    }

    // De-duplicate preserving order
    let mut seen = std::collections::HashSet::new();
    slugs.retain(|s| seen.insert(s.clone()));
    slugs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn person_slugs() {
        let slugs = generate_slugs("John Smith", false);
        assert!(slugs.contains(&"john-smith".to_string()));
        assert!(slugs.contains(&"johnsmith".to_string()));
    }

    #[test]
    fn org_slugs() {
        let slugs = generate_slugs("Acme Corporation", true);
        assert!(slugs.contains(&"acme-corporation".to_string()));
        assert!(slugs.contains(&"acme".to_string()));
        assert!(slugs.contains(&"ac".to_string())); // acronym
    }

    #[test]
    fn empty_name() {
        assert!(generate_slugs("", false).is_empty());
    }
}
