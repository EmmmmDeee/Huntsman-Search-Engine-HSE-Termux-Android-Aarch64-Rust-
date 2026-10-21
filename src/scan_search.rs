//! Search over saved scans, read as Spiderfoot's search box reads it, the one matcher the
//! console's search, `scans search` and `GET /api/search` share.
//!
//! A query is `/regex/` (a [`Pattern`], matched anywhere in the value, so its time is linear in
//! the value whatever the pattern), text with `*` (the whole value, each `*` standing for any run
//! of characters, as Spiderfoot turns `*` into SQL's `%`), or plain text (anywhere in the value).
//! All three ignore case. An element matches when its data, the data of the element it was found
//! from or its module does, the three columns Spiderfoot's search reads. Spiderfoot searches
//! one scan from its scan view; here the same search runs over every saved scan too.

use std::collections::BTreeMap;

use crate::pattern::{Pattern, PatternError};
use crate::scan_store::ScanResults;
use crate::sf_elements::DataElement;

/// A parsed search.
#[derive(Debug)]
pub enum Query {
    /// `/regex/`: a regular expression anywhere in the value.
    Regex(Pattern),
    /// Text with `*`: the whole value, lowercased, split at each `*`.
    Wildcard(Vec<String>),
    /// Anything else, lowercased: the text anywhere in the value. Empty matches every value.
    Contains(String),
}

impl Query {
    /// Read a search as Spiderfoot's box does, trimmed.
    ///
    /// # Errors
    /// [`PatternError`] when a `/regex/` does not compile.
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let text = text.trim();
        if let Some(inner) = text
            .strip_prefix('/')
            .and_then(|rest| rest.strip_suffix('/'))
            .filter(|inner| !inner.is_empty())
        {
            return Pattern::new_ignore_case(inner).map(Self::Regex);
        }
        let lower = text.to_lowercase();
        if lower.contains('*') {
            return Ok(Self::Wildcard(
                lower.split('*').map(str::to_owned).collect(),
            ));
        }
        Ok(Self::Contains(lower))
    }

    /// Whether `value` matches.
    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Regex(pattern) => pattern.is_match(value),
            Self::Wildcard(parts) => glob(parts, &value.to_lowercase()),
            // Common ASCII searches need no heap allocation per candidate. Preserve the old
            // lowering semantics for Unicode and for directly constructed uppercase needles:
            // only Query::parse guarantees a pre-lowercased ASCII needle.
            Self::Contains(needle) if needle.is_empty() => true,
            Self::Contains(needle)
                if value.is_ascii()
                    && needle.is_ascii()
                    && needle.bytes().all(|byte| !byte.is_ascii_uppercase()) =>
            {
                value
                    .as_bytes()
                    .windows(needle.len())
                    .any(|candidate| candidate.eq_ignore_ascii_case(needle.as_bytes()))
            }
            Self::Contains(needle) => value.to_lowercase().contains(needle.as_str()),
        }
    }
}

/// Whether `value` is `parts` joined by runs of any characters, the first part at its start and
/// the last at its end. The leftmost place of each middle part is the one that leaves the most
/// for the rest, so one pass decides it.
fn glob(parts: &[String], value: &str) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return value.is_empty();
    };
    let Some(mut left) = value.strip_prefix(first.as_str()) else {
        return false;
    };
    let Some((last, middle)) = rest.split_last() else {
        return left.is_empty();
    };
    for part in middle {
        match left.find(part.as_str()) {
            Some(at) => left = &left[at + part.len()..],
            None => return false,
        }
    }
    left.ends_with(last.as_str())
}

/// Every element of `results` but the root that `query` matches, of `kind` when one is given
/// (any case), in the scan's order.
#[must_use]
pub fn hits<'a>(
    results: &'a ScanResults,
    query: &Query,
    kind: Option<&str>,
) -> Vec<&'a DataElement> {
    let sources: BTreeMap<&str, &str> = results
        .elements
        .iter()
        .map(|element| (element.id.as_str(), element.data.as_str()))
        .collect();
    results
        .elements
        .iter()
        .filter(|element| element.kind != "ROOT")
        .filter(|element| kind.is_none_or(|kind| element.kind.eq_ignore_ascii_case(kind)))
        .filter(|element| {
            query.matches(&element.data)
                || query.matches(&element.module)
                || element
                    .source
                    .as_deref()
                    .and_then(|source| sources.get(source))
                    .is_some_and(|data| query.matches(data))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(query: &str, value: &str) -> bool {
        Query::parse(query).unwrap().matches(value)
    }

    #[test]
    fn ascii_contains_fast_path_matches_the_original_lowercase_semantics() {
        // Exhaustively compare the former expression against the allocation-free path,
        // including boundaries, repeated prefixes, mixed case and empty values.
        let alphabet = ["a", "A", "b", "B", "1", "-", " "];
        let needles = ["", "a", "A", "b", "1", "ab", "BA", "-1", "zz", "aaa"];
        let mut samples = vec![String::new()];
        for _ in 0..4 {
            let previous = samples.clone();
            for prefix in previous {
                for letter in alphabet {
                    samples.push(format!("{prefix}{letter}"));
                }
            }
        }
        for value in &samples {
            for query in needles {
                let parsed = Query::parse(query).unwrap();
                let lowered = query.trim().to_lowercase();
                let expected = value.to_lowercase().contains(lowered.as_str());
                assert_eq!(parsed.matches(value), expected, "query={query:?}, value={value:?}");
            }
        }
    }

    #[test]
    fn unicode_and_directly_constructed_query_semantics_are_unchanged() {
        assert!(matches("ZÜRICH", "Zürich station"));
        assert!(matches("İ", "İstanbul"));
        assert!(!matches("STRASSE", "Straße"));
        assert!(Query::Contains(String::new()).matches(""));
        // Query is a public enum: callers can bypass parse and supply an uppercase needle.
        assert!(!Query::Contains("ABC".into()).matches("abc"));
    }

    #[test]
    fn a_query_reads_as_spiderfoots_box_does() {
        // Plain text anywhere, regardless of case.
        assert!(matches("Example", "mail.example.com"));
        assert!(!matches("example.org", "mail.example.com"));
        // A wildcard is the whole value.
        assert!(matches("*.example.com", "mail.EXAMPLE.com"));
        assert!(!matches("*.example.com", "mail.example.com.au"));
        assert!(matches("m*l.*.com", "mail.example.com"));
        assert!(matches("a*a", "aa"));
        assert!(!matches("aa*aa", "aaa"));
        assert!(matches("*", ""));
        // A regex anywhere, regardless of case.
        assert!(matches(r"/^10\.\d+/", "10.0.0.1"));
        assert!(matches("/CVE-20(21|22)/", "cve-2021-44228"));
        assert!(!matches(r"/^10\.\d+/", "110.0.0.1"));
        // Too short to be a regex, so the slash is the text.
        assert!(matches("//", "http://x"));
        assert!(Query::parse("/(a/").is_err());
        assert!(matches("", "anything"));
    }
}
