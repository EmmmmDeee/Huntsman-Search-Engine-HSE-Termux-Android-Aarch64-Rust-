//! `util::scan` — cached multi-pattern literal matching on `aho-corasick`.
//!
//! The single home for "does this untrusted text contain any of these N
//! patterns?" (and leftmost-find) scanning. One compiled automaton replaces an
//! N-way `patterns.iter().any(|p| hay.contains(p))` linear scan with a single
//! Teddy/SIMD pass, and centralises the bounded, boundary-safe-byte discipline
//! (PROBLEM_TREE §3.F F.1 / SOLUTION_TREE SOL-F1). Build a [`MatchSet`] once —
//! ideally in a `LazyLock` next to the pattern table it scans — and query it many
//! times. Matching against `&str` always yields `&str`-boundary offsets because
//! the patterns are matched against the original bytes (no `to_lowercase()`
//! offset-on-a-copy — the T0 panic class can't recur here).

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// A compiled set of literal patterns for fast "contains any" / leftmost-find
/// scanning over untrusted text.
pub struct MatchSet {
    ac: AhoCorasick,
}

impl MatchSet {
    /// Build a case-sensitive matcher over `patterns`. Like the cached
    /// `Regex::new`s, the build is infallible for the static pattern lists we
    /// pass (constructed once at startup), so an internal build error `expect`s.
    pub fn new<I, P>(patterns: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        Self::build(patterns, false)
    }

    /// Build an ASCII-case-insensitive matcher: ASCII `A-Z`/`a-z` fold, every
    /// other byte (incl. all multibyte UTF-8) is matched literally — so it never
    /// mis-folds or panics on non-ASCII input.
    pub fn new_ascii_ci<I, P>(patterns: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        Self::build(patterns, true)
    }

    fn build<I, P>(patterns: I, ascii_ci: bool) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        let ac = AhoCorasickBuilder::new()
            // Leftmost-longest = the intuitive "earliest start, then longest"
            // match a hand-rolled `.find()` priority scan expects.
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(ascii_ci)
            .build(patterns)
            .expect("util::scan::MatchSet: aho-corasick build over static patterns");
        Self { ac }
    }

    /// Does `haystack` contain at least one pattern? One Teddy/SIMD pass,
    /// equivalent to `patterns.iter().any(|p| haystack.contains(p))`.
    #[must_use]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.ac.is_match(haystack)
    }

    /// Byte offset of the start of the leftmost(-longest) match, or `None`. The
    /// offset is a real `&str` boundary (patterns match the original bytes), so
    /// `&haystack[offset..]` is always safe.
    #[must_use]
    pub fn find(&self, haystack: &str) -> Option<usize> {
        self.ac.find(haystack).map(|m| m.start())
    }

    /// Byte range `[start, end)` of the leftmost(-longest) match, or `None`.
    /// Both offsets are valid `&str` boundaries (patterns match original bytes).
    /// `&haystack[start..]` covers the match and everything that follows;
    /// `&haystack[end..]` is the text immediately after the match — use `end`
    /// to skip past a matched marker without knowing its length in advance.
    #[must_use]
    pub fn find_range(&self, haystack: &str) -> Option<(usize, usize)> {
        self.ac.find(haystack).map(|m| (m.start(), m.end()))
    }

    /// Zero-based index of the matched pattern in the slice supplied to
    /// `new` / `new_ascii_ci`, or `None` when no pattern is found.
    /// Complements [`Self::find`] for callers that need to dispatch on *which*
    /// pattern matched rather than *where* it matched — e.g. looking up the
    /// associated value in a parallel table without a second linear scan.
    #[must_use]
    pub fn find_id(&self, haystack: &str) -> Option<usize> {
        self.ac.find(haystack).map(|m| m.pattern().as_usize())
    }
}

/// A compiled set of literal prefix patterns for fast "which prefix does this
/// string start with?" lookups. Backed by aho-corasick with
/// [`MatchKind::LeftmostFirst`] so that declaration order is preserved: when
/// multiple patterns anchor at position 0, the one declared first is returned.
/// Build once (typically in a `std::sync::LazyLock`) and query many times.
pub struct PrefixMatcher {
    ac: AhoCorasick,
}

impl PrefixMatcher {
    /// Build a case-sensitive prefix matcher over `patterns`. Build is
    /// infallible for the static pattern tables we use; an error panics.
    pub fn new<I, P>(patterns: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("util::scan::PrefixMatcher: aho-corasick build over static patterns");
        Self { ac }
    }

    /// Returns the index of the first-declared pattern whose text appears at
    /// byte offset 0 of `haystack`, or `None` if no pattern anchors to the
    /// start. When two patterns both match at offset 0, the one with the
    /// lower index (declared first) wins — preserving specific-before-generic
    /// table order without a full O(N) scan.
    #[must_use]
    pub fn find_prefix(&self, haystack: &str) -> Option<usize> {
        self.ac
            .find(haystack.as_bytes())
            .filter(|m| m.start() == 0)
            .map(|m| m.pattern().as_usize())
    }
}

#[cfg(test)]
mod tests {
    use super::MatchSet;

    #[test]
    fn is_match_equals_contains_any() {
        let m = MatchSet::new(["datadome", "perimeterx", "hcaptcha.com"]);
        assert!(m.is_match("…blah datadome blah…"));
        assert!(m.is_match("x hcaptcha.com y"));
        assert!(!m.is_match("nothing matches here"));
        assert!(!m.is_match(""));
    }

    #[test]
    fn find_returns_leftmost_boundary_safe_offset() {
        let m = MatchSet::new(["world", "xyz"]);
        let hay = "héllo world"; // 'é' is 2 bytes → "world" sits past a multibyte char
        let off = m.find(hay).expect("match");
        assert_eq!(&hay[off..off + 5], "world");
        let _ = &hay[off..]; // offset is a valid &str boundary — never panics
        assert_eq!(m.find("no match"), None);
    }

    #[test]
    fn leftmost_longest_prefers_earliest_then_longest() {
        let m = MatchSet::new(["ab", "abcd"]);
        // Both start at 0; longest ("abcd") wins → end offset proves it.
        assert_eq!(m.find("abcdef"), Some(0));
        assert!(m.is_match("zzab"));
    }

    #[test]
    fn ascii_case_insensitive_folds_only_ascii() {
        let m = MatchSet::new_ascii_ci(["datadome"]);
        assert!(m.is_match("DataDome blocked"));
        assert!(m.is_match("DATADOME"));
        // A non-ASCII char is matched literally — fullwidth 'Ｄ' is not ASCII 'd'.
        assert!(!m.is_match("Ｄatadome"));
    }

    #[test]
    fn never_panics_on_multibyte_or_control_input() {
        let m = MatchSet::new_ascii_ci(["key", "secret"]);
        // Untrusted-text contract: multibyte + NUL/control bytes never panic.
        assert!(m.is_match("café résumé 日本語 \u{0}\u{7f} secret here"));
        let _ = m.find("ключ \u{1} key 🔑");
        let _ = m.is_match("");
    }

    #[test]
    fn find_range_returns_boundary_safe_start_and_end() {
        let m = MatchSet::new_ascii_ci(["enrolled in ", "enrolled for "]);
        let hay = "You are enrolled for Sydney NSW";
        let (start, end) = m.find_range(hay).expect("match");
        assert_eq!(&hay[start..end], "enrolled for ");
        assert_eq!(&hay[end..], "Sydney NSW");
        assert_eq!(m.find_range("no match here"), None);
    }

    #[test]
    fn find_id_returns_pattern_index() {
        let m =
            MatchSet::new_ascii_ci(["northern territory", "south australia", "western australia"]);
        // "south australia" is index 1; case-insensitive
        assert_eq!(m.find_id("somewhere in South Australia"), Some(1));
        // "western australia" is index 2
        assert_eq!(m.find_id("Perth WA, Western Australia"), Some(2));
        assert_eq!(m.find_id("nowhere"), None);
    }
}
