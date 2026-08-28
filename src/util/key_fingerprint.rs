//! Provider-prefixed, non-reversible fingerprint of an API key.
//!
//! Every entity derived from a keyed request records WHICH key/origin returned
//! it — for provenance and debugging — without persisting the full secret in the
//! entity store. Each keyed provider (`util::oathnet`, `util::see_know`) exposes
//! its own one-line `key_fingerprint(key)` that fixes its label and truncation
//! widths and delegates here, so the empty/short guards and the char-safe
//! `head…tail` elision live in ONE place and cannot drift between providers (two
//! copies of this had already been written verbatim, each with its own prefix).

/// Build a `"{prefix}:{head}…{tail}"` fingerprint of `key`.
///
/// - Empty (after trimming) → `"{prefix}:(no key)"`.
/// - `key.len() <= short_max` bytes → `"{prefix}:{key}"` verbatim: a short key
///   has too little length to elide usefully, and each provider picks the width
///   below which it would rather show the whole (already low-value) token.
/// - Otherwise the first `head` and last `tail` **chars** around a `…` (U+2026),
///   so the middle of the secret is never emitted.
///
/// The short-circuit compares BYTE length while `head`/`tail` count CHARS — kept
/// verbatim from the two provider copies this unifies; for the ASCII API keys in
/// scope the two measures coincide, and the `chars()` boundaries keep it panic-
/// free on any input regardless.
#[must_use]
pub fn fingerprint(prefix: &str, key: &str, short_max: usize, head: usize, tail: usize) -> String {
    let k = key.trim();
    if k.is_empty() {
        return format!("{prefix}:(no key)");
    }
    if k.len() <= short_max {
        return format!("{prefix}:{k}");
    }
    let head_s: String = k.chars().take(head).collect();
    let tail_s: String = {
        let mut t: Vec<char> = k.chars().rev().take(tail).collect();
        t.reverse();
        t.into_iter().collect()
    };
    format!("{prefix}:{head_s}\u{2026}{tail_s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_whitespace_only_report_no_key() {
        assert_eq!(fingerprint("p", "", 12, 8, 4), "p:(no key)");
        assert_eq!(fingerprint("p", "   ", 12, 8, 4), "p:(no key)");
    }

    #[test]
    fn short_keys_pass_through_verbatim_after_trim() {
        // At or below short_max bytes: shown whole (trimmed), no elision.
        assert_eq!(fingerprint("p", "abc123", 12, 8, 4), "p:abc123");
        assert_eq!(fingerprint("p", "twelvechars0", 12, 8, 4), "p:twelvechars0"); // len == 12
        assert_eq!(fingerprint("p", "  abc123  ", 12, 8, 4), "p:abc123");
    }

    #[test]
    fn long_keys_elide_head_and_tail_around_the_ellipsis() {
        // 16 chars > short_max 12 → first 8 … last 4 (oathnet widths).
        assert_eq!(
            fingerprint("oathnet.org", "0123456789abcdef", 12, 8, 4),
            "oathnet.org:01234567\u{2026}cdef"
        );
        // Different provider widths (see-know: 18/13/6) elide differently: the
        // 23-char key keeps its first 13 and last 6 chars.
        assert_eq!(
            fingerprint("see-know", "seek-1234567890aaaabbbb", 18, 13, 6),
            "see-know:seek-12345678\u{2026}aabbbb"
        );
    }

    #[test]
    fn multibyte_key_never_splits_a_char() {
        // head/tail count chars, so a key past short_max with multibyte chars is
        // elided on char boundaries (never panics, never emits a partial code point).
        let out = fingerprint("p", "αβγδεζηθικλμν", 4, 3, 2);
        assert_eq!(out, "p:αβγ\u{2026}μν");
    }
}
