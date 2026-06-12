/// A trimmed, non-empty borrow of an optional string field, else `None`.
/// Whitespace-only is treated as absent. Single definition so the many OSINT
/// modules that surface "the value if the upstream actually sent one" share
/// identical semantics instead of each re-deriving them.
///
/// ```
/// use huntsman_search_engine::util::str_util::nonempty;
///
/// assert_eq!(nonempty(&Some("  hi ".to_string())), Some("hi")); // trimmed
/// assert_eq!(nonempty(&Some("   ".to_string())), None);          // blank → absent
/// assert_eq!(nonempty(&None), None);
/// ```
#[must_use]
pub fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// The ASCII digits of `s`, in order, with every other character dropped.
/// One definition of "keep only the digits" for phone / ABN / ACN / LEI
/// normalisation (was re-derived inline in ~9 places).
///
/// ```
/// use huntsman_search_engine::util::str_util::ascii_digits;
///
/// assert_eq!(ascii_digits("+61 (2) 9374-4000"), "61293744000");
/// assert_eq!(ascii_digits("no digits here"), "");
/// ```
#[must_use]
pub fn ascii_digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Borrow the longest prefix of `s` that is at most `max` bytes and ends on a
/// UTF-8 character boundary. Zero-copy — caps oversized fields (key fragments,
/// scraped summaries) without ever risking the panic of a raw `&s[..max]`.
///
/// # Guarantees
/// - **Prefix:** `s.starts_with(truncate_safe(s, max))`.
/// - **Bounded:** `truncate_safe(s, max).len() <= max`.
/// - **Lossless when it fits:** if `s.len() <= max`, the whole of `s` is
///   returned.
/// - **Never splits a code point**, so the result is always valid UTF-8;
///   **total** — never panics, for any `s` and any `max` (including `0`).
///
/// ```
/// use huntsman_search_engine::util::str_util::truncate_safe;
///
/// assert_eq!(truncate_safe("hello", 3), "hel");    // ASCII exact cut
/// assert_eq!(truncate_safe("hello", 99), "hello"); // fits → whole string
/// assert_eq!(truncate_safe("", 0), "");
/// // `max` lands inside the 2-byte 'é' (bytes 1..3) → backs off to "a".
/// assert_eq!(truncate_safe("aébc", 2), "a");
/// ```
#[must_use]
pub fn truncate_safe(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A byte-offset substring window that can never panic on a multibyte boundary.
///
/// Direct `&s[start..end]` slicing panics when `start`/`end` fall inside a
/// multibyte UTF-8 character — exactly the hazard when slicing scraped HTML at
/// *arithmetic* offsets like `pos ± N` (a postcode position widened by 60, an
/// HTML marker offset widened by 300). Real web pages routinely carry multibyte
/// bytes (accented names, typographic quotes, NBSP), so such offsets land
/// mid-character. This clamps both ends to the nearest valid char boundary
/// (rounding inward), bounded by `s.len()`, and guarantees `start <= end` — so
/// the worst case is a window a byte or two narrower than requested, never a
/// panic.
///
/// ```
/// use huntsman_search_engine::util::str_util::char_window;
///
/// let s = "aébc"; // bytes: a=0, é=1..3, b=3, c=4, len=5
/// assert_eq!(char_window(s, 0, 5), "aébc"); // whole string
/// // end=2 is inside 'é' → rounds up to 3; start=1 is a boundary → "é".
/// assert_eq!(char_window(s, 1, 2), "é");
/// // start=2 is inside 'é' → rounds up to 3 → "bc"; end past len clamps to len.
/// assert_eq!(char_window(s, 2, 999), "bc");
/// assert_eq!(char_window(s, 999, 999), "");
/// ```
#[must_use]
pub fn char_window(s: &str, start: usize, end: usize) -> &str {
    let len = s.len();
    let mut a = start.min(len);
    while a < len && !s.is_char_boundary(a) {
        a += 1;
    }
    let mut b = end.min(len).max(a);
    while b < len && !s.is_char_boundary(b) {
        b += 1;
    }
    &s[a..b]
}

/// Fold common Latin diacritics to their base ASCII letter, lowercase, and
/// drop everything else. Pure and dependency-free (no `deunicode`/ICU — keeps
/// the Termux single-binary lean). A name like `"José Müller-Łódź"` folds to
/// the ASCII stem real platforms actually use (`josemullerlodz`), so derived
/// usernames/emails match. Multi-char expansions (`æ→ae`, `ß→ss`, `þ→th`) are
/// handled; non-Latin scripts (Arabic, CJK) have no ASCII fold and are
/// dropped — callers should split into words *before* folding each token.
///
/// # Guarantees
/// - **Charset:** the result contains only `[a-z0-9]` — every byte is ASCII
///   lowercase alphanumeric. The result is therefore always valid to index by
///   byte; `name_intel::permute` relies on this for safe slicing. (Proved
///   exhaustively over every Unicode scalar value by
///   `fold_ascii_lower_output_is_ascii_lower_alnum_for_all_scalars`.)
/// - **Idempotent:** `fold_ascii_lower(&fold_ascii_lower(s)) == fold_ascii_lower(s)`
///   (a corollary: `[a-z0-9]` map to themselves).
/// - **Total:** never panics, on any input including arbitrary Unicode.
/// - A token with no foldable Latin content yields the empty string.
///
/// ```
/// use huntsman_search_engine::util::str_util::fold_ascii_lower;
///
/// assert_eq!(fold_ascii_lower("José Müller"), "josemuller"); // diacritics + space dropped
/// assert_eq!(fold_ascii_lower("O'Brien-Smith"), "obriensmith"); // punctuation dropped
/// assert_eq!(fold_ascii_lower("Straße"), "strasse"); // ß → ss
/// assert_eq!(fold_ascii_lower("日本語"), ""); // no ASCII fold → empty
/// assert!(
///     fold_ascii_lower("Zoë_99 🎉")
///         .bytes()
///         .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
/// );
/// ```
pub fn fold_ascii_lower(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            'a'..='z' | '0'..='9' => out.push(ch),
            'A'..='Z' => out.push(ch.to_ascii_lowercase()),
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'À' | 'Á' | 'Â' | 'Ã' | 'Ä' | 'Å' | 'ā' | 'ă'
            | 'ą' => out.push('a'),
            'ç' | 'Ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => out.push('c'),
            'è' | 'é' | 'ê' | 'ë' | 'È' | 'É' | 'Ê' | 'Ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => {
                out.push('e')
            }
            'ì' | 'í' | 'î' | 'ï' | 'Ì' | 'Í' | 'Î' | 'Ï' | 'ī' | 'ĭ' | 'į' | 'ı' => {
                out.push('i')
            }
            'ñ' | 'Ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'Ò' | 'Ó' | 'Ô' | 'Õ' | 'Ö' | 'Ø' | 'ō' | 'ŏ'
            | 'ő' => out.push('o'),
            'ù' | 'ú' | 'û' | 'ü' | 'Ù' | 'Ú' | 'Û' | 'Ü' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => {
                out.push('u')
            }
            'ý' | 'ÿ' | 'Ý' | 'Ŷ' | 'ŷ' => out.push('y'),
            'ł' | 'Ł' => out.push('l'),
            'ś' | 'š' | 'ş' | 'Ś' | 'Š' | 'Ş' => out.push('s'),
            'ź' | 'ż' | 'ž' | 'Ź' | 'Ż' | 'Ž' => out.push('z'),
            'ð' | 'Đ' | 'đ' => out.push('d'),
            'ț' | 'ţ' | 'Ț' | 'Ţ' => out.push('t'),
            'ğ' | 'Ğ' => out.push('g'),
            'ř' | 'Ř' => out.push('r'),
            'æ' | 'Æ' => out.push_str("ae"),
            'œ' | 'Œ' => out.push_str("oe"),
            'ß' => out.push_str("ss"),
            'þ' | 'Þ' => out.push_str("th"),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{ascii_digits, char_window, fold_ascii_lower, nonempty, truncate_safe};

    #[test]
    fn nonempty_trims_and_treats_blank_as_absent() {
        assert_eq!(nonempty(&Some("  hi ".to_string())), Some("hi"));
        assert_eq!(nonempty(&Some("x".to_string())), Some("x"));
        assert_eq!(nonempty(&Some("   ".to_string())), None);
        assert_eq!(nonempty(&Some(String::new())), None);
        assert_eq!(nonempty(&None), None);
    }

    #[test]
    fn ascii_digits_keeps_only_digits_in_order() {
        assert_eq!(ascii_digits("+61 (4) 123-456"), "614123456");
        assert_eq!(ascii_digits("AS13335"), "13335");
        assert_eq!(ascii_digits("no digits here"), "");
        assert_eq!(ascii_digits(""), "");
        // Non-ASCII digits (e.g. Arabic-Indic ٤) are not ASCII → dropped.
        assert_eq!(ascii_digits("a١2b3"), "23");
    }

    #[test]
    fn truncate_safe_never_splits_a_codepoint() {
        // Caps web_crawler's page body etc. A raw `s[..max]` panics when
        // `max` lands mid-codepoint; truncate_safe must back off to the
        // nearest char boundary instead (for every possible cut point).
        let s = "aé😀b"; // 1 + 2 + 4 + 1 = 8 bytes, char boundaries at 0,1,3,7,8
        for max in 0..=s.len() + 2 {
            let out = truncate_safe(s, max);
            assert!(s.starts_with(out), "must be a prefix (max={max})");
            assert!(out.len() <= max, "must not exceed max (max={max})");
            // Result is always valid UTF-8 by construction (it's a &str), and
            // the call itself must not panic — which is the whole point.
        }
        assert_eq!(truncate_safe(s, 100), s, "<= len returns whole string");
        assert_eq!(truncate_safe("hello", 3), "hel"); // pure-ASCII exact cut
    }

    #[test]
    fn char_window_never_panics_at_any_arithmetic_offset() {
        // The whole point of char_window: slicing scraped HTML at arithmetic
        // byte offsets (pos±N) must never panic on a multibyte boundary.
        // Exhaustively window every (start, end) pair, including past the end —
        // the loop completing IS the panic-safety proof.
        let s = "aé😀b xÿz"; // mixed 1/2/4-byte chars interleaved with ASCII
        for start in 0..=s.len() + 2 {
            for end in 0..=s.len() + 2 {
                let out = char_window(s, start, end);
                // Always a real contiguous substring (valid &str by construction).
                assert!(out.is_empty() || s.contains(out), "real slice: {start},{end}");
            }
        }
        // Boundary-rounding spot-checks ("aébc": a=0, é=1..3, b=3, c=4).
        assert_eq!(char_window("aébc", 1, 3), "é"); // both ends on boundaries
        assert_eq!(char_window("aébc", 2, 4), "b"); // start inside 'é' → rounds to 3
        assert_eq!(char_window("aébc", 0, 0), ""); // empty window
    }

    /// All four documented guarantees, over an adversarial corpus × every
    /// `max` (incl. 0 and past the end): prefix, bounded, lossless-when-fits,
    /// boundary-aligned + idempotent — and the call never panics.
    #[test]
    fn truncate_safe_invariants_hold_over_corpus() {
        for s in [
            "",
            "a",
            "aé😀b",
            "héllo wörld",
            "🎉🎉🎉",
            "ascii-only",
            "\u{0}\u{7f}\u{200b}",
        ] {
            for max in 0..=s.len() + 3 {
                let out = truncate_safe(s, max);
                assert!(s.starts_with(out), "prefix: {s:?} max={max}");
                assert!(out.len() <= max, "bounded: {s:?} max={max}");
                assert!(s.is_char_boundary(out.len()), "boundary: {s:?} max={max}");
                if s.len() <= max {
                    assert_eq!(out, s, "lossless when it fits: {s:?} max={max}");
                }
                // Re-truncating the result at the same cap is a fixed point.
                assert_eq!(truncate_safe(out, max), out, "idempotent: {s:?} max={max}");
            }
        }
    }

    #[test]
    fn folds_latin_diacritics() {
        assert_eq!(fold_ascii_lower("José"), "jose");
        assert_eq!(fold_ascii_lower("Müller"), "muller");
        assert_eq!(fold_ascii_lower("Łódź"), "lodz");
        assert_eq!(fold_ascii_lower("Çağrı"), "cagri"); // ç→c, ğ→g, ı→i
        assert_eq!(fold_ascii_lower("Straße"), "strasse"); // ß → ss
        assert_eq!(fold_ascii_lower("Æon"), "aeon"); // æ → ae
        // ASCII passes through lowercased; punctuation/space dropped.
        assert_eq!(fold_ascii_lower("O'Brien-Smith"), "obriensmith");
        // Non-Latin has no ASCII fold → dropped.
        assert_eq!(fold_ascii_lower("علي"), "");
    }

    /// Charset guarantee, proved EXHAUSTIVELY: for every Unicode scalar
    /// value, folding it yields only `[a-z0-9]` and never panics. Because the
    /// fold is per-character, this covers the entire input domain for the
    /// charset property — any longer string is a concatenation of these. This
    /// is the invariant that makes downstream byte-slicing of the result safe.
    #[test]
    fn fold_ascii_lower_output_is_ascii_lower_alnum_for_all_scalars() {
        for cp in 0u32..=0x10_FFFF {
            let Some(ch) = char::from_u32(cp) else {
                continue; // surrogate range: not a scalar value
            };
            let folded = fold_ascii_lower(ch.encode_utf8(&mut [0u8; 4]));
            assert!(
                folded
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "U+{cp:04X} folded to non-[a-z0-9]: {folded:?}"
            );
        }
    }

    /// Idempotence over an adversarial multi-char corpus: the result is a
    /// fixed point (follows from the charset guarantee, but pinned directly).
    #[test]
    fn fold_ascii_lower_is_idempotent() {
        for s in [
            "José Müller-Łódź",
            "O'Brien-Smith",
            "Straße",
            "ABC123xyz",
            "🎉 mixed Ünïcödé 日本語 99",
            "",
            "\u{0}\u{7f}\u{200b}", // NUL, DEL, zero-width space
        ] {
            let once = fold_ascii_lower(s);
            assert_eq!(fold_ascii_lower(&once), once, "not idempotent for {s:?}");
        }
    }
}
