
use super::{
    ascii_digits, char_window, find_ascii_ci, fold_ascii_lower, nonempty, slugify,
    truncate_display, truncate_safe,
};

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
                assert!(
                    out.is_empty() || s.contains(out),
                    "real slice: {start},{end}"
                );
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

    #[test]
    fn slugify_lowercases_and_collapses_non_alnum_to_dash() {
        assert_eq!(slugify("Hello World"), "hello-world");
        assert_eq!(slugify("github.com"), "github-com");
        assert_eq!(slugify("---"), "");
        assert_eq!(slugify("client transfer prohibited"), "client-transfer-prohibited");
        assert_eq!(slugify("no-spaces"), "no-spaces");
        assert_eq!(slugify("a  b   c"), "a-b-c");
        assert_eq!(slugify(""), "");
    }

    #[test]
    fn truncate_display_appends_ellipsis_when_long() {
        assert_eq!(truncate_display("hello", 10), "hello");
        assert_eq!(truncate_display("hello world", 5), "hello…");
        let long: String = "a".repeat(300);
        let t = truncate_display(&long, 200);
        assert!(t.ends_with('…'));
        assert_eq!(t.chars().count(), 201);
    }

    // ── find_ascii_ci ─────────────────────────────────────────────────────────

    #[test]
    fn find_ascii_ci_matches_case_insensitively() {
        assert_eq!(find_ascii_ci("abcDEF", "def"), Some(3));
        assert_eq!(find_ascii_ci("Hello World", "WORLD"), Some(6));
        assert_eq!(find_ascii_ci("xx", "xx"), Some(0));
    }

    #[test]
    fn find_ascii_ci_offset_is_valid_in_the_original_after_multibyte() {
        // `İ` is 2 bytes; an offset from `to_lowercase()` would be wrong here.
        // The returned offset must index the ORIGINAL string on a char boundary.
        let s = "İ division of x";
        let off = find_ascii_ci(s, "DIVISION OF ").unwrap();
        assert_eq!(off, 3); // İ(2 bytes) + ' '(1)
        assert!(s[off..].starts_with("division of ")); // slice must not panic
    }

    #[test]
    fn find_ascii_ci_none_empty_and_too_long() {
        assert_eq!(find_ascii_ci("abc", "xyz"), None);
        assert_eq!(find_ascii_ci("abc", ""), Some(0)); // empty needle
        assert_eq!(find_ascii_ci("ab", "abc"), None); // needle longer than haystack
    }

    #[test]
    fn find_ascii_ci_non_ascii_never_matches_ascii_needle() {
        // A multibyte char's bytes never ASCII-fold-equal an ASCII needle byte.
        assert_eq!(find_ascii_ci("İ", "i"), None);
    }
