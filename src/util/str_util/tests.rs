
use super::{
    ascii_digits, char_window, find_ascii_ci, fold_ascii_lower, is_handle, mask_secret, nonempty,
    parse_asn, slugify, truncate_display, truncate_safe,
};

    #[test]
    fn is_handle_enforces_bounds_and_charset() {
        // reddit_user (3..=20) and hacker_news (2..=15) bounds.
        assert!(is_handle("pg", 2, 15));
        assert!(is_handle("spez", 3, 20));
        assert!(is_handle("a-b_c9", 3, 20));
        assert!(!is_handle("a", 3, 20)); // below min
        assert!(!is_handle("x".repeat(21).as_str(), 3, 20)); // above max
        assert!(!is_handle("bad.handle", 3, 20)); // '.' not allowed
        assert!(!is_handle("space bar", 3, 20)); // space not allowed
        assert!(!is_handle("café", 2, 15)); // non-ASCII rejected
    }

    #[test]
    fn parse_asn_strips_case_insensitive_prefix_and_validates() {
        // The shared form the bgpview/ip_registry/zoomeye sites converged on.
        assert_eq!(parse_asn("AS13335"), Some(13335));
        assert_eq!(parse_asn("as13335"), Some(13335)); // zoomeye lacked this
        assert_eq!(parse_asn("As13335"), Some(13335));
        assert_eq!(parse_asn("13335"), Some(13335));
        assert_eq!(parse_asn("  AS13335 "), Some(13335));
        assert_eq!(parse_asn("AS 13335"), Some(13335)); // inner space trimmed
        assert_eq!(parse_asn("4294967295"), Some(u64::from(u32::MAX))); // 32-bit ASN
        // Rejections: not a bare AS prefix, or trailing junk → no garbage URL.
        assert_eq!(parse_asn("ASN13335"), None);
        assert_eq!(parse_asn("13335x"), None);
        assert_eq!(parse_asn("AS"), None);
        assert_eq!(parse_asn(""), None);
        assert_eq!(parse_asn("astronomy"), None); // "as" prefix, "tronomy" not digits
    }

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

    #[test]
    fn mask_secret_fully_masks_below_sixteen_chars() {
        // A 9-15 char secret must NOT get a head(4)+tail(4) hint — that would
        // leave less than half of it hidden (and reveal ALL of one <= 8 chars,
        // the shape of the bug this guards: one call site used an `> 8`
        // threshold instead of this `< 16` one).
        assert_eq!(mask_secret(""), "•");
        assert_eq!(mask_secret("abc"), "•••");
        assert_eq!(mask_secret("abcdefgh"), "••••••••");
        assert_eq!(mask_secret("abcdefghijklmno"), "•".repeat(15));
    }

    #[test]
    fn mask_secret_reveals_head_and_tail_at_sixteen_chars_and_above() {
        assert_eq!(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA…MPLE");
        assert_eq!(mask_secret(&"x".repeat(16)), "xxxx…xxxx");
    }

    #[test]
    fn mask_secret_is_char_boundary_safe_on_multibyte_input() {
        // Byte-indexed slicing (`&v[..4]`/`&v[len-4..]`) would panic if the 4th
        // byte lands inside a multi-byte char; `chars()`-based indexing never does.
        let v = "𝕊éCRet𝕊éCRet𝕊éCRet"; // 18 chars, well over the 16-char threshold
        let m = mask_secret(v);
        assert!(m.contains('…'));
        assert_eq!(m.chars().count(), 9);
    }

// ── Property tests (proptest) ──────────────────────────────────────────────
// These pin the *invariants* the doc comments promise — "Total: never panics",
// "Prefix", "Bounded", boundary-safety — over thousands of arbitrary inputs
// (incl. multibyte / non-Latin / control chars), the exact class of input that
// produced the T0 `to_lowercase()`-offset slice panics. A regression that
// reintroduces a non-boundary slice fails here, not in production on a stranger's
// scraped homepage.
mod prop {
    use proptest::prelude::*;

    use super::super::{
        ascii_digits, ceil_char_boundary, char_window, find_ascii_ci, floor_char_boundary,
        slugify, truncate_display, truncate_safe,
    };

    proptest! {
        /// `find_ascii_ci` returns an offset that is always safe to slice the
        /// ORIGINAL haystack at (the whole point of the helper) and that actually
        /// matches case-insensitively.
        #[test]
        fn find_ascii_ci_offset_is_boundary_safe_and_matches(h in ".{0,64}", n in ".{0,8}") {
            if let Some(i) = find_ascii_ci(&h, &n) {
                prop_assert!(i + n.len() <= h.len());
                prop_assert!(h.is_char_boundary(i), "start {i} not a boundary in {h:?}");
                prop_assert!(h.is_char_boundary(i + n.len()), "end not a boundary");
                // The slice is valid (no panic) AND matches the needle ASCII-CI.
                prop_assert!(h[i..i + n.len()].eq_ignore_ascii_case(&n));
            }
        }

        /// An empty needle is found at 0; a needle longer than the haystack is
        /// never found.
        #[test]
        fn find_ascii_ci_edge_lengths(h in ".{0,32}") {
            prop_assert_eq!(find_ascii_ci(&h, ""), Some(0));
            let longer = format!("{h}x");
            prop_assert_eq!(find_ascii_ci(&h, &longer), None);
        }

        /// `truncate_safe` is a bounded, char-boundary prefix — for ANY `max`.
        #[test]
        fn truncate_safe_is_a_bounded_prefix(s in ".{0,64}", max in 0usize..80) {
            let t = truncate_safe(&s, max);
            prop_assert!(s.starts_with(t));
            prop_assert!(t.len() <= max);
            prop_assert!(s.is_char_boundary(t.len()));
            // Lossless when it fits.
            if s.len() <= max {
                prop_assert_eq!(t, &s);
            }
        }

        /// `char_window` never panics and always yields a real substring of `s`
        /// (both ends rounded to boundaries, never inverted), for any offsets.
        #[test]
        fn char_window_is_a_real_substring(s in ".{0,64}", a in 0usize..80, b in 0usize..80) {
            let w = char_window(&s, a, b);
            // It is literally a sub-slice of s (so boundaries held — no panic).
            prop_assert!(s.contains(w) || w.is_empty());
            prop_assert!(w.len() <= s.len());
        }

        /// `floor`/`ceil` return valid boundaries that bracket the (clamped) index
        /// and are always safe to slice at.
        #[test]
        fn char_boundaries_are_valid_and_ordered(s in ".{0,64}", i in 0usize..80) {
            let lo = floor_char_boundary(&s, i);
            let hi = ceil_char_boundary(&s, i);
            prop_assert!(s.is_char_boundary(lo));
            prop_assert!(s.is_char_boundary(hi));
            prop_assert!(lo <= hi);
            prop_assert!(hi <= s.len());
            // Both slice positions are valid (would panic otherwise).
            let _ = (&s[..lo], &s[hi..]);
        }

        /// `slugify` output is the promised charset with no edge/double dashes.
        #[test]
        fn slugify_charset_and_shape(s in ".{0,64}") {
            let slug = slugify(&s);
            prop_assert!(
                slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "unexpected char in slug {slug:?}"
            );
            prop_assert!(!slug.starts_with('-') && !slug.ends_with('-'));
            prop_assert!(!slug.contains("--"));
        }

        /// `ascii_digits` keeps only ASCII digits and never grows the string.
        #[test]
        fn ascii_digits_keeps_only_digits(s in ".{0,64}") {
            let d = ascii_digits(&s);
            prop_assert!(d.bytes().all(|b| b.is_ascii_digit()));
            prop_assert!(d.len() <= s.len());
        }

        /// `truncate_display` is char-bounded; lossless when it already fits.
        #[test]
        fn truncate_display_char_bound(s in ".{0,64}", max in 0usize..40) {
            let t = truncate_display(&s, max);
            if s.chars().count() <= max {
                prop_assert_eq!(&t, &s);
            } else {
                // head (max chars) + the single ellipsis.
                prop_assert_eq!(t.chars().count(), max + 1);
                prop_assert!(t.ends_with('…'));
            }
        }
    }
}
