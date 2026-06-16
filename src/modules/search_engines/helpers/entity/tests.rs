use super::*;

    fn sr(title: &str, snippet: &str, url: &str, query: &str) -> SearchResult {
        SearchResult {
            url: url.to_string(),
            title: title.to_string(),
            snippet: snippet.to_string(),
            engine: "test",
            query: query.to_string(),
        }
    }

    #[test]
    fn extract_addresses_never_panics_on_multibyte_after_reconstructed_address() {
        // Regression: the postcode-lookahead reconstructs the address as
        // "City, State" (a ", " separator), so when the source text used
        // different punctuation the string is NOT a literal substring and
        // `find` returns None. The old `unwrap_or(0) + r.len()` fallback then
        // indexed at a byte offset (18) unrelated to the text — here it lands
        // inside the 3-byte '€', slicing mid-codepoint and panicking. The
        // address itself is still extracted; only the (skipped) postcode
        // lookahead differs.
        let addrs = extract_addresses_from_text("Nundah,Queensland€xx");
        assert!(
            addrs.iter().any(|a| a == "Nundah, Queensland"),
            "address still extracted, no panic: {addrs:?}"
        );

        // The real-world payload that crashed a live scan: an en-dash (U+2013)
        // in a SOHO real-estate page title. Must not panic.
        let _ = extract_addresses_from_text(
            "SOHO Galleries – Sydney Art Gallery, New South Wales and beyond",
        );

        // Positive path intact: a clean address with a trailing postcode still
        // gains the postcode-qualified variant.
        let with_pc = extract_addresses_from_text("Lives in Gatton, QLD 4343 now");
        assert!(
            with_pc.iter().any(|a| a == "Gatton, QLD 4343"),
            "postcode still attaches on clean input: {with_pc:?}"
        );
    }

    // ── score_username ───────────────────────────────────────────────────────

    #[test]
    fn score_username_term_overlap_gives_probable_confidence() {
        // "jordan" appears in the username → Signal 1 fires (+3) → score ≥ 3 → 0.55
        let r = sr("Jordan Meyers profile", "some text", "https://x.com/jordanm", "jordan meyers");
        let terms = vec!["jordan".to_string(), "meyers".to_string()];
        let (score, conf) = score_username("jordanmeyers", "x.com", &terms, &r);
        assert!(score >= 3, "term overlap must reach probable threshold: {score}");
        assert_eq!(conf, 0.55);
    }

    #[test]
    fn score_username_no_signals_gives_candidate_confidence() {
        // username "zzz" shares nothing with terms and host is not a people-search
        let r = sr("", "", "https://example.com/zzz", "alice bob");
        let terms = vec!["alice".to_string(), "bob".to_string()];
        let (score, conf) = score_username("zzz", "example.com", &terms, &r);
        assert_eq!(score, 0);
        assert_eq!(conf, 0.30);
    }

    #[test]
    fn score_username_people_search_host_boosts_score() {
        // Host is whitepages.com → Signal 2 (+3) → probable even without name match
        let r = sr("", "", "https://whitepages.com/bob", "bob smith");
        let terms = vec!["bob".to_string()];
        let (_score, conf) = score_username("randomhandle", "whitepages.com", &terms, &r);
        assert_eq!(conf, 0.55, "people-search host must yield probable confidence");
    }

    #[test]
    fn score_username_co_occurrence_adds_to_score() {
        // term "alice" (≥4 chars) appears in snippet → Signal 3 (+2)
        let r = sr("", "Alice uses handle xyz", "https://blog.com", "alice");
        let terms = vec!["alice".to_string()];
        let (score, _) = score_username("xyz", "blog.com", &terms, &r);
        assert!(score >= 2, "co-occurrence must contribute: {score}");
    }

    #[test]
    fn score_username_site_query_adds_to_score() {
        // query contains "site:github.com" → Signal 4 (+1)
        let r = sr("", "", "https://github.com/alice", "site:github.com alice");
        let terms = vec!["alice".to_string()];
        let (score, _) = score_username("alice", "github.com", &terms, &r);
        assert!(score >= 1, "site: query must add at least 1 to score: {score}");
    }

    #[test]
    fn score_username_subdomain_people_search_is_recognised() {
        // records.whitepages.com is a subdomain of whitepages.com → people-search fires
        let r = sr("", "", "https://records.whitepages.com/alice", "alice");
        let terms = vec!["alice".to_string()];
        let (_score, conf) = score_username("anyhandle", "records.whitepages.com", &terms, &r);
        assert_eq!(conf, 0.55);
    }

    // ── normalise_address_key ────────────────────────────────────────────────

    #[test]
    fn normalise_expands_au_state_abbreviations() {
        let k = normalise_address_key("Gatton, QLD");
        assert!(k.contains("queensland"), "QLD must expand: {k:?}");
        assert!(!k.contains("qld"), "abbreviation must be replaced: {k:?}");
    }

    #[test]
    fn normalise_strips_trailing_postcode() {
        let with = normalise_address_key("Gatton, QLD 4343");
        let without = normalise_address_key("Gatton, QLD");
        assert_eq!(with, without, "postcode must be stripped for dedup: {with:?} != {without:?}");
    }

    #[test]
    fn normalise_does_not_strip_leading_street_number() {
        // "42 Collins Street" — "42" is a leading token, not a trailing postcode
        let k = normalise_address_key("42 Collins Street, Melbourne VIC 3000");
        assert!(k.starts_with("42"), "leading street number must be kept: {k:?}");
    }

    #[test]
    fn normalise_collapses_punctuation_to_spaces() {
        let a = normalise_address_key("Sydney, NSW");
        let b = normalise_address_key("Sydney NSW");
        assert_eq!(a, b, "comma vs space must dedup to same key");
    }
