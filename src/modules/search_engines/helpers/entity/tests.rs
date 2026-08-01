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

    #[test]
    fn extract_addresses_strips_bled_over_state_from_run_on_cities() {
        // Real SERP bio that produced a bogus geolocation fix: a run-on listing
        // two cities. `rfind` grabbed "California Dallas" as the city for Texas
        // (the leading "California" is the STATE of "Los Angeles, California").
        // The extractor must yield "Los Angeles, California" and "Dallas, Texas",
        // never the phantom "California Dallas, Texas".
        let addrs = extract_addresses_from_text(
            "Graduate '13 Los Angeles, California Dallas, Texas Contact: x@y.com",
        );
        assert!(
            addrs.iter().any(|a| a == "Los Angeles, California"),
            "first address intact: {addrs:?}"
        );
        assert!(
            addrs.iter().any(|a| a == "Dallas, Texas"),
            "bled-over state stripped → real city recovered: {addrs:?}"
        );
        assert!(
            !addrs.iter().any(|a| a.contains("California Dallas")),
            "phantom 'California Dallas' city must not survive: {addrs:?}"
        );

        // Safety: a genuine city that BEGINS with its own state name keeps it —
        // the bled token must DIFFER from the address's state to be stripped.
        let vb = extract_addresses_from_text("Studio in Virginia Beach, Virginia today");
        assert!(
            vb.iter().any(|a| a == "Virginia Beach, Virginia"),
            "state-named city preserved when token matches its state: {vb:?}"
        );
        // Safety: word-path cities (no preceding comma) are untouched.
        let kc = extract_addresses_from_text("She lives in Kansas City, Missouri now");
        assert!(
            kc.iter().any(|a| a == "Kansas City, Missouri"),
            "word-path state-named city preserved: {kc:?}"
        );
    }

    #[test]
    fn extract_addresses_deduplicates_repeated_mentions_within_one_text() {
        // Found via a real scan's debug log: a single SERP result's combined
        // title+snippet text mentioned the same locality twice (once in each),
        // and the STATES pass (unlike the AU_PLACES pass, which already dedupes
        // via `seen_addr_keys`) pushed the identical "City, State" string once
        // per repeat. build.rs's per-result merge loop then recorded the SAME
        // search result as its own "corroboration" of an address it had just
        // emitted, inflating the entity's `corroboration` field with duplicate,
        // non-independent evidence for a single result.
        let addrs = extract_addresses_from_text(
            "Autobarn Lawnton — 707 Gympie Road, Lawnton, Queensland. \
             This designer townhouse is in the heart of Lawnton, Queensland.",
        );
        let count = addrs.iter().filter(|a| *a == "Lawnton, Queensland").count();
        assert_eq!(
            count, 1,
            "a locality repeated twice in one text must be extracted once, got {addrs:?}"
        );
    }

    #[test]
    fn extract_addresses_states_and_au_places_passes_share_one_dedup_set() {
        // Both passes independently derive "Brisbane, QLD" from this text: the
        // STATES pass via the literal ", QLD" comma pattern, the AU_PLACES pass
        // via its own "Brisbane" + nearby "qld" context scan. The AU_PLACES
        // pass must not re-add the address the STATES pass already found —
        // verified end-to-end (a shared, cross-pass dedup set), not just via
        // the AU_PLACES-internal set alone.
        let addrs =
            extract_addresses_from_text("Now in Brisbane, QLD — Brisbane is home to the QLD Museum.");
        let count = addrs.iter().filter(|a| *a == "Brisbane, QLD").count();
        assert_eq!(
            count, 1,
            "STATES and AU_PLACES passes must not double-emit the same locality: {addrs:?}"
        );
    }

    // ── score_username ───────────────────────────────────────────────────────

    #[test]
    fn score_username_term_overlap_gives_probable_confidence() {
        // "jordan" appears in the username → Signal 1 fires (+3) → score ≥ 3 → confidence::MEDIUM_HIGH
        let r = sr("Jordan Meyers profile", "some text", "https://x.com/jordanm", "jordan meyers");
        let terms = vec!["jordan".to_string(), "meyers".to_string()];
        let (score, conf) = score_username("jordanmeyers", "x.com", &terms, &r);
        assert!(score >= 3, "term overlap must reach probable threshold: {score}");
        assert_eq!(conf, confidence::MEDIUM_HIGH);
    }

    #[test]
    fn address_state_detection_is_whole_word_not_substring() {
        // Ordinary words must not be mis-read as a state abbreviation — the free
        // prose around an AU place name routinely contains "ser{vic}e", "{act}ed",
        // which a bare substring scan turned into VIC / ACT and fabricated a wrong
        // jurisdiction. (`Logan`/`Ipswich` are known AU suburbs so the place gate
        // fires; only the state refinement is on trial.)
        let acted = extract_addresses_from_text(
            "Logan is a suburb in australia. the council acted quickly",
        );
        assert!(
            !acted.iter().any(|a| a.contains("ACT")),
            "\"acted\" must not be read as the ACT: {acted:?}"
        );
        let service =
            extract_addresses_from_text("Ipswich in australia, the service desk was great");
        assert!(
            !service.iter().any(|a| a.contains("VIC")),
            "\"service\" must not be read as VIC: {service:?}"
        );
        // A genuine whole-word state token still classifies correctly.
        let real = extract_addresses_from_text("Logan QLD is home");
        assert!(
            real.iter().any(|a| a.contains("QLD")),
            "a real QLD token must still classify: {real:?}"
        );
    }

    #[test]
    fn score_username_first_name_only_match_stays_candidate() {
        // A DIFFERENT person who shares only the target's GIVEN name must not be
        // promoted to PROBABLE: target "Jordan Meyers", SERP result for a stranger
        // "jordan_blake" on a non-people-search host. Even with first-name
        // co-occurrence (Signal 3) and a "jordan" stem (Signal 5) stacking, the
        // surname-anchor cap holds it at CANDIDATE (0.30) — the wrong-attribution
        // class `url_matches_target` already guards for paths.
        let terms = vec!["jordan".to_string(), "meyers".to_string()];
        let stranger = sr(
            "Jordan Blake (@jordan_blake)",
            "Jordan Blake's profile",
            "https://x.com/jordan_blake",
            "jordan meyers",
        );
        let (score, conf) = score_username("jordan_blake", "x.com", &terms, &stranger);
        assert!(score < 3, "first-name-only stranger must not reach PROBABLE: {score}");
        assert_eq!(conf, 0.30);

        // The real subject's surname-anchored handle DOES reach PROBABLE.
        let subject = sr(
            "Jordan Meyers",
            "profile",
            "https://x.com/jmeyers",
            "jordan meyers",
        );
        let (score, conf) = score_username("jmeyers", "x.com", &terms, &subject);
        assert!(score >= 3, "surname-anchored handle must reach PROBABLE: {score}");
        assert_eq!(conf, confidence::MEDIUM_HIGH);
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
        assert_eq!(conf, confidence::MEDIUM_HIGH, "people-search host must yield probable confidence");
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
        assert_eq!(conf, confidence::MEDIUM_HIGH);
    }

    #[test]
    fn score_username_business_slug_containing_the_surname_stays_candidate() {
        // Regression: a live "Brett Lawnton" scan surfaced a real "Tackle World
        // Lawnton" fishing-tackle retailer (named after the Lawnton suburb, QLD —
        // unrelated to the subject) whose Facebook slug "tackle_world_lawnton"
        // reached PROBABLE via Signal 1 (bare surname-anchor match) alone, then
        // got recycled into a further search purely because "lawnton" is a
        // substring — pulling the business's own web presence into the subject's
        // identity graph. "tackle"/"world" match neither the given nor surname
        // term, so this compound slug must be capped at CANDIDATE.
        let terms = vec!["brett".to_string(), "lawnton".to_string()];
        let r = sr(
            "Tackle World Lawnton",
            "Your local independent fishing expert",
            "https://m.facebook.com/tackle_world_lawnton",
            "\"tackleworldlawnton1\"",
        );
        let (score, conf) = score_username("tackle_world_lawnton", "facebook.com", &terms, &r);
        assert!(
            score < 3,
            "an unrelated business slug containing only the surname must not reach PROBABLE: {score}"
        );
        assert_eq!(conf, 0.30);
    }

    #[test]
    fn score_username_genuine_firstname_lastname_handle_still_reaches_probable() {
        // The fix must not over-broadly demote a real compound personal handle:
        // every part of "brett_lawnton" belongs to the subject's own name (no
        // foreign part), so Signal 1 alone still reaches PROBABLE.
        let terms = vec!["brett".to_string(), "lawnton".to_string()];
        let r = sr("Brett Lawnton", "profile", "https://x.com/brett_lawnton", "brett lawnton");
        let (score, conf) = score_username("brett_lawnton", "x.com", &terms, &r);
        assert!(
            score >= 3,
            "a genuine firstname_lastname handle must still reach PROBABLE: {score}"
        );
        assert_eq!(conf, confidence::MEDIUM_HIGH);
    }

    // ── locality_key ────────────────────────────────────────────────

    #[test]
    fn normalise_expands_au_state_abbreviations() {
        let k = locality_key("Gatton, QLD");
        assert!(k.contains("queensland"), "QLD must expand: {k:?}");
        assert!(!k.contains("qld"), "abbreviation must be replaced: {k:?}");
    }

    #[test]
    fn normalise_strips_trailing_postcode() {
        let with = locality_key("Gatton, QLD 4343");
        let without = locality_key("Gatton, QLD");
        assert_eq!(with, without, "postcode must be stripped for dedup: {with:?} != {without:?}");
    }

    #[test]
    fn normalise_does_not_strip_leading_street_number() {
        // "42 Collins Street" — "42" is a leading token, not a trailing postcode
        let k = locality_key("42 Collins Street, Melbourne VIC 3000");
        assert!(k.starts_with("42"), "leading street number must be kept: {k:?}");
    }

    #[test]
    fn normalise_collapses_punctuation_to_spaces() {
        let a = locality_key("Sydney, NSW");
        let b = locality_key("Sydney NSW");
        assert_eq!(a, b, "comma vs space must dedup to same key");
    }

    /// State abbreviations must expand TOKEN-WISE, never by substring.
    ///
    /// The module-local key this now delegates to `util::address_au` replaced
    /// `s.replace(abbr, full)` over the whole string, so `nsw` became
    /// `new south wales` and the later `wa` rule then matched the `wa` inside
    /// `wales` — yielding `new south western australiales`. The equality tests
    /// above could not catch it because the corruption is symmetric: both
    /// spellings of a locality mangle to the same wrong string and still
    /// compare equal. These assert the key's CONTENT, which is what the
    /// symmetric-equality checks cannot.
    #[test]
    fn state_expansion_is_token_wise_not_substring() {
        for input in ["Sydney, NSW", "Newcastle, NSW", "Sydney, New South Wales"] {
            let k = locality_key(input);
            assert!(
                k.ends_with("new south wales"),
                "{input:?} must expand to `new south wales`, got {k:?}"
            );
            assert!(
                !k.contains("western australia"),
                "the `wa` inside `wales` must not expand: {input:?} -> {k:?}"
            );
        }
    }

    /// A non-AU address must survive unmangled: the substring expansion turned
    /// `Santa Monica, CA` into `south australianorthern territorya monica ca`
    /// (`sa` inside `santa`, then `nt` inside the result).
    #[test]
    fn non_au_address_is_not_mangled_by_state_expansion() {
        let k = locality_key("Santa Monica, CA");
        assert_eq!(k, "santa monica ca", "no AU state token is present here");
    }

    /// A word containing a state code as a substring must be left intact —
    /// `contact` contains both `act` and (after any naive rewrite) `nt`.
    #[test]
    fn words_containing_state_codes_are_left_intact() {
        let k = locality_key("Contact Street, VIC");
        assert_eq!(k, "contact street victoria");
    }

    /// The per-module dedup key and the engine-wide consolidation backstop
    /// (`core::engine::passes::consolidate_address_localities`) must agree by
    /// construction. They are now literally the same function; this pins that.
    #[test]
    fn module_key_is_the_same_function_as_the_engine_backstop() {
        for addr in [
            "Murrumbateman, NSW",
            "Murrumbateman, NSW 2582",
            "Kuraby, Queensland",
            "Wagga Wagga, NSW 2650",
        ] {
            assert_eq!(
                locality_key(addr),
                crate::util::address_au::locality_key(addr),
                "module and engine must compute one key for {addr:?}"
            );
        }
    }

    #[test]
    fn extract_urls_from_text_pulls_embedded_links_and_trims_punctuation() {
        // A snippet naming the subject's other profiles.
        let urls = extract_urls_from_text(
            "Bio: see https://github.com/alice and http://twitter.com/alice_b, plus https://example.com.",
        );
        assert_eq!(
            urls,
            vec![
                "https://github.com/alice".to_string(),
                "http://twitter.com/alice_b".to_string(),
                "https://example.com".to_string(),
            ],
            "embedded http(s) URLs extracted; trailing comma/period trimmed"
        );
        // Plain prose with no links yields nothing.
        assert!(extract_urls_from_text("just a plain bio with no links").is_empty());
        // A bare "http" word without the scheme separator is not a URL.
        assert!(extract_urls_from_text("the http protocol is old").is_empty());
        // De-duplication, and the bare-scheme guard (too short to be a real URL).
        let dd = extract_urls_from_text("https://x.io/a https://x.io/a https://");
        assert_eq!(
            dd,
            vec!["https://x.io/a".to_string()],
            "deduped; bare scheme dropped"
        );
    }

    #[test]
    fn extract_urls_from_text_keeps_balanced_trailing_paren() {
        // Regression (real-execution derived): a live `rust-lang.org` search
        // produced BOTH the correct URL and a truncated duplicate missing the
        // closing paren, because the trailing-punctuation trim stripped the
        // balanced `)` of a Wikipedia disambiguation path. A matched `)` must
        // be kept; only a DANGLING one (prose `(...)` wrapping) is stripped.
        let urls = extract_urls_from_text(
            "ref: https://en.wikipedia.org/wiki/Rust_(programming_language)",
        );
        assert_eq!(
            urls,
            vec!["https://en.wikipedia.org/wiki/Rust_(programming_language)".to_string()],
            "balanced trailing ) is part of the URL and must be preserved"
        );

        // A DANGLING close paren from prose wrapping is still stripped.
        let wrapped = extract_urls_from_text("(see https://example.com/path)");
        assert_eq!(
            wrapped,
            vec!["https://example.com/path".to_string()],
            "unbalanced ) from prose wrapping is trimmed"
        );

        // Balanced paren then sentence punctuation: keep the ), drop the period.
        let sentence = extract_urls_from_text("End: https://ex.com/a_(b).");
        assert_eq!(
            sentence,
            vec!["https://ex.com/a_(b)".to_string()],
            "trailing sentence period trimmed; balanced ) kept"
        );
    }
