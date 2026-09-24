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

    #[test]
    fn score_username_common_surname_without_independent_signal_stays_candidate() {
        // Regression (Cycle AM): a FullName control with a common surname like
        // "John Smith" must not match unrelated handles that happen to contain
        // "smith" without an independent signal. The bare surname anchor is too weak
        // for common names — "smith_engineering" for "John Smith" is a business name
        // that happens to contain a popular surname, not a personal handle for John.
        // Without independent corroboration (a people-search host), Signal 1
        // alone must not clear the PROBABLE gate.
        let terms = vec!["john".to_string(), "smith".to_string()];
        let r = sr(
            "Smith Engineering",
            "business profile",
            "https://business.com/smith_engineering",
            "john smith",
        );
        let (score, conf) = score_username("smith_engineering", "business.com", &terms, &r);
        assert!(
            score < 3,
            "common surname without independent signal must not reach PROBABLE: {score}"
        );
        assert_eq!(conf, 0.30);

        // A site: query targeting the platform is HSE's own query construction,
        // not independent evidence (REQ-SEARCH-011): the business slug stays
        // CANDIDATE under it.
        let r_with_site = sr(
            "Smith Engineering",
            "business profile",
            "https://github.com/smith_engineering",
            "site:github.com john smith",
        );
        let (score_site, conf_site) = score_username("smith_engineering", "github.com", &terms, &r_with_site);
        assert!(
            score_site < 3,
            "HSE's own site: dork must not lift a business slug to PROBABLE: {score_site}"
        );
        assert_eq!(conf_site, 0.30);

        // With people-search provenance, the surname anchor clears the gate
        let r_people_search = sr(
            "John Smith",
            "public record",
            "https://whitepages.com/smith_engineering",
            "john smith",
        );
        let (score_ps, conf_ps) = score_username("smith_engineering", "whitepages.com", &terms, &r_people_search);
        assert!(
            score_ps >= 3,
            "surname anchor + people-search host must reach PROBABLE: {score_ps}"
        );
        assert_eq!(conf_ps, confidence::MEDIUM_HIGH);
    }

    #[test]
    fn score_username_site_query_does_not_lift_business_slug_gate() {
        // REQ-SEARCH-011, live scan 7258fc07 ("Ian Thorpe"): the facility handle
        // `ianthorpe_aquatic` reached PROBABLE and was pivoted into a follow-up
        // handle search only because HSE's own `site:instagram.com` dork
        // returned it.
        let terms = vec!["ian".to_string(), "thorpe".to_string()];
        let r = sr(
            "Ian Thorpe Aquatic Centre (@ianthorpe_aquatic)",
            "Instagram instagram.com › ianthorpe_aquatic Ian Thorpe Aquatic Centre (@ianthorpe_aquatic)",
            "https://www.instagram.com/ianthorpe_aquatic/?hl=en",
            "Ian Thorpe site:instagram.com OR site:github.com OR site:reddit.com",
        );
        let (score, conf) = score_username("ianthorpe_aquatic", "www.instagram.com", &terms, &r);
        assert!(
            score < 3,
            "a facility slug must not reach PROBABLE via HSE's own site: dork: {score}"
        );
        assert_eq!(conf, 0.30);

        // A genuine handle under the same query is unaffected.
        let r2 = sr(
            "Ian Thorpe (@ian_thorpe)",
            "",
            "https://www.instagram.com/ian_thorpe/",
            "Ian Thorpe site:instagram.com",
        );
        let (s2, c2) = score_username("ian_thorpe", "www.instagram.com", &terms, &r2);
        assert!(s2 >= 3, "a real firstname_lastname handle stays PROBABLE: {s2}");
        assert_eq!(c2, confidence::MEDIUM_HIGH);
    }

    #[test]
    fn an_org_title_span_yields_one_bounded_org_without_the_person_or_boilerplate() {
        // REQ-SEARCH-010, live scan 7258fc07 ("Ian Thorpe"): one LinkedIn title
        // minted 'Ian Thorpe - Thorpedo Inc' AND 'Ian Thorpe - Thorpedo Inc.',
        // and namesakes' employers were admitted because the person's name,
        // glued onto the company, carried the subject term.
        let terms = vec!["ian".to_string(), "thorpe".to_string()];
        assert_eq!(
            extract_organisations_from_text("Ian Thorpe - Thorpedo Inc. | LinkedIn", &terms),
            vec!["Thorpedo Inc.".to_string()],
            "one org, no person prefix, no suffix-variant duplicate"
        );
        // A namesake's employer carries no subject term once the person prefix
        // is cut off.
        for title in [
            "Ian Thorpe - Commercial Portfolio Management Pty Ltd | LinkedIn",
            "Megan Thorpe Email & Phone Number | Covalent Lithium Pty Ltd",
            "Ian Thorpe – SEL UK Ltd",
            "Carol Thorpe — Perspective Financial Group Ltd",
            "Ian Thorpe › Some Other Co.",
        ] {
            assert!(
                extract_organisations_from_text(title, &terms).is_empty(),
                "{title:?} -> {:?}",
                extract_organisations_from_text(title, &terms)
            );
        }
        // Every dotted/undotted and nested pair collapses to one org.
        let t = vec!["acme".to_string()];
        assert_eq!(
            extract_organisations_from_text("Acme Corp. - Home", &t),
            vec!["Acme Corp.".to_string()]
        );
        assert_eq!(
            extract_organisations_from_text("Acme Holdings Pty Ltd", &t),
            vec!["Acme Holdings Pty Ltd".to_string()]
        );
        assert_eq!(
            extract_organisations_from_text("Acme Holdings Pty. Ltd. | Acme Pty Limited", &t),
            vec!["Acme Holdings Pty. Ltd.".to_string(), "Acme Pty Limited".to_string()]
        );
        // Two companies in one run of prose are two spans, never one glued org.
        let two = extract_organisations_from_text("Beta Ltd and Acme Pty Ltd", &t);
        assert!(!two.iter().any(|o| o.starts_with("Beta")), "{two:?}");
        assert_eq!(
            extract_organisations_from_text("Beta Ltd, Acme Pty Ltd", &t),
            vec!["Acme Pty Ltd".to_string()]
        );
    }

    #[test]
    fn an_org_in_snippet_prose_is_its_capitalised_name_run_matched_at_word_starts() {
        // REQ-SEARCH-013: prose carries no title separator, so the separator
        // bound alone let the person's name — and the title/snippet join — glue
        // onto the company, and the person's name then passed the term filter.
        let terms = vec!["ian".to_string(), "thorpe".to_string()];
        let glued = "Ian Thorpe | LinkedIn Ian Thorpe is the managing director of \
                     Harbour Holdings Pty Ltd";
        assert!(
            extract_organisations_from_text(glued, &terms).is_empty(),
            "{:?}",
            extract_organisations_from_text(glued, &terms)
        );
        // A given name inside another word is not the subject's term.
        let australian = "Australian Unity Limited - Ian Thorpe";
        assert!(
            extract_organisations_from_text(australian, &terms).is_empty(),
            "{:?}",
            extract_organisations_from_text(australian, &terms)
        );
        // The company's own name still carries the term, in prose too.
        assert_eq!(
            extract_organisations_from_text(
                "Ian Thorpe is a director of Thorpe Family Holdings Pty Ltd since 2001",
                &terms
            ),
            vec!["Thorpe Family Holdings Pty Ltd".to_string()]
        );
        // Connectors between capitalised words stay inside the name.
        assert_eq!(
            extract_organisations_from_text(
                "she banks with Bank of Queensland Limited",
                &["queensland".to_string()]
            ),
            vec!["Bank of Queensland Limited".to_string()]
        );
        // An all-caps run has no lowercase end: the 60-byte floor still bounds
        // it, and a word the floor cuts through is not taken.
        let caps = "IAN THORPE IS THE MANAGING DIRECTOR OF THE HARBOUR THORPE HOLDINGS PTY LTD";
        for org in extract_organisations_from_text(caps, &terms) {
            assert!(org.len() <= 60 + " PTY LTD".len(), "{org:?}");
            assert!(caps.contains(&format!(" {org}")), "{org:?} starts mid-word");
        }
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

    /// REQ-SEARCH-ADDR-001: a people-search listing title "Name, State" is not a
    /// locality. The extractor itself stays text-only; the name-scan caller
    /// drops these with `surname_bearer_locality`.
    #[test]
    fn a_people_search_listing_title_is_not_a_locality() {
        let listed = extract_addresses_from_text(
            "Ian Thorpe, North Carolina (NC) | Spokeo — Bill Thorpe, Florida",
        );
        assert!(listed.iter().any(|a| a == "Ian Thorpe, North Carolina"), "{listed:?}");
        for person in ["Ian Thorpe, North Carolina", "Bill Thorpe, Florida"] {
            assert!(surname_bearer_locality(person, "Ian Thorpe").is_none(), "{person}");
        }
        // Real places survive: a suburb that IS the surname, a place-prefixed
        // name, an unrelated city, and a comma-free string.
        for place in [
            "Lawnton, QLD",
            "Port Thorpe, Tasmania",
            "Mount Thorpe, QLD",
            "Houston, Texas",
            "Thorpe",
        ] {
            assert!(surname_bearer_locality(place, "Ian Thorpe").is_some_and(|a| a == place), "{place}");
        }
        assert!(surname_bearer_locality("Lawnton, QLD", "Ian Lawnton").is_some_and(|a| a == "Lawnton, QLD"));
        // `person_surname` reads a diacritic-folded surname
        // (REQ-IDENTITY-GATE-003); the listing prints the accented one.
        assert!(surname_bearer_locality("Bich Nguyễn, Hà Nội", "Lan Nguyen").is_none());
    }

    /// REQ-SEARCH-ADDR-003: the REQ-SEARCH-ADDR-002 rule dropped every
    /// multi-word city with the surname after its first word, losing a suburb
    /// that carries the surname mid-name and a statement locating the bearer.
    /// A place suffix after the surname is a place; `in <Place>` after it is
    /// the place; anything else (a facility, a trade) is a thing named after
    /// a surname-bearer.
    #[test]
    fn a_suburb_carrying_the_surname_and_a_located_bearer_are_localities() {
        let found = extract_addresses_from_text("Our offices in Box Hill North, Victoria");
        assert!(
            found.iter().any(|a| a == "Box Hill North, Victoria"),
            "input pinned: {found:?}"
        );
        for place in ["Box Hill North, Victoria", "Box Hill South, VIC"] {
            assert_eq!(surname_bearer_locality(place, "Ian Hill").as_deref(), Some(place));
        }
        // REQ-SEARCH-ADDR-002's stated loss, closed: a lake named for a park.
        assert_eq!(
            surname_bearer_locality("Albert Park Lake, VIC", "Ian Park").as_deref(),
            Some("Albert Park Lake, VIC")
        );
        let found = extract_addresses_from_text(
            "Swim coach, Ian Thorpe in Ultimo, New South Wales, Australia",
        );
        let located = "Ian Thorpe in Ultimo, New South Wales";
        assert!(found.iter().any(|a| a == located), "input pinned: {found:?}");
        assert_eq!(
            surname_bearer_locality(located, "Ian Thorpe").as_deref(),
            Some("Ultimo, New South Wales")
        );
        // Still dropped: a listing title, a venue, a business, and a bare
        // "in" with no place after it.
        for bearer in [
            "Ian Thorpe, North Carolina",
            "Ian Thorpe Aquatic Centre in Ultimo, New South Wales",
            "Jamie Thorpe Plumbing, QLD",
            "Ian Thorpe in, NSW",
        ] {
            assert_eq!(surname_bearer_locality(bearer, "Ian Thorpe"), None, "{bearer}");
        }
    }

    /// REQ-SEARCH-ADDR-004: `"<Given> <Surname> in <Place>"` locates the
    /// subject only when `<Given> <Surname>` names the subject. A people-search
    /// snippet that names "Ian Thorpe" passes the per-result gate and can list
    /// his relatives; REQ-SEARCH-ADDR-003 read the surname alone, so "Carol
    /// Thorpe in Mosman" became the Address "Mosman, NSW" on Ian's scan.
    #[test]
    fn a_relative_located_in_a_place_does_not_locate_the_subject() {
        let found = extract_addresses_from_text(
            "Ian Thorpe, age 45 - relatives, Carol Thorpe in Mosman, NSW",
        );
        let relative = "Carol Thorpe in Mosman, NSW";
        assert!(found.iter().any(|a| a == relative), "input pinned: {found:?}");
        for bearer in [
            relative,
            "Relatives: Bill Thorpe; Carol Thorpe in Mosman, NSW",
            // The subject named earlier in the segment is not this bearer.
            "Ian Thorpe's sister Carol Thorpe in Mosman, NSW",
            "Ian and Carol Thorpe in Mosman, NSW",
            // A bare title names nobody in particular.
            "Mr Thorpe in Mosman, NSW",
        ] {
            assert_eq!(surname_bearer_locality(bearer, "Ian Thorpe"), None, "{bearer}");
        }
        // The subject himself, however the name before the surname is written.
        for (located, subject) in [
            ("Ian Thorpe in Mosman, NSW", "Ian Thorpe"),
            ("Contact Ian Thorpe in Mosman, NSW", "Ian Thorpe"),
            ("I. Thorpe in Mosman, NSW", "Ian Thorpe"),
            ("Ian James Thorpe in Mosman, NSW", "Ian James Thorpe"),
            ("Carol Thorpe in Mosman, NSW", "Carol Thorpe"),
        ] {
            assert_eq!(
                surname_bearer_locality(located, subject).as_deref(),
                Some("Mosman, NSW"),
                "{located} for {subject}"
            );
        }
        // A mononym subject has no surname to read: every address is kept.
        assert_eq!(
            surname_bearer_locality("Carol Thorpe in Mosman, NSW", "Thorpe").as_deref(),
            Some("Carol Thorpe in Mosman, NSW")
        );
    }

    /// REQ-SEARCH-ADDR-002: a venue named after a surname-bearer is not a
    /// locality. The verbatim LinkedIn job title from scan 7258fc07 yielded the
    /// Address "Ian Thorpe Aquatic Centre in Ultimo, New South Wales"; the
    /// surname sits mid-segment, so the old last-word test kept it and Photon's
    /// (correct) geocode of the pool became the headline location fix.
    #[test]
    fn a_venue_named_after_a_surname_bearer_is_not_a_locality() {
        let found = extract_addresses_from_text(
            "Workforce Australia for Individuals hiring Exercise Physiologist NSW, \
             Ian Thorpe Aquatic Centre in Ultimo, New South Wales, Australia | LinkedIn",
        );
        let venue = "Ian Thorpe Aquatic Centre in Ultimo, New South Wales";
        assert!(found.iter().any(|a| a == venue), "input pinned: {found:?}");
        assert!(surname_bearer_locality(venue, "Ian Thorpe").is_none());
        // Places survive: a one-word suburb that is the surname, a place-word
        // prefix, a place that STARTS with the surname, an unrelated city.
        for place in [
            "Lawnton, QLD",
            "Port Thorpe, Tasmania",
            "Mount Thorpe, QLD",
            "Thorpe Bay, Essex",
            "Houston, Texas",
        ] {
            assert!(surname_bearer_locality(place, "Ian Thorpe").is_some_and(|a| a == place), "{place}");
        }
    }

