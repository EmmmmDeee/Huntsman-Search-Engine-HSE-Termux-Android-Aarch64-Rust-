use super::*;

    #[test]
    fn extract_coords_from_text_reads_marked_forms_only() {
        // Positive: an unambiguous geo: URI and a Plus Code in snippet prose
        // each yield exactly one coordinate.
        let geo = extract_coords_from_text("Meet here geo:-27.4766,153.0166;u=35 tonight");
        assert_eq!(geo.len(), 1, "geo: URI must yield one coordinate: {geo:?}");
        assert!(geo[0].starts_with("-27.476"), "got {geo:?}");

        let plus = extract_coords_from_text("Location code 4RRH46RW+RH7 near the CBD");
        assert_eq!(plus.len(), 1, "Plus Code must yield one coordinate: {plus:?}");

        // NEGATIVE (the whole point of the conservative design): ordinary prose
        // numbers that would parse as an in-range decimal pair must NOT fabricate
        // a coordinate.
        for prose in [
            "The item is $33.50, 151.20 including tax",
            "Upgrade to version 1.5, 2.3 today",
            "Call 0410 959 140 or visit us",
            "Scores were 12.5, 45.9 across the board",
            "Ranked 4.5, 9.8 out of ten",
        ] {
            assert!(
                extract_coords_from_text(prose).is_empty(),
                "prose must not fabricate a coordinate: {prose:?} -> {:?}",
                extract_coords_from_text(prose)
            );
        }

        // Same point twice ⇒ deduped.
        let dup = extract_coords_from_text("geo:-27.4766,153.0166 and again geo:-27.4766,153.0166");
        assert_eq!(dup.len(), 1, "identical points must dedup: {dup:?}");
    }

    /// Non-ASCII snippet text must not panic. The `geo:` prefix test indexes the
    /// candidate token by BYTE, so a token whose 4th byte falls inside a
    /// multi-byte character used to split it and panic — observed live as
    /// `end byte index 4 is not a char boundary; it is inside 'í' (bytes 3..5)`,
    /// which took the whole `search_engines` module down for that target (the
    /// engine's `catch_unwind` contained it, but the module returned nothing).
    ///
    /// Accented words are ordinary in real search snippets, so this is routine
    /// input, not a crafted edge case.
    #[test]
    fn extract_coords_from_text_survives_multibyte_tokens() {
        // Each token places a multi-byte char across the byte-4 boundary the
        // `geo:` check slices at ("Cru" is 3 bytes, 'í' spans bytes 3..5).
        for text in [
            "Cruíz",
            "Foo Cruíz bar",
            "José",
            "señor",
            "naïve café",
            "Ruíz-Menéndez lives in Córdoba",
            // Multi-byte at the very start, and a 4-byte codepoint.
            "ñandú",
            "😀abc",
            "abc😀def",
            // Shorter-than-prefix tokens must stay safe too.
            "í",
            "aí",
            "abí",
        ] {
            let got = extract_coords_from_text(text);
            assert!(
                got.is_empty(),
                "non-coordinate prose must yield nothing: {text:?} -> {got:?}"
            );
        }

        // A real geo: URI still parses when multi-byte text surrounds it — the
        // fix must not cost the positive case.
        let mixed = extract_coords_from_text("Café Cruíz geo:-27.4766,153.0166 señor");
        assert_eq!(mixed.len(), 1, "geo: URI beside multibyte text: {mixed:?}");
        assert!(mixed[0].starts_with("-27.476"), "got {mixed:?}");

        // Case-insensitivity of the `geo:` scheme is preserved.
        let upper = extract_coords_from_text("GEO:-27.4766,153.0166");
        assert_eq!(upper.len(), 1, "scheme is case-insensitive: {upper:?}");
    }

    #[test]
    fn extract_coords_from_text_rejects_null_island() {
        // `geo:0,0` parses cleanly as an in-range decimal pair — coords::parse
        // deliberately keeps it (it's a legitimate literal a page could state) —
        // but this call site turns the result straight into a Coordinates
        // entity, so it must apply the output-side null-island/range gate
        // itself. A scraped snippet's placeholder/garbage geo: URI must not
        // fabricate a null-island finding.
        let null_island = extract_coords_from_text("Tracker default geo:0,0;u=1 unset");
        assert!(
            null_island.is_empty(),
            "geo:0,0 must not yield a Coordinates entity: {null_island:?}"
        );
        // A real point elsewhere in the same text still comes through.
        let mixed =
            extract_coords_from_text("Bad default geo:0,0 but also geo:-27.4766,153.0166 here");
        assert_eq!(mixed.len(), 1, "only the valid point should survive: {mixed:?}");
        assert!(mixed[0].starts_with("-27.476"), "got {mixed:?}");
    }

    /// The recycler must respect the module's hard fetch deadline: with a deadline
    /// already in the past it issues NO requests and adds NO entities, so it can
    /// never overrun the engine's kill timeout (which would discard the whole
    /// result, primary findings included — the live "timeout → 0 entities" bug).
    #[tokio::test]
    async fn recycle_entities_respects_a_past_deadline() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::module::{ModuleContext, ModuleResult};

        let mut result = ModuleResult::new();
        // A ≥confidence::LOW entity that would otherwise trigger recycle re-queries.
        result.push(Entity::new(
            EntityKind::Email,
            "jane.doe@example.com",
            confidence::MEDIUM_PLUS,
            "scan",
        ));
        let before = result.entities.len();

        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        let ctx = ModuleContext {
            scan_id: "scan".into(),
            bus,
            http: reqwest::Client::new(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
        };
        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);

        recycle_entities(&ctx, &mut result, &HashSet::new(), &[], past).await;

        assert_eq!(
            result.entities.len(),
            before,
            "a past deadline short-circuits the recycler before any fetch"
        );
    }

    fn sr(title: &str, snippet: &str) -> SearchResult {
        SearchResult {
            url: "https://example.com/x".to_string(),
            title: title.to_string(),
            snippet: snippet.to_string(),
            engine: "test",
            query: "q".to_string(),
        }
    }

    fn names(results: &[SearchResult], target: &Target) -> Vec<String> {
        extract_family_names(results, target)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn fullname_finds_same_surname_different_first_name() {
        let target = Target::new(TargetKind::FullName, "John Smith");
        let results = [sr("Jane Smith and John Smith", "live in Brisbane")];
        // Jane Smith surfaced; the target John Smith is excluded.
        assert_eq!(names(&results, &target), vec!["Jane Smith"]);
    }

    #[test]
    fn email_initial_dot_surname_now_matches() {
        // Regression: `j.smith@…` must derive the surname `smith`. Before the
        // leading-separator strip, lastname was ".smith" and matched nothing.
        let target = Target::new(TargetKind::Email, "j.smith@example.com");
        let results = [sr("Robert Smith profile", "")];
        assert_eq!(names(&results, &target), vec!["Robert Smith"]);
    }

    #[test]
    fn email_initialsurname_without_separator_still_matches() {
        let target = Target::new(TargetKind::Email, "jsmith@example.com");
        let results = [sr("Robert Smith", "")];
        assert_eq!(names(&results, &target), vec!["Robert Smith"]);
    }

    #[test]
    fn short_surname_is_rejected() {
        // Surname < 4 chars (here "fox") yields nothing — too noisy to pivot on.
        let target = Target::new(TargetKind::FullName, "John Fox");
        let results = [sr("Jane Fox", "")];
        assert!(names(&results, &target).is_empty());
    }

    #[test]
    fn deduplicates_and_titlecases_multibyte_surname() {
        // "Müller" surname must not panic (char-wise title-casing) and repeats
        // collapse to one.
        let target = Target::new(TargetKind::FullName, "Hans Müller");
        let results = [
            sr("anna müller", "anna müller again"),
            sr("anna müller", ""),
        ];
        assert_eq!(names(&results, &target), vec!["Anna Müller"]);
    }

    #[test]
    fn non_fullname_non_email_kinds_yield_nothing() {
        let target = Target::new(TargetKind::Username, "smithy");
        let results = [sr("Jane Smith", "")];
        assert!(extract_family_names(&results, &target).is_empty());
    }

    fn social_sr(username: &str, query: &str) -> SearchResult {
        SearchResult {
            url: format!("https://twitter.com/{username}"),
            title: format!("{username} on Twitter"),
            snippet: format!("{username} tweets"),
            engine: "test",
            query: query.to_string(),
        }
    }

    #[test]
    fn extract_username_pivots_emits_scored_social_profiles() {
        // "john" appears inside path handle "johndoe" → Signal 1 (+3) → emitted.
        // The handle differs from target "john" so the equality guard is bypassed.
        let target = Target::new(TargetKind::Username, "john");
        let results = [social_sr("johndoe", "john")];
        let pivots = extract_username_pivots(&results, &target);
        assert!(
            pivots.iter().any(|p| p.contains("johndoe")),
            "johndoe profile must be returned as a pivot: {pivots:?}"
        );
    }

    #[test]
    fn extract_username_pivots_skips_non_social_hosts() {
        // Same path handle but on a non-social host → skipped.
        let target = Target::new(TargetKind::Username, "alice");
        let results = [SearchResult {
            url: "https://example.com/alice".to_string(),
            title: "Alice".to_string(),
            snippet: "alice".to_string(),
            engine: "test",
            query: "alice".to_string(),
        }];
        let pivots = extract_username_pivots(&results, &target);
        assert!(pivots.is_empty(), "non-social host must be skipped: {pivots:?}");
    }

    // ── extract_display_names_from_titles ────────────────────────────────────

    fn instagram_sr(username: &str, display: &str, query: &str) -> SearchResult {
        SearchResult {
            url: format!("https://instagram.com/{username}"),
            title: format!("{display} (@{username}) • Instagram Photos and Videos"),
            snippet: format!("{username} photos"),
            engine: "test",
            query: query.to_string(),
        }
    }

    #[test]
    fn display_name_extracted_from_instagram_title() {
        let target = Target::new(TargetKind::Username, "ryno23_");
        let results = [instagram_sr("ryno23_", "Ryne Manka", "ryno23_")];
        let entities = extract_display_names_from_titles(&results, &target, "s");
        assert_eq!(entities.len(), 1, "should extract one Person entity");
        let e = &entities[0];
        assert_eq!(e.kind, EntityKind::Person);
        assert_eq!(e.value, "Ryne Manka");
        assert!((e.confidence - confidence::HIGH).abs() < 1e-9);
        assert!(e.has_tag("social-name"));
        assert!(e.has_tag(crate::core::tags::SEARCH_DISCOVERED));
        assert!(e.has_tag("derived"));
    }

    #[test]
    fn display_name_rejects_non_social_host() {
        let target = Target::new(TargetKind::Username, "ryno23_");
        let results = [SearchResult {
            url: "https://example.com/ryno23_".to_string(),
            title: "Ryne Manka (@ryno23_) • Photos".to_string(),
            snippet: "ryno23_".to_string(),
            engine: "test",
            query: "ryno23_".to_string(),
        }];
        let entities = extract_display_names_from_titles(&results, &target, "s");
        assert!(
            entities.is_empty(),
            "non-social host must not produce Person entities"
        );
    }

    #[test]
    fn display_name_rejects_allcaps_name() {
        // "ZMKCR (@ZMKCR)" — all-uppercase display name is a gamertag, not a real name.
        let target = Target::new(TargetKind::Username, "zmkcr");
        let results = [SearchResult {
            url: "https://x.com/ZMKCR".to_string(),
            title: "ZMKCR (@ZMKCR) / X Posts".to_string(),
            snippet: "zmkcr tweets".to_string(),
            engine: "test",
            query: "zmkcr".to_string(),
        }];
        let entities = extract_display_names_from_titles(&results, &target, "s");
        assert!(
            entities.is_empty(),
            "all-caps display name must be rejected: got {entities:?}"
        );
    }

    #[test]
    fn display_name_deduplicates_across_results() {
        let target = Target::new(TargetKind::Username, "ryno23_");
        let results = [
            instagram_sr("ryno23_", "Ryne Manka", "ryno23_"),
            instagram_sr("ryno23_", "Ryne Manka", "ryno23_"),
        ];
        let entities = extract_display_names_from_titles(&results, &target, "s");
        assert_eq!(entities.len(), 1, "duplicate display name must be collapsed to one entity");
    }

    #[test]
    fn display_name_requires_seed_term_in_title() {
        // Title mentions a real name + handle but the seed term "alice" is absent.
        let target = Target::new(TargetKind::Username, "alice");
        let results = [SearchResult {
            url: "https://instagram.com/ryno23_".to_string(),
            title: "Ryne Manka (@ryno23_) • Instagram Photos".to_string(),
            snippet: "photos".to_string(),
            engine: "test",
            query: "alice".to_string(),
        }];
        let entities = extract_display_names_from_titles(&results, &target, "s");
        assert!(
            entities.is_empty(),
            "no seed term match → should emit nothing"
        );
    }

    // ── extract_bio_aggregator_urls ──────────────────────────────────────────

    #[test]
    fn bio_aggregator_signal1_url_is_linktr_ee() {
        let target = Target::new(TargetKind::Username, "ryno23");
        let results = [SearchResult {
            url: "https://linktr.ee/ryno23".to_string(),
            title: "ryno23 | linktree".to_string(),
            snippet: "all links for ryno23".to_string(),
            engine: "test",
            query: "ryno23".to_string(),
        }];
        let entities = extract_bio_aggregator_urls(&results, &target, "s");
        assert_eq!(entities.len(), 1);
        let e = &entities[0];
        assert_eq!(e.kind, EntityKind::Url);
        assert_eq!(e.value, "https://linktr.ee/ryno23");
        assert!((e.confidence - confidence::HIGH_PLUS).abs() < 1e-9, "bio aggregator conf should be confidence::HIGH_PLUS");
        assert!(e.has_tag("bio-aggregator"));
        assert!(e.has_tag("social-profile"));
        assert!(e.has_tag(crate::core::tags::SEARCH_DISCOVERED));
    }

    #[test]
    fn bio_aggregator_signal1_telegram_link() {
        let target = Target::new(TargetKind::Username, "ryno23");
        let results = [SearchResult {
            url: "https://t.me/ryno23".to_string(),
            title: "ryno23 Telegram channel".to_string(),
            snippet: "join ryno23 on telegram".to_string(),
            engine: "test",
            query: "ryno23".to_string(),
        }];
        let entities = extract_bio_aggregator_urls(&results, &target, "s");
        assert_eq!(entities.len(), 1);
        let e = &entities[0];
        assert!((e.confidence - confidence::HIGH).abs() < 1e-9, "messaging conf should be confidence::HIGH");
        assert!(e.has_tag("messaging-profile"));
        assert!(!e.has_tag("bio-aggregator"));
    }

    #[test]
    fn bio_aggregator_signal2_url_in_snippet_text() {
        let target = Target::new(TargetKind::Username, "ryno23");
        let results = [SearchResult {
            url: "https://reddit.com/r/gaming/comments/abc".to_string(),
            title: "Ryno23 gaming links".to_string(),
            snippet: "ryno23 posts all links at linktr.ee/ryno23 for easy access".to_string(),
            engine: "test",
            query: "ryno23".to_string(),
        }];
        let entities = extract_bio_aggregator_urls(&results, &target, "s");
        assert_eq!(entities.len(), 1, "bio URL from snippet text should be emitted");
        let e = &entities[0];
        assert_eq!(e.value, "https://linktr.ee/ryno23");
        assert!((e.confidence - confidence::HIGH).abs() < 1e-9, "text signal conf should be confidence::HIGH");
        assert!(e.has_tag("bio-aggregator"));
    }

    #[test]
    fn bio_aggregator_deduplicates_signal1_and_signal2() {
        // URL is both the result URL (signal 1) and appears in its own snippet (signal 2).
        let target = Target::new(TargetKind::Username, "ryno23");
        let results = [SearchResult {
            url: "https://linktr.ee/ryno23".to_string(),
            title: "ryno23 | linktree".to_string(),
            snippet: "linktr.ee/ryno23 — all social links".to_string(),
            engine: "test",
            query: "ryno23".to_string(),
        }];
        let entities = extract_bio_aggregator_urls(&results, &target, "s");
        assert_eq!(entities.len(), 1, "same URL from both signals must collapse to one entity");
    }

    #[test]
    fn bio_aggregator_requires_seed_term() {
        // Bio aggregator URL present but seed term absent from title+snippet → skipped.
        let target = Target::new(TargetKind::Username, "xyzuniquexyz");
        let results = [SearchResult {
            url: "https://linktr.ee/someoneelse".to_string(),
            title: "someoneelse links".to_string(),
            snippet: "random unrelated content here".to_string(),
            engine: "test",
            query: "xyzuniquexyz".to_string(),
        }];
        let entities = extract_bio_aggregator_urls(&results, &target, "s");
        assert!(
            entities.is_empty(),
            "no seed term match → should emit nothing"
        );
    }

/// REQ-SEARCH-002 (the recycler): a recycled result is about the entity its
/// query asked for only when it names that entity. The engines answered
/// `"qx82vtnrmpaw" address OR location OR city` with Microsoft's Wikipedia
/// page and the recycler minted "Redmond" as the handle's address; the same
/// text naming the handle still yields it.
#[test]
fn a_recycled_result_that_never_names_the_entity_its_query_asked_about_mines_nothing() {
    let query = "\"qx82vtnrmpaw\" address OR location OR city";
    assert_eq!(recycled_subject(query), Some("qx82vtnrmpaw"));
    assert_eq!(recycled_subject("no quoted term"), None);
    assert_eq!(recycled_subject("\"\" address"), None);

    let existing = ModuleResult::new();
    let stranger = SearchResult {
        url: "https://en.wikipedia.org/wiki/Microsoft".to_string(),
        title: "Microsoft - Wikipedia".to_string(),
        snippet: "Microsoft Corporation is an American multinational technology company \
                  headquartered in Redmond, Washington."
            .to_string(),
        engine: "bing",
        query: query.to_string(),
    };
    assert!(!recycled_result_names_its_subject(&stranger));
    let mined = mine_recycled_results(&existing, &[stranger], "scan");
    assert!(
        mined.is_empty(),
        "a result that never names the entity mines nothing: {:?}",
        mined
            .iter()
            .map(|e| (e.kind.clone(), e.value.clone()))
            .collect::<Vec<_>>()
    );

    let named = SearchResult {
        url: "https://example.com/people/qx82vtnrmpaw".to_string(),
        title: "qx82vtnrmpaw".to_string(),
        snippet: "qx82vtnrmpaw is a technology worker headquartered in Redmond, Washington."
            .to_string(),
        engine: "bing",
        query: query.to_string(),
    };
    assert!(recycled_result_names_its_subject(&named));
    let mined = mine_recycled_results(&existing, &[named], "scan");
    assert!(
        mined
            .iter()
            .any(|e| e.kind == EntityKind::Address && e.value.to_lowercase().contains("redmond")),
        "the same text in a result that names the entity yields the address: {:?}",
        mined
            .iter()
            .map(|e| (e.kind.clone(), e.value.clone()))
            .collect::<Vec<_>>()
    );
}

/// REQ-SEARCH-003 (the recycler, contract boundary): the recycled subject is
/// named only as a whole word, never as a raw substring of a longer one. A
/// three-character handle `abc` recycled through the engines and answered with
/// a page about `abcnews.com` embedded `abc` — `hay.contains("abc")` read the
/// longer host as naming the handle and minted its address, the same
/// false-attribution class REQ-SEARCH-002 gated, narrowed to a substring
/// collision. This pins the gate (`recycled_result_names_its_subject`) to the
/// boundary-aware predicate at the call site, not merely the helper in
/// isolation: it fails if the recycler is reverted to `contains`.
#[test]
fn a_recycled_subject_embedded_in_a_longer_word_is_not_named_by_it() {
    let query = "\"abc\" address OR location OR city";
    assert_eq!(recycled_subject(query), Some("abc"));

    let existing = ModuleResult::new();
    // `abcnews` embeds `abc`; the page is about the broadcaster, not the handle.
    // The handle appears only inside `abcnews.com` (snippet and URL), never as a
    // standalone word — the substring collision.
    let collision = SearchResult {
        url: "https://abcnews.com/tech".to_string(),
        title: "Technology desk".to_string(),
        snippet: "abcnews.com is headquartered in Redmond, Washington.".to_string(),
        engine: "bing",
        query: query.to_string(),
    };
    assert!(
        !recycled_result_names_its_subject(&collision),
        "a longer word embedding the handle does not name it"
    );
    let mined = mine_recycled_results(&existing, &[collision], "scan");
    assert!(
        mined.is_empty(),
        "a substring collision mines nothing: {:?}",
        mined
            .iter()
            .map(|e| (e.kind.clone(), e.value.clone()))
            .collect::<Vec<_>>()
    );

    // The same body in a result that names the handle as a whole word still
    // mines — the gate narrowed the false match, it did not close the real one.
    let named = SearchResult {
        url: "https://example.com/u/abc".to_string(),
        title: "abc".to_string(),
        snippet: "abc is a technology worker headquartered in Redmond, Washington.".to_string(),
        engine: "bing",
        query: query.to_string(),
    };
    assert!(recycled_result_names_its_subject(&named));
    let mined = mine_recycled_results(&existing, &[named], "scan");
    assert!(
        mined
            .iter()
            .any(|e| e.kind == EntityKind::Address && e.value.to_lowercase().contains("redmond")),
        "a result that names the handle as a word still yields the address: {:?}",
        mined
            .iter()
            .map(|e| (e.kind.clone(), e.value.clone()))
            .collect::<Vec<_>>()
    );
}
