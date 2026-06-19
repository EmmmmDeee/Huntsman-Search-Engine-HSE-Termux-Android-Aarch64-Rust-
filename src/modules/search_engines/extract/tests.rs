use super::*;

    /// The recycler must respect the module's hard fetch deadline: with a deadline
    /// already in the past it issues NO requests and adds NO entities, so it can
    /// never overrun the engine's kill timeout (which would discard the whole
    /// result, primary findings included — the live "timeout → 0 entities" bug).
    #[tokio::test]
    async fn recycle_entities_respects_a_past_deadline() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::module::{ModuleContext, ModuleResult};

        let mut result = ModuleResult::new();
        // A ≥0.40 entity that would otherwise trigger recycle re-queries.
        result.push(Entity::new(
            EntityKind::Email,
            "jane.doe@example.com",
            0.60,
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
            proxy_pool: Default::default(),
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
