use crate::core::confidence;
use super::*;
    use std::collections::HashMap;

    fn ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: HashMap::default(),
            cancel: crate::core::cancel::CancelHandle::new(),
        }
    }

    #[test]
    fn separator_swaps_cover_all_forms() {
        let v = UsernameVariants::variants("john.doe");
        assert!(v.contains(&"john_doe".to_string()));
        assert!(v.contains(&"john-doe".to_string()));
        assert!(v.contains(&"johndoe".to_string()));
        // never emits the seed itself
        assert!(!v.contains(&"john.doe".to_string()));
    }

    #[test]
    fn strips_trailing_digits() {
        assert_eq!(UsernameVariants::variants("jdoe1990"), vec!["jdoe"]);
        assert_eq!(UsernameVariants::variants("jdoe123"), vec!["jdoe"]);
    }

    #[test]
    fn strips_separator_bounded_vanity_tokens() {
        assert!(UsernameVariants::variants("the_real_jdoe").contains(&"jdoe".to_string()));
        assert!(UsernameVariants::variants("jdoe_official").contains(&"jdoe".to_string()));
        // Vanity tokens AND a trailing numeric disambiguator both stripped →
        // the bare canonical handle is reached.
        assert!(UsernameVariants::variants("the_real_jdoe1990").contains(&"jdoe".to_string()));
        // leading + trailing decoration and a numeric tail all stripped
        let v = UsernameVariants::variants("the.john.doe.1990");
        assert!(v.contains(&"johndoe".to_string()));
        assert!(v.contains(&"john_doe".to_string()));
    }

    #[test]
    fn plain_handle_yields_nothing() {
        // No separator, no digits, no vanity → no defensible transformation.
        assert!(UsernameVariants::variants("jdoe").is_empty());
        assert!(UsernameVariants::variants("alice").is_empty());
    }

    #[test]
    fn rejects_short_and_placeholder_handles() {
        assert!(UsernameVariants::variants("ab").is_empty());
        assert!(UsernameVariants::variants("a.b").is_empty()); // collapses to "ab" (len 2)
        assert!(UsernameVariants::variants("admin").is_empty());
        assert!(UsernameVariants::variants("test").is_empty());
    }

    #[test]
    fn output_is_bounded_sorted_and_deduped() {
        let v = UsernameVariants::variants("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p");
        assert!(v.len() <= MAX_VARIANTS);
        // sorted + deduped (BTreeSet invariant)
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(v, sorted);
    }

    #[tokio::test]
    async fn process_emits_candidate_usernames() {
        let t = Target::new(TargetKind::Username, "john.doe");
        let r = UsernameVariants.process(&t, &ctx()).await.unwrap();
        assert!(!r.entities.is_empty());
        for e in &r.entities {
            assert_eq!(e.kind, EntityKind::Username);
            assert!((e.confidence - VARIANT_CONF).abs() < 1e-9);
            assert!(e.confidence < confidence::MEDIUM, "must stay below the expansion floor");
            assert!(e.has_tag("variant"));
            assert!(e.has_tag("candidate"));
            assert_eq!(e.evidence[0].source, SRC);
        }
    }

    #[tokio::test]
    async fn process_emits_nothing_for_plain_handle() {
        let t = Target::new(TargetKind::Username, "jdoe");
        let r = UsernameVariants.process(&t, &ctx()).await.unwrap();
        assert!(r.entities.is_empty());
    }

    #[test]
    fn accepts_username_and_email() {
        assert!(UsernameVariants.accepts(&Target::new(TargetKind::Username, "x")));
        // Email seeds are now accepted: local-part variants derived at depth=0.
        assert!(UsernameVariants.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!UsernameVariants.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn is_passive_and_social() {
        assert!(UsernameVariants.is_passive());
        assert_eq!(UsernameVariants.category(), ModuleCategory::Social);
    }

    #[test]
    fn is_trailing_decorator_matches_vanity_tokens_and_digits() {
        // All-digit suffixes and known vanity tokens are decorators.
        assert!(is_trailing_decorator("1990"));
        assert!(is_trailing_decorator("007"));
        assert!(is_trailing_decorator("real"));
        assert!(is_trailing_decorator("official"));
        // Mixed and pure alpha non-vanity tokens are not decorators.
        assert!(!is_trailing_decorator("alice"));
        assert!(!is_trailing_decorator("johndoe"));
    }

    #[test]
    fn module_metadata() {
        let m = UsernameVariants;
        assert_eq!(m.name(), "username_variants");
        assert!(!m.description().is_empty());
        assert!(!m.attack_techniques().is_empty());
        assert!(m.produces().contains(&EntityKind::Username));
    }

    #[test]
    fn add_variant_guards_length_and_seed() {
        let seed = "jdoe";
        let mut out: BTreeSet<String> = BTreeSet::new();
        // Too short (< MIN_HANDLE_LEN = 4) → not inserted.
        add_variant(&mut out, seed, "abc".to_string());
        // Exactly the seed → not inserted.
        add_variant(&mut out, seed, "jdoe".to_string());
        // Long enough and distinct → inserted.
        add_variant(&mut out, seed, "janedoe".to_string());
        // 4 chars is the boundary (>= MIN_HANDLE_LEN) → inserted.
        add_variant(&mut out, seed, "jane".to_string());
        assert_eq!(out.len(), 2);
        assert!(out.contains("janedoe"));
        assert!(out.contains("jane"));
        assert!(!out.contains("abc"));
        assert!(!out.contains("jdoe"));
    }
