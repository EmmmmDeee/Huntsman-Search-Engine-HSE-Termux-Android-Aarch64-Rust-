use super::*;

    fn p(s: &str) -> ParsedName {
        parse(s).expect("parses")
    }

    #[test]
    fn parses_two_part_name() {
        let n = p("Jordan Meyers");
        assert_eq!(n.first, "jordan");
        assert_eq!(n.last, "meyers");
        assert_eq!(n.middle, None);
        assert_eq!(n.number, None);
        assert_eq!(n.display_full(), "Jordan Meyers");
    }

    #[test]
    fn parses_three_part_and_year() {
        let n = p("jordan leigh meyers 1987");
        assert_eq!(n.first, "jordan");
        assert_eq!(n.middle.as_deref(), Some("leigh"));
        assert_eq!(n.last, "meyers");
        assert_eq!(n.number.as_deref(), Some("1987"));
        // Display capitalises the leading letter without mangling the rest.
        assert_eq!(n.display_full(), "Jordan Leigh Meyers");
    }

    #[test]
    fn single_token_is_rejected() {
        assert!(parse("Jordan").is_none());
        assert!(parse("   1987   ").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn display_accessors_never_panic_on_degenerate_name() {
        // `ParsedName` has public fields, so a value can be built bypassing
        // `parse()`'s ≥2-word guarantee. The public accessors must degrade to
        // "" instead of panicking (an index/`expect` would abort `hse serve`
        // under panic="abort"). Regression guard for that latent panic.
        let empty = ParsedName {
            first: String::new(),
            middle: None,
            last: String::new(),
            number: None,
            display_words: Vec::new(),
        };
        assert_eq!(empty.display_first(), "");
        assert_eq!(empty.display_last(), "");
        assert_eq!(empty.display_full(), "");

        // Normal parsed names still report the right first/last words.
        let n = p("Jordan Lee Meyers");
        assert_eq!(n.display_first(), "Jordan");
        assert_eq!(n.display_last(), "Meyers");
    }

    #[test]
    fn extract_number_prefers_four_digit_year() {
        // A leading 2-digit run must not shadow the real 4-digit birth year.
        assert_eq!(p("Jordan 12 Meyers 1987").number.as_deref(), Some("1987"));
        // With no 4-digit run present, the first 2–4 digit run is taken.
        assert_eq!(p("Jordan Meyers 71").number.as_deref(), Some("71"));
    }

    #[test]
    fn non_latin_name_yields_pivots_but_no_handles() {
        // Cyrillic ASCII-folds to empty handle tokens: the name still parses so
        // display-name search pivots generate, but username/email permutation
        // (which needs ASCII handles) is empty.
        let n = parse(
            "\u{0418}\u{0432}\u{0430}\u{043d} \u{041f}\u{0435}\u{0442}\u{0440}\u{043e}\u{0432}",
        )
        .expect("non-Latin name parses for pivots");
        assert!(n.first.is_empty() && n.last.is_empty());
        assert!(usernames(&n).is_empty(), "no ASCII handle => no usernames");
        assert!(emails(&n, &default_domains()).is_empty());
        let pivots = pivots(&n, None);
        assert!(!pivots.is_empty(), "display-name pivots still generate");
        // Handle-only platforms are skipped when there is no ASCII handle.
        assert!(
            !pivots
                .iter()
                .any(|pv| pv.platform.starts_with("Instagram")
                    || pv.platform.starts_with("WhatsMyName")),
            "handle-only pivots must be skipped without an ASCII handle"
        );
        assert!(pivots.iter().any(|pv| pv.url.contains("google.com/search")));
    }

    #[test]
    fn latin_diacritics_fold_to_ascii_handles() {
        // Migrant/EU names must derive matchable ASCII handles, not drop the
        // accented letter (José → jose, not jos).
        let n = p("José Müller");
        assert_eq!(n.first, "jose");
        assert_eq!(n.last, "muller");
        assert!(usernames(&n).iter().any(|u| u.handle == "jose.muller"));
        // Display form preserves the original accents for quoted searches.
        assert_eq!(n.display_full(), "José Müller");
    }

    #[test]
    fn folds_punctuation_and_accents() {
        let n = p("José O'Brien-Smith");
        // Apostrophe/hyphen folded out of handle tokens; Latin accent folded to
        // its base letter (é → e) so the handle matches real-world accounts.
        assert_eq!(n.first, "jose");
        assert_eq!(n.last, "obriensmith");
    }

    #[test]
    fn handles_comma_separator() {
        let n = p("Meyers, Jordan");
        assert_eq!(n.first, "meyers");
        assert_eq!(n.last, "jordan");
    }

    #[test]
    fn usernames_cover_namint_core_shapes() {
        let u: Vec<String> = usernames(&p("Jordan Meyers"))
            .into_iter()
            .map(|s| s.handle)
            .collect();
        for want in [
            "jordan.meyers",
            "jordanmeyers",
            "jmeyers",
            "jordan_meyers",
            "jordanm",
            "meyers.jordan",
            "meyersjordan",
            "jordan-meyers",
        ] {
            assert!(u.contains(&want.to_string()), "missing {want}: {u:?}");
        }
    }

    #[test]
    fn usernames_include_middle_blends() {
        let u: Vec<String> = usernames(&p("Jordan Leigh Meyers"))
            .into_iter()
            .map(|s| s.handle)
            .collect();
        assert!(u.contains(&"jordanleighmeyers".to_string()));
        assert!(u.contains(&"jlmeyers".to_string())); // f + m_i + l
        assert!(u.contains(&"jordanlmeyers".to_string())); // f + m_i + l
    }

    #[test]
    fn usernames_include_year_suffix() {
        let u: Vec<String> = usernames(&p("Jordan Meyers 87"))
            .into_iter()
            .map(|s| s.handle)
            .collect();
        assert!(u.iter().any(|h| h.ends_with("87")), "no year suffix: {u:?}");
    }

    #[test]
    fn usernames_bounded_and_deduped() {
        let u = usernames(&p("Ana Bo Ce De Ef"));
        assert!(u.len() <= MAX_USERNAMES);
        let mut set = std::collections::HashSet::new();
        for s in &u {
            assert!(set.insert(s.handle.clone()), "dup: {}", s.handle);
        }
        // Best-first ordering by weight.
        for w in u.windows(2) {
            assert!(w[0].weight >= w[1].weight);
        }
    }

    #[test]
    fn primary_outranks_secondary() {
        let u = usernames(&p("Jordan Meyers"));
        let by = |h: &str| u.iter().find(|s| s.handle == h).map(|s| s.weight);
        assert!(by("jordan.meyers").unwrap() > by("meyers.jordan").unwrap());
    }

    #[test]
    fn derived_usernames_stay_below_the_probable_floor() {
        // Derived handles are unconfirmed guesses — every one must classify as
        // Candidate (c_eff < 0.40) until a discovery module corroborates it, per
        // name_intel's documented "low-confidence candidate" contract. Guards
        // every handle weight (incl. W_PRIMARY) against drifting back over the
        // 0.40 floor, where a pure guess would masquerade as a Probable finding.
        use crate::core::entity::{Classification, Entity, EntityKind};
        let handles = usernames(&p("Jordan Leigh Meyers 1987"));
        let max_w = handles.iter().map(|u| u.weight).fold(0.0_f64, f64::max);
        assert!(
            max_w < 0.40,
            "strongest derived handle weight {max_w} must stay below the 0.40 Probable floor"
        );
        for u in &handles {
            let e = Entity::new(EntityKind::Username, &u.handle, u.weight, "s");
            assert_eq!(
                e.classify(),
                Classification::Candidate,
                "derived handle '{}' (w={}) must stay a Candidate",
                u.handle,
                u.weight
            );
        }
    }

    #[test]
    fn emails_cross_logins_and_domains() {
        let domains = vec!["gmail.com".to_string(), "proton.me".to_string()];
        let e = emails(&p("Jordan Meyers"), &domains);
        assert!(e.contains(&"jordan.meyers@gmail.com".to_string()));
        assert!(e.contains(&"jordan.meyers@proton.me".to_string()));
        assert!(e.iter().all(|a| a.contains('@')));
        assert!(e.len() <= MAX_EMAILS);
    }

    #[test]
    fn emails_rank_common_provider_and_shape_first() {
        // The average person's address is far likelier to be a top shape on a
        // mainstream provider than `first.last` on a rare one. With Gmail and
        // Proton both available, every Gmail guess must outrank the Proton one,
        // and `firstlast@gmail` (a top shape on the modal provider) must beat
        // `first.last@proton` (top shape, long-tail provider).
        let domains = vec!["proton.me".to_string(), "gmail.com".to_string()];
        let e = emails(&p("Jordan Meyers"), &domains);
        let pos = |needle: &str| e.iter().position(|a| a == needle);
        let gmail_flat = pos("jordanmeyers@gmail.com").expect("firstlast@gmail present");
        let proton_dot = pos("jordan.meyers@proton.me").expect("first.last@proton present");
        assert!(
            gmail_flat < proton_dot,
            "firstlast@gmail must rank above first.last@proton; got {e:?}"
        );
        // first.last@gmail — top shape × top provider — is the single best guess.
        assert_eq!(
            e.first().map(String::as_str),
            Some("jordan.meyers@gmail.com")
        );
    }

    #[test]
    fn emails_are_bounded_under_many_domains() {
        let domains: Vec<String> = (0..50).map(|i| format!("d{i}.com")).collect();
        let e = emails(&p("Jordan Leigh Meyers 90"), &domains);
        assert_eq!(e.len(), MAX_EMAILS);
        let set: std::collections::HashSet<_> = e.iter().collect();
        assert_eq!(set.len(), e.len(), "no duplicate addresses");
    }

    #[test]
    fn gravatar_is_stable_md5_and_case_insensitive() {
        // Reference MD5 of "jordan@example.com".
        let a = gravatar_url("Jordan@Example.com");
        let b = gravatar_url("  jordan@example.com ");
        assert_eq!(a, b, "gravatar must normalise case/whitespace");
        assert!(a.contains("/avatar/"));
        // 32 hex chars between /avatar/ and ?.
        let hash = a
            .split("/avatar/")
            .nth(1)
            .and_then(|t| t.split('?').next())
            .unwrap();
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pivots_are_bounded_and_encoded() {
        let n = p("Jordan Leigh Meyers");
        let pv = pivots(&n, Some("jordan.meyers@gmail.com"));
        assert!(pv.len() <= MAX_PIVOTS);
        assert!(!pv.is_empty());
        for piv in &pv {
            assert!(piv.url.starts_with("https://"), "non-https: {}", piv.url);
            // The quoted name must be percent-encoded, never raw spaces/quotes.
            assert!(!piv.url.contains(' '), "raw space in {}", piv.url);
            assert!(!piv.url.contains('"'), "raw quote in {}", piv.url);
        }
        assert!(pv.iter().any(|x| x.platform.starts_with("Google")));
        assert!(pv.iter().any(|x| x.platform.starts_with("Epieos")));
    }

    #[test]
    fn pivots_without_email_skip_epieos() {
        let n = p("Jordan Meyers");
        let pv = pivots(&n, None);
        assert!(!pv.iter().any(|x| x.platform.starts_with("Epieos")));
    }

    #[test]
    fn default_domains_used_without_env() {
        // Not asserting against env (tests share a process); just shape.
        let d = default_domains();
        assert!(d.contains(&"gmail.com".to_string()));
        assert!(d.iter().all(|x| x.contains('.')));
    }

    #[test]
    fn provider_weight_ranks_consumer_mailboxes() {
        // Each arm maps to an exact f64 literal (see `provider_weight`); compare
        // with exact equality since no arithmetic is performed on these values.
        assert_eq!(provider_weight("gmail.com"), 1.0);
        assert_eq!(provider_weight("googlemail.com"), 1.0);
        for d in ["outlook.com", "hotmail.com", "live.com", "msn.com"] {
            assert_eq!(provider_weight(d), 0.6, "{d}");
        }
        for d in ["yahoo.com", "ymail.com"] {
            assert_eq!(provider_weight(d), 0.5, "{d}");
        }
        for d in ["icloud.com", "me.com", "mac.com"] {
            assert_eq!(provider_weight(d), 0.45, "{d}");
        }
        assert_eq!(provider_weight("aol.com"), 0.4);
        for d in ["gmx.com", "gmx.net", "mail.com"] {
            assert_eq!(provider_weight(d), 0.35, "{d}");
        }
        for d in ["proton.me", "protonmail.com", "pm.me", "tutanota.com"] {
            assert_eq!(provider_weight(d), 0.3, "{d}");
        }
        // Unrecognised custom provider falls to the neutral mid weight.
        assert_eq!(provider_weight("example.org"), 0.4);
        assert_eq!(provider_weight("corp.internal"), 0.4);
    }

    #[test]
    fn extract_number_direct_prefers_four_digit_run() {
        // A 4-digit run wins over an earlier 2-digit run regardless of position.
        assert_eq!(extract_number("a12b1987c").as_deref(), Some("1987"));
    }

    #[test]
    fn extract_number_direct_takes_first_short_run_without_year() {
        // No 4-digit run present -> first 2–4 digit run is taken.
        assert_eq!(extract_number("x71y").as_deref(), Some("71"));
    }

    #[test]
    fn extract_number_direct_ignores_overlong_and_single_runs() {
        // A 5-digit run never satisfies `(2..=4).contains(&run.len())`, so it is
        // never pushed as a run -> no number captured.
        assert_eq!(extract_number("123456"), None);
        // A lone 1-digit run is below the 2-digit floor and is ignored.
        assert_eq!(extract_number("a1b"), None);
        // No digits at all.
        assert_eq!(extract_number("abc"), None);
    }

    #[test]
    fn clean_display_token_keeps_letters_and_internal_punct() {
        // Internal apostrophe/hyphen kept; only the FIRST char is uppercased.
        assert_eq!(clean_display_token("o'brien").as_deref(), Some("O'brien"));
        assert_eq!(clean_display_token("jean-paul").as_deref(), Some("Jean-paul"));
        // Outer hyphen/apostrophe trimmed before titlecasing.
        assert_eq!(clean_display_token("-mary-").as_deref(), Some("Mary"));
        // Digits are filtered out; the surviving letters still titlecase.
        assert_eq!(clean_display_token("ab3").as_deref(), Some("Ab"));
        // No surviving letter -> None.
        assert_eq!(clean_display_token("123"), None);
        assert_eq!(clean_display_token(""), None);
    }

    #[test]
    fn titlecase_uppercases_only_the_first_char() {
        assert_eq!(titlecase("mcdonald"), "Mcdonald");
        // An already-mixed-case remainder is preserved verbatim.
        assert_eq!(titlecase("McDonald"), "McDonald");
        assert_eq!(titlecase("a"), "A");
        // Empty input hits the `None` branch and returns an empty String.
        assert_eq!(titlecase(""), "");
    }

    #[test]
    fn dedup_top_keeps_max_weight_drops_empty_and_orders() {
        // `raw` is consumed by `dedup_top`, so a Vec literal here is correct
        // (not a useless_vec — the fn takes `Vec<(String, f64)>` by value).
        let raw = vec![
            ("b".to_string(), 0.5),
            ("a".to_string(), 0.9),
            ("b".to_string(), 0.8),
            (String::new(), 1.0),
        ];
        let out = dedup_top(raw, 10);
        // Empty handle dropped; "b" keeps its MAX weight (0.8, not 0.5);
        // ordered by weight desc -> ["a"(0.9), "b"(0.8)].
        let pairs: Vec<(String, f64)> = out.iter().map(|s| (s.handle.clone(), s.weight)).collect();
        assert_eq!(
            pairs,
            vec![("a".to_string(), 0.9), ("b".to_string(), 0.8)]
        );
    }

    #[test]
    fn dedup_top_truncates_to_cap() {
        let raw = vec![
            ("b".to_string(), 0.5),
            ("a".to_string(), 0.9),
            ("b".to_string(), 0.8),
            (String::new(), 1.0),
        ];
        let out = dedup_top(raw, 1);
        assert_eq!(out.len(), 1);
        // The single retained handle is the highest-weighted ("a").
        assert_eq!(out[0].handle, "a");
        assert_eq!(out[0].weight, 0.9);
    }

    #[test]
    fn dedup_top_sorts_equal_weights_by_handle_asc() {
        // Tie-break on equal weight is handle ascending.
        let raw = vec![("zoe".to_string(), 0.5), ("amy".to_string(), 0.5)];
        let out = dedup_top(raw, 10);
        let handles: Vec<&str> = out.iter().map(|s| s.handle.as_str()).collect();
        assert_eq!(handles, ["amy", "zoe"]);
    }
