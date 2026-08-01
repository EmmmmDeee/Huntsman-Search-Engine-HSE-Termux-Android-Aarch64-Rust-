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
            first_variants: Vec::new(),
            middle_variants: Vec::new(),
            last_variants: Vec::new(),
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
    fn cyrillic_name_transliterates_to_handles() {
        // "Иван Петров" (Ivan Petrov). Was a coverage hole: Cyrillic folded to
        // empty handle tokens, so the seed derived ZERO usernames/emails —
        // measured live at 0/0. The transliteration engine romanizes it, so the
        // full username/email permutation now fires like any Latin name.
        let n = parse(
            "\u{0418}\u{0432}\u{0430}\u{043d} \u{041f}\u{0435}\u{0442}\u{0440}\u{043e}\u{0432}",
        )
        .expect("Cyrillic name parses");
        assert_eq!(n.first, "ivan");
        assert_eq!(n.last, "petrov");
        let u: Vec<String> = usernames(&n).into_iter().map(|h| h.handle).collect();
        assert!(u.contains(&"ivan.petrov".to_string()));
        assert!(u.contains(&"ipetrov".to_string()));
        assert!(
            !emails(&n, &default_domains()).is_empty(),
            "Cyrillic name now derives speculative emails"
        );
        // Handle-gated pivots (Instagram, …) now generate too, since a handle exists.
        let pivots = pivots(&n, None);
        assert!(
            pivots.iter().any(|pv| pv.platform.starts_with("Instagram")),
            "handle pivots generate once a transliterated handle exists"
        );
        // The display form keeps the original Cyrillic for quoted searches.
        assert!(pivots.iter().any(|pv| pv.url.contains("google.com/search")));
    }

    #[test]
    fn real_cyrillic_surnames_romanize_recognizably() {
        // Public figures — the primary romanization must be the recognizable
        // Latin stem their real handles/press use.
        assert_eq!(p("Мария Шарапова").last, "sharapova"); // Maria Sharapova
        assert_eq!(p("Владимир Путин").last, "putin"); // Vladimir Putin
        assert_eq!(p("Сергей Брин").last, "brin"); // Sergey Brin
        assert_eq!(p("Гарри Каспаров").last, "kasparov"); // Garry Kasparov
        // -ый surname ending collapses to "-y" in the web scheme (Navalny).
        assert_eq!(p("Алексей Навальный").last, "navalny");
    }

    #[test]
    fn greek_name_transliterates_to_handles() {
        // "Γιώργος Παπαδόπουλος" (Giorgos Papadopoulos) — the ου digraph must
        // romanize to "ou" (papadopoulos, not papadopoylos).
        let n = p("Γιώργος Παπαδόπουλος");
        assert_eq!(n.first, "giorgos");
        assert_eq!(n.last, "papadopoulos");
        let u: Vec<String> = usernames(&n).into_iter().map(|h| h.handle).collect();
        assert!(u.contains(&"giorgos.papadopoulos".to_string()));
        // Alexis Tsipras — τσ→ts, ξ→x, η→i.
        assert_eq!(p("Αλέξης Τσίπρας").first, "alexis");
        assert_eq!(p("Αλέξης Τσίπρας").last, "tsipras");
    }

    #[test]
    fn german_umlaut_yields_both_muller_and_mueller() {
        // The plain fold stays PRIMARY (muller — unchanged), and the ue-expansion
        // convention is added as a real alternate handle people register under.
        let n = p("Hans Müller");
        assert_eq!(n.last, "muller"); // primary unchanged
        let u: Vec<String> = usernames(&n).into_iter().map(|h| h.handle).collect();
        assert!(u.contains(&"hans.muller".to_string()));
        assert!(
            u.contains(&"hans.mueller".to_string()),
            "the German ue-expansion variant must also derive"
        );
    }

    #[test]
    fn han_script_still_yields_no_handles() {
        // CJK has no letter-level offline romanization (needs a dictionary), so
        // it honestly stays handle-free — only display-name pivots generate.
        // Guards against a false claim that we romanize scripts we do not.
        // (Space-separated so it parses into two tokens; Han names are normally
        // written without spaces and would parse to None — also handle-free.)
        let n = parse("\u{674e} \u{660e}").expect("Han name parses for pivots");
        assert!(n.first.is_empty() && n.last.is_empty());
        assert!(usernames(&n).is_empty());
        assert!(emails(&n, &default_domains()).is_empty());
        assert!(!pivots(&n, None).is_empty(), "display pivots still generate");
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
