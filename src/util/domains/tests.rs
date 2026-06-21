use super::*;

    #[test]
    fn infrastructure_email_detects_role_and_provider_mailboxes() {
        // Role local-parts on any domain.
        assert!(is_infrastructure_email("abuse@cloudflare.com"));
        assert!(is_infrastructure_email("dns@cloudflare.com"));
        assert!(is_infrastructure_email("hostmaster@example.org"));
        assert!(is_infrastructure_email("no-reply@acme.com"));
        // Non-role mailbox but on a provider domain → still infrastructure.
        assert!(is_infrastructure_email("network-ops@amazonaws.com"));
        assert!(is_infrastructure_email("jdoe@sendgrid.net"));
        // Subdomain of a provider.
        assert!(is_infrastructure_email("noc@mail.cloudflare.com"));
        // Trailing dot / case tolerance.
        assert!(is_infrastructure_email("Abuse@Cloudflare.com."));
        // Live-scan registrar/role artifacts that previously leaked into the
        // people graph (Network Solutions placeholder, copyright + enquiry desks).
        assert!(is_infrastructure_email("namehost@worldnic.com"));
        assert!(is_infrastructure_email("dmca@telegram.org"));
        assert!(is_infrastructure_email("generalenquiry@nswlrs.com.au"));
        // Genuine personal mail is NOT infrastructure.
        assert!(!is_infrastructure_email("jordanavery@gmail.com"));
        assert!(!is_infrastructure_email("jane.doe@example.org"));
        // Consumer freemail is NEVER infrastructure — googlemail.com is Gmail's
        // alias (it used to be wrongly listed in INFRA_MAIL, so a real person's
        // address was flagged as a provider mailbox; live audit caught it).
        assert!(!is_infrastructure_email("oada@googlemail.com"));
        assert!(!is_infrastructure_email("onur.ada@googlemail.com"));
        // Even a role-ish local-part on freemail is a person/small-biz mailbox,
        // not a provider desk — freemail short-circuits before the role check.
        assert!(!is_infrastructure_email("sales@gmail.com"));
        // A real person whose local-part merely contains a role substring is
        // NOT gated (exact-token match, no false positive on "info").
        assert!(!is_infrastructure_email("infosys.engineer@example.org"));
        // Malformed input is safely false.
        assert!(!is_infrastructure_email("not-an-email"));
    }

    #[test]
    fn role_localpart_basics() {
        assert!(is_role_localpart("dns") && is_role_localpart("no-reply"));
        assert!(is_role_localpart("postmaster") && is_role_localpart("abuse"));
        assert!(!is_role_localpart("jordanavery") && !is_role_localpart("jane.doe"));
    }

    #[test]
    fn freemail_basics() {
        assert!(is_freemail("gmail.com"));
        assert!(is_freemail("bigpond.com"));
        assert!(!is_freemail("acme.com.au"));
        assert!(!is_freemail(""));
    }

    #[test]
    fn is_or_subdomain_of_respects_label_boundaries() {
        // Equal and genuine subdomains belong.
        assert!(is_or_subdomain_of("example.com", "example.com"));
        assert!(is_or_subdomain_of("sub.example.com", "example.com"));
        assert!(is_or_subdomain_of("a.b.example.com", "example.com"));
        // Mid-label and different-TLD do NOT (the bug the helper prevents).
        assert!(!is_or_subdomain_of("notexample.com", "example.com"));
        assert!(!is_or_subdomain_of("example.com.au", "example.com"));
        assert!(!is_or_subdomain_of("example.com", "sub.example.com"));
        // Proper-subdomain excludes the apex.
        assert!(!is_proper_subdomain_of("example.com", "example.com"));
        assert!(is_proper_subdomain_of("sub.example.com", "example.com"));
        assert!(!is_proper_subdomain_of("notexample.com", "example.com"));
    }

    #[test]
    fn domain_helpers_cross_function_invariants() {
        // Generative invariant check over a constructed host corpus: example tests
        // pin individual cases, this pins the *relationships* between the helpers,
        // so a future change to one that desyncs from another is caught.
        let labels = ["a", "sub", "mail", "shop", "www", "deeply", "nested"];
        let bases = ["example", "acme", "target-co"];
        // Single-label TLDs plus every curated multi-label suffix.
        let mut suffixes: Vec<String> = vec!["com".into(), "org".into(), "io".into()];
        suffixes.extend(MULTI_LABEL_SUFFIXES.iter().map(|s| (*s).to_string()));

        let mut corpus: Vec<String> = Vec::new();
        for base in bases {
            for suf in &suffixes {
                let apex = format!("{base}.{suf}"); // registrable form
                corpus.push(apex.clone());
                // Build a few subdomains of varying depth.
                for depth in 1..=3 {
                    let prefix = labels[..depth].join(".");
                    corpus.push(format!("{prefix}.{apex}"));
                }
            }
        }

        for host in &corpus {
            // Reflexive / irreflexive.
            assert!(is_or_subdomain_of(host, host), "reflexive: {host}");
            assert!(!is_proper_subdomain_of(host, host), "irreflexive: {host}");

            let r = registrable_domain(host).expect("corpus hosts have >= 2 labels");

            // INVARIANT 1: the registrable domain is always an equal-or-subdomain
            // of its host (a label-aligned suffix), never an unrelated string.
            // `registrable_domain` lowercases; the corpus is already lowercase.
            assert!(
                is_or_subdomain_of(host, &r),
                "registrable {r} must be an equal-or-subdomain of host {host}"
            );

            // INVARIANT 2: idempotence — the registrable domain of a registrable
            // domain is itself (collapsing twice changes nothing).
            assert_eq!(
                registrable_domain(&r).as_deref(),
                Some(r.as_str()),
                "registrable_domain not idempotent for {host} (r={r})"
            );

            // INVARIANT 3: proper-subdomain implies equal-or-subdomain, and the
            // two agree except exactly at equality.
            for other in &corpus {
                let sub = is_proper_subdomain_of(host, other);
                let eq_or_sub = is_or_subdomain_of(host, other);
                if sub {
                    assert!(eq_or_sub, "proper-subdomain must imply or-subdomain");
                }
                assert_eq!(
                    eq_or_sub,
                    host == other || sub,
                    "or-subdomain must be exactly (equal OR proper-subdomain): {host} vs {other}"
                );
            }
        }
    }

    #[test]
    fn social_includes_country_subdomains() {
        assert!(is_social_platform("linkedin.com"));
        assert!(is_social_platform("au.linkedin.com"));
        assert!(is_social_platform("m.facebook.com"));
        assert!(!is_social_platform("acme.com"));
    }

    #[test]
    fn multi_label_suffix_table_is_sorted_for_binary_search() {
        assert!(
            MULTI_LABEL_SUFFIXES.is_sorted(),
            "MULTI_LABEL_SUFFIXES must stay sorted (binary_search)"
        );
    }

    #[test]
    fn registrable_domain_single_label_tlds() {
        assert_eq!(
            registrable_domain("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("cdn.assets.example.org").as_deref(),
            Some("example.org")
        );
        // Fewer than two labels → no registrable domain.
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain(""), None);
    }

    #[test]
    fn registrable_domain_multi_label_suffixes() {
        // The whole point: AU + common international multi-label suffixes resolve
        // to the registered name, not the bare suffix.
        assert_eq!(
            registrable_domain("shop.example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(
            registrable_domain("example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(registrable_domain("a.b.co.uk").as_deref(), Some("b.co.uk"));
        assert_eq!(
            registrable_domain("dept.gov.au").as_deref(),
            Some("dept.gov.au")
        );
        // The bare suffix itself has no registered label in front → kept as-is
        // (two labels, not in a 3-label position).
        assert_eq!(registrable_domain("com.au").as_deref(), Some("com.au"));
    }

    #[test]
    fn registrable_domain_normalises_case_and_trailing_dot() {
        assert_eq!(
            registrable_domain("WWW.Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("  Shop.Example.Com.AU  ").as_deref(),
            Some("example.com.au")
        );
    }
