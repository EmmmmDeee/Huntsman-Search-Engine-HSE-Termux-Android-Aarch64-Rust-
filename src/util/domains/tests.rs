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
        // Network-ops role local-parts on a NON-provider domain — these only
        // became infrastructure once noc/sysadmin/tech were merged into
        // is_role_localpart from employer_pivot's own role list.
        assert!(is_infrastructure_email("noc@acmecorp.com.au"));
        assert!(is_infrastructure_email("sysadmin@acmecorp.com.au"));
        assert!(is_infrastructure_email("tech@acmecorp.com.au"));
        // Trailing dot / case tolerance.
        assert!(is_infrastructure_email("Abuse@Cloudflare.com."));
        // Genuine personal mail is NOT infrastructure.
        assert!(!is_infrastructure_email("jordanavery@gmail.com"));
        assert!(!is_infrastructure_email("jane.doe@example.org"));
        // Consumer freemail is personal PII, never infrastructure — even on
        // googlemail.com, which is just Gmail's alternate domain (regression: it
        // used to sit in the provider-infra set and suppressed real subject mail
        // from SERP/WHOIS discovery).
        assert!(!is_infrastructure_email("ali.kareem@googlemail.com"));
        assert!(!is_infrastructure_email("alikareem@googlemail.com"));
        assert!(!is_infrastructure_email("jdoe@yahoo.com"));
        assert!(!is_infrastructure_email("jane@outlook.com"));
        // …but an automated *desk* on a freemail domain is still infrastructure
        // (the role local-part decides, not the provider).
        assert!(is_infrastructure_email("abuse@googlemail.com"));
        assert!(is_infrastructure_email("postmaster@gmail.com"));
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
    fn role_localpart_covers_network_ops_words_merged_from_employer_pivot() {
        // noc/sysadmin/tech were merged in from employer_pivot's own,
        // independently-maintained role list when it was consolidated onto
        // this single-sourced one.
        assert!(is_role_localpart("noc"));
        assert!(is_role_localpart("sysadmin"));
        assert!(is_role_localpart("tech"));
    }

    #[test]
    fn infra_provider_domain_detects_cdn_registrar_and_nameserver_domains() {
        // Exact provider domain.
        assert!(is_infra_provider_domain("cloudflare.com"));
        assert!(is_infra_provider_domain("godaddy.com"));
        // A nameserver is a subdomain of the provider — rdap_domain/whois both
        // surface exactly this shape as a first-class Domain entity.
        assert!(is_infra_provider_domain("ns1.cloudflare.com"));
        // Trailing dot / case tolerance.
        assert!(is_infra_provider_domain("Cloudflare.COM."));
        // A genuine business domain is not infrastructure.
        assert!(!is_infra_provider_domain("acmecorp.com.au"));
        assert!(!is_infra_provider_domain(""));
    }

    #[test]
    fn freemail_basics() {
        assert!(is_freemail("gmail.com"));
        assert!(is_freemail("bigpond.com"));
        // AU ISP mail domains (Exetel's mailbox domain is exemail.com.au, not
        // exetel.com.au — the webmail host differs from the address domain).
        assert!(is_freemail("exemail.com.au"));
        assert!(is_freemail("iprimus.com.au"));
        assert!(!is_freemail("acme.com.au"));
        assert!(!is_freemail(""));
    }

    #[test]
    fn app_package_id_detects_reverse_dns_packages() {
        // Real Android / iOS reverse-DNS app identifiers — the stealer-log
        // `domain` values that must NOT become Domain entities.
        assert!(is_app_package_id("com.facebook.katana"));
        assert!(is_app_package_id("com.google.android.gms"));
        assert!(is_app_package_id("org.mozilla.firefox"));
        assert!(is_app_package_id("net.whatsapp.WhatsApp"));
        assert!(is_app_package_id("io.metamask.MetaMask"));
        // Case / trailing-dot tolerant.
        assert!(is_app_package_id("COM.Facebook.Katana."));
        // Genuine registrable domains are NOT packages (TLD is the LAST label).
        assert!(!is_app_package_id("facebook.com"));
        assert!(!is_app_package_id("www.google.com"));
        assert!(!is_app_package_id("shop.example.com.au"));
        assert!(!is_app_package_id("mail.protonmail.com"));
        // Two-label inputs are never treated as packages (a bare domain stays).
        assert!(!is_app_package_id("example.com"));
        assert!(!is_app_package_id("com.au"));
        // A 3+-label host that does NOT lead with a generic TLD is a domain.
        assert!(!is_app_package_id("api.stripe.com"));
        // Regression: `app.` and `dev.` are common real subdomain prefixes, NOT
        // reverse-DNS package leads. They were misclassified as packages and the
        // valid Domain silently dropped; both must now survive as domains.
        assert!(!is_app_package_id("app.example.com"));
        assert!(!is_app_package_id("dev.portal.com"));
        assert!(!is_app_package_id("dev.azure.com"));
        assert!(!is_app_package_id("app.slack.com"));
        assert!(looks_like_domain("app.example.com"));
        assert!(looks_like_domain("dev.portal.com"));
        // The genuinely-generic leads still gate reverse-DNS packages.
        assert!(is_app_package_id("io.metamask.MetaMask"));
        assert!(is_app_package_id("net.whatsapp.WhatsApp"));
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

    #[test]
    fn looks_like_domain_rejects_ip_and_app_package_noise() {
        // Real registrable domains from the stealer/breach feeds.
        for good in [
            "discord.com",
            "snapchat.com",
            "a-zfastfitcentre.co.uk",
            "xyz.blueskyweb.app",
            "aliexprass.ml",
            "gmail.com",
        ] {
            assert!(looks_like_domain(good), "{good} is a real domain");
        }
        // Noise that stealer/breach `domain` fields carry — minting any of these as
        // a Domain misdirects dns/cert/wayback (the grounded bug from the scan logs).
        for junk in [
            "192.168.0.1",   // private LAN/router IP — pervasive in stealer logs
            "192.168.1.1",
            "79.98.132.222", // public C2/panel IP
            "54.39.106.39",
            "com.facebook.katana", // android app package (reverse-DNS, 3+ labels)
            "com.google.android.apps.authenticator2",
            "localhost",           // single label
            "android",             // bare label
            "1.2.3",               // numeric junk, no real TLD
            "user@domain.com",     // stray @ — not a bare domain
            "",
        ] {
            assert!(!looks_like_domain(junk), "{junk:?} must be rejected");
        }
    }
