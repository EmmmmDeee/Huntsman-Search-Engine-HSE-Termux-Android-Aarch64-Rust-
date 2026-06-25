
use super::{
    AllPolicy, Ipv4Cidr, Ipv6Cidr, Mechanism, Member, Qualifier, SpfIssue, is_spf, members, parse,
};
use std::net::IpAddr;

    #[test]
    fn is_spf_is_case_insensitive_on_the_version_tag() {
        assert!(is_spf("v=spf1 -all"));
        assert!(is_spf("V=SPF1 ip4:1.2.3.4 -all")); // RFC 7208 §4.5
        assert!(!is_spf("v=dmarc1"));
        assert!(!is_spf("spf1"));
        assert!(!is_spf(""));
    }

    #[test]
    fn members_yields_ip4_ip6_and_includes_skipping_junk() {
        let got: Vec<Member> = members(
            "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.example.com \
             ip4: ip6: include: include:localhost a mx -all",
        )
        .collect();
        assert_eq!(
            got,
            vec![
                Member::Ip("198.51.100.0"),
                Member::Ip("2001:db8::"), // IPv6 colons preserved, CIDR stripped
                Member::Include("_spf.example.com"),
                // bare ip4:/ip6:/include: and dotless include:localhost dropped;
                // a/mx/-all are not IP/include members.
            ]
        );
    }

    #[test]
    fn members_strip_mechanism_qualifiers() {
        // Mechanisms can carry a qualifier (`+`/`-`/`~`/`?`, RFC 7208 §4.6.1).
        // Each qualified ip4/ip6/include must still be surfaced.
        let got: Vec<Member> = members(
            "v=spf1 +ip4:198.51.100.1 -ip6:2001:db8::1 ~include:_spf.a.test \
             ?include:_spf.b.test -all",
        )
        .collect();
        assert_eq!(
            got,
            vec![
                Member::Ip("198.51.100.1"),
                Member::Ip("2001:db8::1"),
                Member::Include("_spf.a.test"),
                Member::Include("_spf.b.test"),
            ]
        );
    }

    #[test]
    fn members_ip_without_cidr_returned_verbatim() {
        // IP addresses without a CIDR suffix are returned as-is.
        let got: Vec<Member> = members("v=spf1 ip4:203.0.113.5 ip6:2001:db8::cafe").collect();
        assert_eq!(
            got,
            vec![Member::Ip("203.0.113.5"), Member::Ip("2001:db8::cafe")]
        );
    }

    #[test]
    fn members_yields_a_and_mx_domain_mechanisms() {
        let got: Vec<Member> = members(
            "v=spf1 a:mail.example.com mx:relay.example.net a mx include:_spf.example.org -all",
        )
        .collect();
        assert_eq!(
            got,
            vec![
                Member::A("mail.example.com"),
                Member::Mx("relay.example.net"),
                // bare `a` and bare `mx` (no colon) are skipped — they reference the
                // current domain's own A/MX records and add no new OSINT pivot
                Member::Include("_spf.example.org"),
            ]
        );
    }

    #[test]
    fn members_skips_a_mx_with_macros_or_dotless_targets() {
        // Macro-bearing a:/mx: targets don't resolve to static domains.
        let got: Vec<Member> =
            members("v=spf1 a:%{d}.example.com mx:localhost a: mx: -all").collect();
        assert!(got.is_empty(), "got: {got:?}");
    }

    #[test]
    fn members_yields_redirect_target_and_skips_macros() {
        let got: Vec<Member> =
            members("v=spf1 redirect=_spf.example.net include:%{i}._spf.macro.test").collect();
        // The redirect target is surfaced; the macro-bearing include is skipped
        // (a `%{…}` member is not a literal domain).
        assert_eq!(got, vec![Member::Redirect("_spf.example.net")]);
        // A dotless / empty redirect is dropped like a dotless include.
        assert!(
            members("v=spf1 redirect= redirect=localhost")
                .next()
                .is_none()
        );
    }

    // ── Structural parse + analysis ─────────────────────────────────────────

    /// The exact epik.com record from the project's debug bundle — a well-formed,
    /// strict (`-all`) SPF with mx, a, ten ip4s, and two includes.
    const EPIK: &str = "v=spf1 mx a ip4:209.196.144.40 ip4:209.196.144.17/32 \
        ip4:209.196.144.12/32 ip4:102.223.180.13/32 ip4:162.243.12.225/32 \
        ip4:54.240.63.0/25 ip4:54.240.40.0/25 ip4:54.240.56.128/26 ip4:69.72.33.233 \
        ip4:159.135.235.193 include:mailgun.org include:_spf.mailrelay.rrpproxy.net -all";

    #[test]
    fn parses_real_record_policy_lookups_and_clean_issues() {
        let r = parse(EPIK).unwrap();
        assert_eq!(r.all_policy(), AllPolicy::HardFail); // -all
        // mx + a + 2 includes = 4 DNS-lookup terms (ip4s don't count); under 10.
        assert_eq!(r.dns_lookup_count(), 4);
        // A correct strict record has no findings.
        assert!(r.issues().is_empty(), "unexpected issues: {:?}", r.issues());
        // It lists its literal ip4 senders (default qualifier is Pass).
        let listed: IpAddr = "209.196.144.40".parse().unwrap();
        assert_eq!(r.lists_ip(listed), Some(Qualifier::Pass));
        assert_eq!(r.lists_ip("8.8.8.8".parse().unwrap()), None);
        assert!(parse("v=dmarc1 p=reject").is_none());
    }

    #[test]
    fn all_policy_classification() {
        assert_eq!(parse("v=spf1 -all").unwrap().all_policy(), AllPolicy::HardFail);
        assert_eq!(parse("v=spf1 ~all").unwrap().all_policy(), AllPolicy::SoftFail);
        assert_eq!(parse("v=spf1 ?all").unwrap().all_policy(), AllPolicy::Neutral);
        assert_eq!(parse("v=spf1 +all").unwrap().all_policy(), AllPolicy::Pass);
        assert_eq!(parse("v=spf1 all").unwrap().all_policy(), AllPolicy::Pass); // bare = +
        assert_eq!(
            parse("v=spf1 redirect=_spf.example.com").unwrap().all_policy(),
            AllPolicy::Redirect
        );
        assert_eq!(
            parse("v=spf1 ip4:1.2.3.4").unwrap().all_policy(),
            AllPolicy::ImplicitNeutral
        );
    }

    #[test]
    fn flags_open_and_weak_policies() {
        assert!(parse("v=spf1 +all").unwrap().issues().contains(&SpfIssue::OpenPolicy));
        assert!(parse("v=spf1 ?all").unwrap().issues().contains(&SpfIssue::WeakPolicy));
        assert!(parse("v=spf1 ip4:1.2.3.4").unwrap().issues().contains(&SpfIssue::WeakPolicy));
        // A strict record is neither.
        let strict = parse("v=spf1 ip4:1.2.3.4 -all").unwrap().issues();
        assert!(!strict.contains(&SpfIssue::OpenPolicy) && !strict.contains(&SpfIssue::WeakPolicy));
    }

    #[test]
    fn flags_excess_dns_lookups() {
        // 11 includes alone exceed the RFC 7208 §4.6.4 limit of 10.
        let mut rec = String::from("v=spf1");
        for i in 0..11 {
            rec.push_str(&format!(" include:_spf{i}.example.com"));
        }
        rec.push_str(" -all");
        let r = parse(&rec).unwrap();
        assert_eq!(r.dns_lookup_count(), 11);
        assert!(r.issues().contains(&SpfIssue::ExceedsLookupLimit(11)));
    }

    #[test]
    fn flags_ptr_macros_and_unreachable_mechanisms() {
        let r = parse("v=spf1 ptr include:%{i}.x.test -all ip4:1.2.3.4").unwrap();
        let issues = r.issues();
        assert!(issues.contains(&SpfIssue::DeprecatedPtr));
        assert!(issues.contains(&SpfIssue::MacrosPresent));
        assert!(r.has_macros);
        // One mechanism (the trailing ip4) sits after `-all`, unreachable.
        assert!(issues.contains(&SpfIssue::UnreachableMechanisms(1)));
    }

    #[test]
    fn unknown_modifiers_are_ignored_not_errored() {
        // RFC 7208 §6: unknown modifiers MUST be ignored, not rejected.
        let r = parse("v=spf1 ip4:1.2.3.4 futuremod=whatever -all").unwrap();
        assert_eq!(r.unknown_modifiers, 1);
        assert!(r.invalid_terms.is_empty(), "unknown modifier must not be a syntax error");
        assert!(!r.issues().iter().any(|i| matches!(i, SpfIssue::SyntaxErrors(_))));
    }

    #[test]
    fn malformed_terms_are_collected_leniently() {
        let r = parse("v=spf1 ip4:not-an-ip include:ok.test -all").unwrap();
        assert_eq!(r.invalid_terms, vec!["ip4:not-an-ip".to_string()]);
        // The good include still parsed.
        assert!(r.directives.iter().any(|(_, m)| *m == Mechanism::Include("ok.test".into())));
        assert!(r.issues().contains(&SpfIssue::SyntaxErrors(1)));
    }

    #[test]
    fn cidr_maths_is_overflow_safe_and_correct() {
        // /0 must not shift by the word width.
        assert!(Ipv4Cidr::parse("0.0.0.0/0").unwrap().contains("1.2.3.4".parse().unwrap()));
        assert!(Ipv6Cidr::parse("::/0").unwrap().contains("2001:db8::1".parse().unwrap()));
        // Normal containment.
        let net = Ipv4Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.255.1.2".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        // Bad input is rejected, not panicked.
        assert!(Ipv4Cidr::parse("10.0.0.0/33").is_none());
        assert!(Ipv6Cidr::parse("not-an-addr").is_none());
    }

    #[test]
    fn lists_ip_is_a_qualifier_carrying_membership_test() {
        let r = parse("v=spf1 -ip4:10.0.0.0/8 ip6:2001:db8::/32 ~all").unwrap();
        // The negative-qualified range carries its qualifier through.
        assert_eq!(r.lists_ip("10.1.2.3".parse().unwrap()), Some(Qualifier::Fail));
        assert_eq!(r.lists_ip("2001:db8::99".parse().unwrap()), Some(Qualifier::Pass));
        // Not in any literal range, and a v4 address never matches an ip6 range.
        assert_eq!(r.lists_ip("192.168.1.1".parse().unwrap()), None);
    }
