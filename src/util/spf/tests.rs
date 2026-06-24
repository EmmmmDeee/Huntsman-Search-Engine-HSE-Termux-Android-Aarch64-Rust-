
use super::{Member, is_spf, members};

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
