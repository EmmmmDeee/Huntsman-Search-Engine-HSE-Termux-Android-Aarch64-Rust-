use super::*;

    #[test]
    fn matches_standard_address_shapes() {
        for ok in [
            "alice@example.com",
            "bob.smith+tag@sub.example.co.uk",
            "a@b.io",
            "with%percent@example.com",
        ] {
            assert!(EMAIL_RE.is_match(ok), "should match: {ok}");
        }
    }

    #[test]
    fn rejects_non_addresses() {
        for no in ["@example.com", "user@host", "user@host.123", "plainword"] {
            assert!(!EMAIL_RE.is_match(no), "should NOT match: {no}");
        }
    }

    #[test]
    fn url_re_matches_scheme_and_stops_at_sentence_punctuation() {
        // The bio/profile cases reddit_user + hacker_news relied on: the match
        // over-runs the trailing '.' (callers trim it) and stops at the space.
        let m = URL_RE
            .find("site https://paulgraham.com/bio.html. and more")
            .unwrap();
        assert_eq!(
            m.as_str().trim_end_matches(['.', ',', ')']),
            "https://paulgraham.com/bio.html"
        );
        assert!(URL_RE.is_match("http://x.io/p"));
        assert!(!URL_RE.is_match("no scheme here example.com"));
    }

    #[test]
    fn extracts_and_lowercases_dedupes() {
        assert_eq!(emails("contact alice@example.com"), ["alice@example.com"]);
        let text = "Ping Alice@Example.COM and alice@example.com";
        assert_eq!(emails(text), ["alice@example.com"]);
    }

    #[test]
    fn urls_extracts_all_distinct_trimmed_in_order_uncapped() {
        // Full fidelity: every distinct URL in a link-heavy bio surfaces — no
        // silent first-N cap — with trailing sentence punctuation trimmed,
        // deduped on the trimmed value, first-occurrence order preserved.
        let bio = "sites: https://a.example/, https://b.example/p. \
                   also https://c.example), https://d.example \
                   mirror https://e.example/x https://f.example/y \
                   dup https://a.example/ again";
        assert_eq!(
            urls(bio),
            vec![
                "https://a.example/".to_string(),
                "https://b.example/p".to_string(),
                "https://c.example".to_string(),
                "https://d.example".to_string(),
                "https://e.example/x".to_string(),
                "https://f.example/y".to_string(),
            ],
            "all six distinct URLs, trimmed and deduped, not a capped five"
        );
        assert!(urls("no links here").is_empty());
    }

    #[test]
    fn phones_extracts_e164() {
        assert_eq!(phones("+61412345678"), ["+61412345678"]);
        assert_eq!(phones("call +1 (555) 123-4567"), ["+15551234567"]);
        assert!(phones("5551234567").is_empty());
    }

    #[test]
    fn phones_deduplicates_same_number() {
        let text = "+61412345678 and again +61412345678";
        assert_eq!(phones(text), vec!["+61412345678"]);
    }

    #[test]
    fn page_emails_deduplicates_case_insensitive() {
        let text = "Contact Alice@Example.com or alice@example.com";
        assert_eq!(page_emails(text), vec!["alice@example.com"]);
    }

    #[test]
    fn page_emails_drops_asset_refs() {
        assert!(page_emails("logo@2x.png").is_empty());
        assert_eq!(page_emails("bob@example.com"), ["bob@example.com"]);
    }

    #[test]
    fn page_emails_keeps_a_percent_in_the_local_part() {
        // `%` is in the canonical EMAIL_RE local class; the byte-scanner must not
        // truncate the mailbox at it (fail-before: yielded `percent@example.com`).
        assert!(EMAIL_RE.is_match("with%percent@example.com"));
        assert_eq!(
            page_emails("mail with%percent@example.com now"),
            ["with%percent@example.com"]
        );
    }

    #[test]
    fn page_emails_drops_script_url_fragments() {
        // URL fragments glued to `@` during HTML stripping are not mailboxes
        // (the real-scan bug `viewtopic.phprose.cl@onet.eu`); a clean address in
        // the same text still extracts. Consolidated from search_engines.
        assert!(page_emails("see viewtopic.phprose.cl@onet.eu and index.html@x.com").is_empty());
        assert_eq!(
            page_emails("real person jane.doe@onet.eu posted"),
            ["jane.doe@onet.eu"]
        );
    }

    #[test]
    fn looks_like_email_rejects_provider_field_junk() {
        // Real addresses seen in the breach `email` fields for the Ali.kareem scan.
        for good in [
            "ali.kareem95@gmail.com",
            "alik.8972@yahoo.com",
            "dr.ali.ali52@gmail.com",
        ] {
            assert!(looks_like_email(good), "{good} is a real address");
        }
        // Junk a provider echoes/mangles into an `email` field — must not become an
        // Email entity (this is the see_know `contains('@')`-only gap, now closed).
        for junk in [
            "Ali.kareem",     // username echoed into the email field (snusbase)
            "ali.kareem",
            "user@",          // no host
            "@gmail.com",     // no local part
            "user@localhost", // host has no dot
            "a b@c.com",      // embedded whitespace
            "",
            // Domains the canonical EMAIL_RE (…\.[A-Za-z]{2,}) rejects but the
            // field gate used to admit — an IP literal, a numeric pseudo-TLD, a
            // one-char TLD, and a double-dot host — each of which minted a bogus
            // Email entity that then poisoned correlation.
            "admin@10.0.0.1",
            "user@host.123",
            "user@host.c",
            "x@sub..example.com",
            "user@.example.com",
        ] {
            assert!(!looks_like_email(junk), "{junk:?} must be rejected");
        }
        // Consistency with the free-text scanner on the cases EMAIL_RE also
        // rejects (no `\.[A-Za-z]{2,}` TLD): the field gate is never *more*
        // permissive than the scanner. (The `..` case is one where the gate is
        // deliberately *stricter* than the substring-matching EMAIL_RE, which is
        // correct for an admission gate, so it is not asserted here.)
        for e in ["admin@10.0.0.1", "user@host.123"] {
            assert!(!EMAIL_RE.is_match(e), "EMAIL_RE agrees {e} is not an address");
        }
    }

    #[test]
    fn page_emails_rejects_ip_literal_and_numeric_tld_domains() {
        // The HTML byte-scanner shared the field gate's blind spot: it carved a
        // pseudo-address out of an IP literal or a numeric-TLD host. A valid
        // address in the same text still extracts (no false negative).
        assert!(page_emails("contact admin@10.0.0.1 now").is_empty());
        assert!(page_emails("see user@host.123 here").is_empty());
        assert_eq!(
            page_emails("but real jane.doe@example.com posted"),
            ["jane.doe@example.com"]
        );
    }

    #[test]
    fn classify_credential_field_separates_sentinels_emails_secrets() {
        use CredentialField::{Email, Secret, Sentinel};
        // Real stealer/breach values from the Ali.kareem logs.
        assert_eq!(classify_credential_field("[fail]"), Sentinel);
        assert_eq!(classify_credential_field("  [NOT_SAVED] "), Sentinel);
        assert_eq!(classify_credential_field("<empty>"), Sentinel);
        assert_eq!(classify_credential_field("UPGRADE_TO_SEE_xxxx"), Sentinel);
        assert_eq!(classify_credential_field(""), Sentinel);
        // An email mis-stored in the password slot is recovered as a lead.
        assert_eq!(classify_credential_field("ayilmazer486@gmail.com"), Email);
        // Genuine passwords from the logs stay secrets...
        for pw in ["Yontem2006", "C0R4Pc1", "Kando1453!", "hakunamatata"] {
            assert_eq!(classify_credential_field(pw), Secret, "{pw}");
        }
        // ...including a terrible bare `fail`/`null`: only the BRACKETED form is a
        // sentinel, so a real (if weak) password is never silently discarded.
        assert_eq!(classify_credential_field("fail"), Secret);
        assert_eq!(classify_credential_field("null"), Secret);
    }

    #[test]
    fn macs_extracts_normalises_and_filters() {
        let text = "BSSID: A4-B1-C2-00-11-22 connected; adapter aa:bb:cc:dd:ee:ff\n\
                    broadcast ff:ff:ff:ff:ff:ff and null 00:00:00:00:00:00";
        let got = macs(text);
        // Both real MACs, normalised to lowercase colon form, in order; the
        // broadcast and all-zero addresses are dropped.
        assert_eq!(got, vec!["a4:b1:c2:00:11:22".to_string(), "aa:bb:cc:dd:ee:ff".to_string()]);
        // De-duplicated.
        assert_eq!(macs("x aa:bb:cc:dd:ee:ff y aa:bb:cc:dd:ee:ff").len(), 1);
        // An IPv6 fragment (4-hex groups) is not a MAC.
        assert!(macs("2606:2800:220:1:248:1893:25c8:1946").is_empty());
    }

    #[test]
    fn macs_does_not_carve_a_48bit_mac_out_of_a_longer_eui64_run() {
        // The regex's word boundary treats the separator after the 6th octet as a
        // boundary, so an 8-octet EUI-64 must NOT yield a spurious 48-bit MAC from
        // its first (or middle) six octets — in either colon or hyphen form.
        assert!(
            macs("id aa:bb:cc:dd:ee:ff:00:11 end").is_empty(),
            "no 48-bit MAC may be carved from an 8-octet colon run"
        );
        assert!(
            macs("A4-B1-C2-00-11-22-33-44").is_empty(),
            "no 48-bit MAC may be carved from an 8-octet hyphen run"
        );
        // A genuine standalone MAC flanked by non-separator punctuation still
        // extracts — the fragment guard must not over-reject.
        assert_eq!(
            macs("(aa:bb:cc:dd:ee:ff)"),
            vec!["aa:bb:cc:dd:ee:ff".to_string()]
        );
    }

    #[test]
    fn labeled_ssids_extracts_named_networks_only() {
        let text = "SSID: Smith Home 5G\nWiFi Name = OfficeNet\nWireless Network: null\nrandom line";
        let got = labeled_ssids(text);
        assert_eq!(got, vec!["Smith Home 5G".to_string(), "OfficeNet".to_string()]);
        // No labelled SSID → nothing (SSIDs can't be recognised free-text).
        assert!(labeled_ssids("just a sentence with the word network in it").is_empty());
    }

    #[test]
    fn ibans_validates_mod97_checksum() {
        // The canonical valid example IBAN.
        assert_eq!(
            ibans("transfer to GB82WEST12345698765432 today"),
            vec!["GB82WEST12345698765432".to_string()]
        );
        // Shape-valid but wrong check digits → rejected.
        assert!(ibans("GB00WEST12345698765432").is_empty());
        // Not IBAN-shaped.
        assert!(ibans("just some words and 12345 digits").is_empty());
    }

    /// Property tests: these extractors run over raw scraped HTML, SERP snippets,
    /// breach blobs, and stealer logs — fully attacker-shaped input — so the
    /// load-bearing guarantee is that arbitrary bytes (multibyte UTF-8, control
    /// characters, `@`/`.`/`:` noise) never panic them and every returned token
    /// is well-formed. The byte-walking `page_emails` and the char-slicing
    /// `ibans`/`macs` normalisers are the real panic surface a fuzz-shaped input
    /// probes; example-based tests above cover the intended positive matches.
    mod prop {
        use proptest::prelude::*;

        use super::{
            CredentialField, classify_credential_field, emails, ibans, is_placeholder_secret,
            labeled_ssids, looks_like_email, macs, page_emails, phones,
        };

        proptest! {
            /// `emails` (regex-based, scanner-grade) is total; every hit contains
            /// an `@` with a dotted host part, is lower-cased, and is de-duplicated.
            /// It does NOT assert `looks_like_email`: the loose regex can match a
            /// host that starts with a dot (`a@.example.com`), which the stricter
            /// structural gate rejects — that divergence is by design.
            #[test]
            fn emails_is_total_and_shaped(s in ".{0,256}") {
                let got = emails(&s);
                let mut uniq = std::collections::HashSet::new();
                for e in &got {
                    prop_assert!(!e.chars().any(char::is_uppercase), "not lower-cased: {e:?}");
                    let (local, host) = e.split_once('@').expect("email hit must contain '@'");
                    prop_assert!(!local.is_empty(), "empty local part: {e:?}");
                    prop_assert!(host.contains('.'), "host has no dot: {e:?}");
                    prop_assert!(uniq.insert(e.clone()), "duplicate email: {e:?}");
                }
            }

            /// `page_emails` (the manual byte-walker) is total AND strictly enough
            /// filtered that every hit satisfies the structural `looks_like_email`
            /// gate — it requires a non-empty local, an alphanumeric-leading dotted
            /// host, and strips trailing dots, so unlike the raw regex it can never
            /// emit a dot-leading host. Also lower-cased and de-duplicated.
            #[test]
            fn page_emails_is_total_and_well_formed(s in ".{0,256}") {
                let got = page_emails(&s);
                let mut uniq = std::collections::HashSet::new();
                for e in &got {
                    prop_assert!(!e.chars().any(char::is_uppercase), "not lower-cased: {e:?}");
                    prop_assert!(looks_like_email(e), "ill-formed page email: {e:?}");
                    prop_assert!(uniq.insert(e.clone()), "duplicate page email: {e:?}");
                }
            }

            /// `ibans` is total; every hit is upper-case ASCII-alphanumeric of a
            /// valid IBAN length (checksum validity is pinned by the example test).
            #[test]
            fn ibans_is_total_and_shaped(s in ".{0,256}") {
                for iban in ibans(&s) {
                    prop_assert!((15..=34).contains(&iban.len()), "bad IBAN length: {iban:?}");
                    prop_assert!(
                        iban.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
                        "non-uppercase-alnum IBAN: {iban:?}"
                    );
                }
            }

            /// `macs` is total; every hit is the canonical lower-case colon form
            /// and never the all-zero or broadcast address.
            #[test]
            fn macs_is_total_and_canonical(s in ".{0,256}") {
                for mac in macs(&s) {
                    prop_assert_eq!(mac.len(), 17, "bad MAC length: {}", mac);
                    prop_assert!(
                        mac.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b':'),
                        "non-canonical MAC: {mac:?}"
                    );
                    prop_assert_ne!(mac.as_str(), "00:00:00:00:00:00");
                    prop_assert_ne!(mac.as_str(), "ff:ff:ff:ff:ff:ff");
                }
            }

            /// `phones` is total; every hit is `+` followed by 10..=15 digits only.
            #[test]
            fn phones_is_total_and_e164_shaped(s in ".{0,256}") {
                for p in phones(&s) {
                    prop_assert!(p.starts_with('+'), "no leading '+': {p:?}");
                    let digits = p[1..].chars().filter(char::is_ascii_digit).count();
                    prop_assert_eq!(p.len() - 1, digits, "non-digit after '+': {}", p);
                    prop_assert!((10..=15).contains(&digits), "bad phone digit count: {p:?}");
                }
            }

            /// `labeled_ssids` is total; every hit is within the 802.11 1..=32
            /// character bound.
            #[test]
            fn labeled_ssids_is_total_and_bounded(s in ".{0,256}") {
                for ssid in labeled_ssids(&s) {
                    let n = ssid.chars().count();
                    prop_assert!((1..=32).contains(&n), "SSID out of 802.11 range: {ssid:?}");
                }
            }

            /// The credential-field classifier is total and internally consistent
            /// with its own building blocks: an `Email` verdict implies the trimmed
            /// value passes `looks_like_email`; a `Sentinel` implies it is empty or
            /// a placeholder; a `Secret` implies it is none of those.
            #[test]
            fn classify_credential_field_is_total_and_consistent(s in ".{0,256}") {
                let t = s.trim();
                match classify_credential_field(&s) {
                    CredentialField::Email => prop_assert!(looks_like_email(t)),
                    CredentialField::Sentinel => {
                        prop_assert!(t.is_empty() || is_placeholder_secret(t));
                    }
                    CredentialField::Secret => {
                        prop_assert!(!t.is_empty());
                        prop_assert!(!is_placeholder_secret(t));
                        prop_assert!(!looks_like_email(t));
                    }
                }
            }
        }
    }

    #[test]
    fn iban_is_valid_enforces_registered_country_length() {
        // Build an IBAN with correct mod-97 check digits for (country, bban) via
        // the ISO 13616 "98 − mod97(bban+country+00)" construction, so we can
        // isolate the LENGTH gate from the checksum gate.
        fn make_iban(country: &str, bban: &str) -> String {
            let rearranged = format!("{bban}{country}00");
            let mut rem: u32 = 0;
            for c in rearranged.chars() {
                if let Some(d) = c.to_digit(10) {
                    rem = (rem * 10 + d) % 97;
                } else {
                    rem = (rem * 100 + (c as u32 - 'A' as u32 + 10)) % 97;
                }
            }
            let check = 98 - rem;
            format!("{country}{check:02}{bban}")
        }

        // A correctly-sized GB IBAN (22 chars: GB + 2 check + 18 BBAN) is valid.
        let good_gb = make_iban("GB", "WEST12345698765432");
        assert_eq!(good_gb.len(), 22);
        assert!(iban_is_valid(&good_gb));

        // A GB-prefixed string with a SHORT (14-char) BBAN → 18 chars. It passes
        // the mod-97 checksum by construction, so the old `len in 15..=34` gate
        // accepted it — but GB IBANs are exactly 22, so it is not a real account
        // and the registered-length gate now rejects it.
        let short_gb = make_iban("GB", "WEST1234569876");
        assert_eq!(short_gb.len(), 18);
        assert!(
            iban_mod97_valid(&short_gb),
            "constructed to pass the checksum (the old gate would accept it)"
        );
        assert!(
            !iban_is_valid(&short_gb),
            "wrong length for GB (22) must be rejected: {short_gb}"
        );
        // …and end-to-end through the scanner.
        assert!(ibans(&format!("pay {short_gb} now")).is_empty());

        // An UNREGISTERED country code falls back to the 15..=34 spec range (never
        // a false negative on a future registry addition): a 20-char ZZ IBAN with
        // a valid checksum is still accepted.
        let zz = make_iban("ZZ", "1234567890123456");
        assert_eq!(zz.len(), 20);
        assert!(iban_is_valid(&zz), "unknown CC falls back to the spec range");
    }
