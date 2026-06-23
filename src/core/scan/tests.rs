//! Unit tests for target/scan types and scoring.
//!
//! Split out of the module file (mechanical, behaviour-preserving) so the
//! source reads as implementation; tests reach private items via `use super::*`.

use super::*;

#[test]
fn sanitise_strips_surrounding_quotes_and_stray_punctuation() {
    // The exact real failure: a full_name target arrived quoted.
    assert_eq!(sanitise_target_input("\"Jordan Avery\""), "Jordan Avery");
    // Quote + trailing comma (CSV/list paste).
    assert_eq!(sanitise_target_input("\"Jordan Avery\","), "Jordan Avery");
    assert_eq!(sanitise_target_input("'jdoe'"), "jdoe");
    assert_eq!(sanitise_target_input("  jdoe ;"), "jdoe");
    // Unicode smart quotes.
    assert_eq!(
        sanitise_target_input("\u{201C}Jane Roe\u{201D}"),
        "Jane Roe"
    );
    // Inner punctuation/quotes are preserved — only the bounding layer goes.
    assert_eq!(sanitise_target_input("a\"b"), "a\"b");
    assert_eq!(sanitise_target_input("o'brien"), "o'brien");
    // Idempotent on already-clean input; doesn't mangle structured kinds.
    assert_eq!(
        sanitise_target_input("jordanavery@gmail.com"),
        "jordanavery@gmail.com"
    );
    assert_eq!(sanitise_target_input(""), "");
}

#[test]
fn target_new_sanitises_quoted_full_name() {
    // End-to-end through the user-input boundary: the quotes never reach
    // the stored value (and thus never reach name permutations).
    let t = Target::new(TargetKind::FullName, "\"Jordan Avery\"");
    assert_eq!(t.value, "Jordan Avery");
}

#[test]
fn options_default_is_inert() {
    let o = ScanOptions::default();
    assert!(o.modules.is_none());
    assert_eq!(o.throttle_ms, 0);
    assert!(!o.free_only);
    assert!(!o.passive_only);
    assert_eq!(o.depth, 0);
    assert!((o.min_expand_confidence - 0.50).abs() < 1e-9);
    // Gentle by default (2, not 4) so deep/everything scans don't flood the
    // link or trip provider rate limits.
    assert_eq!(o.max_concurrent, 2);
}

#[test]
fn clamp_depth_enforces_max_depth() {
    assert_eq!(MAX_DEPTH, 3);
    let over = ScanOptions {
        depth: 99,
        ..Default::default()
    };
    assert_eq!(
        over.clamp_depth().depth,
        MAX_DEPTH,
        "deep request is capped"
    );
    let under = ScanOptions {
        depth: 2,
        ..Default::default()
    };
    assert_eq!(under.clamp_depth().depth, 2, "in-range depth is untouched");
}

#[test]
fn optimal_depth_never_exceeds_max_depth_and_is_at_least_one() {
    // Iterate the CANONICAL kind list so a newly-added TargetKind is forced
    // through the depth model (the exhaustive `match`es panic-free here).
    for &kind in crate::core::dependency::ALL_TARGET_KINDS {
        for paid in [true, false] {
            let (d, c) = optimal_depth(kind, paid);
            assert!(
                (1..=MAX_DEPTH).contains(&d),
                "{kind:?} paid={paid}: depth {d}"
            );
            assert!((0.40..=0.55).contains(&c), "{kind:?} paid={paid}: conf {c}");
        }
    }
}

#[test]
fn optimal_depth_is_differentiated_not_pinned_at_ceiling() {
    // Regression guard for the old bug: the hand-tuned 4/5 constants were
    // all flattened to 3 by `.min(MAX_DEPTH)`, so depth carried no signal.
    // The yield model MUST spread depth across the [1, MAX_DEPTH] range.
    let depths: std::collections::BTreeSet<u32> = crate::core::dependency::ALL_TARGET_KINDS
        .iter()
        .flat_map(|&k| [optimal_depth(k, true).0, optimal_depth(k, false).0])
        .collect();
    assert!(
        depths.len() >= 3,
        "depth must be differentiated across kinds, saw only {depths:?}"
    );
    assert!(
        depths.contains(&1),
        "some terminal seed must resolve at depth 1"
    );
    assert!(
        depths.contains(&MAX_DEPTH),
        "some rich seed must reach MAX_DEPTH"
    );

    // Rich identity seeds with paid keys earn the full budget…
    for k in [
        TargetKind::Email,
        TargetKind::FullName,
        TargetKind::Username,
        TargetKind::Domain,
    ] {
        assert_eq!(
            optimal_depth(k, true).0,
            MAX_DEPTH,
            "{k:?} paid → MAX_DEPTH"
        );
        assert_eq!(optimal_depth(k, false).0, 2, "{k:?} keyless → 2");
    }
    // …terminal / registry seeds resolve in a single round.
    for k in [
        TargetKind::Coordinates,
        TargetKind::AbnAcn,
        TargetKind::ApiKey,
    ] {
        assert_eq!(optimal_depth(k, true).0, 1, "{k:?} is terminal");
        assert_eq!(optimal_depth(k, false).0, 1, "{k:?} is terminal");
    }
}

#[test]
fn optimal_depth_paid_tier_is_never_shallower_than_free() {
    for &kind in crate::core::dependency::ALL_TARGET_KINDS {
        assert!(
            optimal_depth(kind, true).0 >= optimal_depth(kind, false).0,
            "{kind:?}: paid depth must be ≥ free depth"
        );
    }
}

#[test]
fn optimal_depth_respects_the_marginal_yield_floor() {
    // The core statistical invariant: the chosen depth D is exactly the
    // cutoff of the yield curve — round D clears the floor, and round D+1
    // (if one exists below MAX_DEPTH) does not. This is what makes the
    // depth a *decision* rather than a constant.
    for &kind in crate::core::dependency::ALL_TARGET_KINDS {
        for paid in [true, false] {
            let (d, _) = optimal_depth(kind, paid);
            assert!(
                predicted_marginal_yield(kind, paid, d) >= MARGINAL_YIELD_FLOOR - f64::EPSILON,
                "{kind:?} paid={paid}: round {d} must clear the floor"
            );
            if d < MAX_DEPTH {
                assert!(
                    predicted_marginal_yield(kind, paid, d + 1) < MARGINAL_YIELD_FLOOR,
                    "{kind:?} paid={paid}: round {} must fall below the floor",
                    d + 1
                );
            }
        }
    }
}

#[test]
fn predicted_marginal_yield_decays_monotonically_with_round() {
    // 0 < q < 1 and m₁ > 0 ⇒ each round is strictly less productive than
    // the last — the property the depth cutoff relies on.
    for &kind in crate::core::dependency::ALL_TARGET_KINDS {
        for paid in [true, false] {
            let mut prev = f64::INFINITY;
            for round in 1..=MAX_DEPTH + 1 {
                let y = predicted_marginal_yield(kind, paid, round);
                assert!(y > 0.0, "{kind:?}: yield must stay positive");
                assert!(y < prev, "{kind:?} round {round}: yield must decay");
                prev = y;
            }
        }
    }
}

#[test]
fn seed_yield_ordering_matches_observed_transcript() {
    // Live transcript: FullName seed surfaced 446 entities, Username 91.
    // The model's round-1 yields must preserve that ≫ ordering, and the
    // richest identity seeds must out-yield terminal seeds.
    for paid in [true, false] {
        assert!(
            seed_marginal_yield(TargetKind::FullName, paid)
                > seed_marginal_yield(TargetKind::Username, paid)
        );
        assert!(
            seed_marginal_yield(TargetKind::Email, paid)
                >= seed_marginal_yield(TargetKind::FullName, paid)
        );
        assert!(
            seed_marginal_yield(TargetKind::Username, paid)
                > seed_marginal_yield(TargetKind::ApiKey, paid)
        );
    }
}

#[test]
fn auto_min_expand_confidence_rises_with_depth_within_band() {
    // Deeper scans are more selective; every value stays in [0.40, 0.55];
    // the paid tier starts no higher than the free tier at equal depth.
    for paid in [true, false] {
        let c1 = auto_min_expand_confidence(1, paid);
        let c2 = auto_min_expand_confidence(2, paid);
        let c3 = auto_min_expand_confidence(3, paid);
        assert!(
            c1 <= c2 && c2 <= c3,
            "confidence floor must rise with depth"
        );
        for c in [c1, c2, c3] {
            assert!((0.40..=0.55).contains(&c));
        }
    }
    for d in 1..=MAX_DEPTH {
        assert!(auto_min_expand_confidence(d, true) <= auto_min_expand_confidence(d, false));
    }
}

#[test]
fn identity_overlap_ties_aliases_and_rejects_strangers() {
    let subject = "jordanavery@gmail.com";
    // Real aliases share a ≥4 substring with the subject handle.
    assert!(identity_overlaps(subject, "jordanavery"));
    assert!(identity_overlaps(subject, "therealfatjordan")); // "jordan"
    assert!(identity_overlaps(subject, "jord.avery")); // "avery"/"jord"
    assert!(identity_overlaps("Jordan Avery", "becky.avery")); // "avery"
    // Unrelated handles do NOT — the wrong-identity rabbit holes.
    assert!(!identity_overlaps(subject, "arizonambb"));
    assert!(!identity_overlaps(subject, "centenario"));
    assert!(!identity_overlaps(subject, "ideasfactory009"));
    // Symmetry + email-local extraction.
    assert!(identity_overlaps("jordanavery", "jordanavery@x.org"));
    // Short identities must match exactly.
    assert!(identity_overlaps("abc", "abc"));
    assert!(!identity_overlaps("abc", "abd"));
    // Empty / punctuation-only never matches.
    assert!(!identity_overlaps("", "jordanavery"));
    assert!(!identity_overlaps("...", "jordanavery"));
}

#[test]
fn wrong_identity_pivot_gates_only_unrelated_weak_single_source_identities() {
    use crate::core::entity::EntityKind;
    let subject = vec!["jordanavery".to_string()];

    // The canonical rabbit hole: an unrelated, weak, single-source handle.
    assert!(is_wrong_identity_pivot(
        &EntityKind::Username,
        0.50,
        1,
        "arizonambb",
        &subject
    ));

    // A genuine alias overlapping the subject is NEVER gated.
    assert!(!is_wrong_identity_pivot(
        &EntityKind::Username,
        0.50,
        1,
        "therealfatjordan", // shares "jordan"
        &subject
    ));

    // Verified confidence earns expansion even with no overlap.
    assert!(!is_wrong_identity_pivot(
        &EntityKind::Person,
        0.80,
        1,
        "arizonambb",
        &subject
    ));

    // Multi-source corroboration earns expansion even with no overlap.
    assert!(!is_wrong_identity_pivot(
        &EntityKind::Username,
        0.50,
        2,
        "arizonambb",
        &subject
    ));

    // Non-identity kinds are never subject to the gate.
    assert!(!is_wrong_identity_pivot(
        &EntityKind::Domain,
        0.10,
        1,
        "arizonambb",
        &subject
    ));

    // An empty subject set (no confirmed identity yet) still gates an
    // unrelated weak handle — there is nothing for it to overlap with.
    assert!(is_wrong_identity_pivot(
        &EntityKind::Username,
        0.50,
        1,
        "arizonambb",
        &[]
    ));
}

#[test]
fn identity_norm_strips_to_email_local_and_alnum() {
    assert_eq!(identity_norm("Matt.Avery@gmail.com"), "mattavery");
    assert_eq!(identity_norm("the_real-matt"), "therealmatt");
}

#[test]
fn is_mega_domain_matches_roots_subdomains_and_www() {
    for d in [
        "facebook.com",
        "www.facebook.com",
        "m.facebook.com",
        "PINTEREST.COM",
        "api.twitter.com",
        "github.com",
        // People-search aggregators — the stranger co-occurrence noise this list
        // exists to dampen.
        "fastpeoplesearch.com",
        "thatsthem.com",
        "clustrmaps.com",
        "zoominfo.com",
        "rocketreach.co",
    ] {
        assert!(is_mega_domain(d), "{d} should be a mega-domain");
    }
    for d in [
        "target-company.com.au",
        "johndoe.com",
        "notfacebook.com", // suffix look-alike must not match
        "facebookx.com",
    ] {
        assert!(!is_mega_domain(d), "{d} must NOT be a mega-domain");
    }
}

#[test]
fn is_infra_domain_matches_shared_providers() {
    // The shared mail/DNS/registrar infra that flooded the real scan.
    for d in [
        "secureserver.net",
        "cns1.secureserver.net",
        "u10020310.ct.sendgrid.net",
        "ns10.dnsmadeeasy.com",
        "a1-245.akam.net",
        "ns-664.awsdns-19.net",    // AWS Route 53 (varying shard root)
        "ns-1778.awsdns-30.co.uk", // …including the co.uk shard
        "MIMECAST.COM",
        "jomax.net",     // GoDaddy registrar/abuse mail (dns@jomax.net)
        "ns1.jomax.net", // …and its nameservers
        "epik.com",      // registrar / nameserver provider
        "ns3.epik.com",
        "registrar-servers.com", // Namecheap control-plane
        // Cloud DNS / CDN / cloud-app / ESP / mail-gateway infra (suffix-matched
        // on the realistic NS / CNAME / MX forms they surface as).
        "ns1-05.azure-dns.com",
        "ns2-09.azure-dns.net",
        "ns-cloud-a1.googledomains.com",
        "ns1.cloudns.net",
        "myapp.azureedge.net",
        "myservice.cloudapp.net",
        "django-env.elasticbeanstalk.com",
        "us5.list-manage.com",
        "target-com.mail.protection.outlook.com", // M365 EOP MX
        "mx.emailsrvr.com",
    ] {
        assert!(is_infra_domain(d), "{d} should be shared infra");
        assert!(is_noncentral_domain(d), "{d} should be non-central");
    }
    // A subject's own domain (even on a normal registrar) is NOT infra.
    for d in ["target-company.com.au", "johndoe.org", "acme-widgets.com"] {
        assert!(!is_infra_domain(d), "{d} must NOT be shared infra");
    }
    // The M365 gateway suffix must NOT swallow `outlook.com` freemail itself —
    // a subject's `…@outlook.com` is a prime finding, never infra.
    assert!(
        !is_infra_domain("outlook.com"),
        "outlook.com freemail is not infra"
    );
}

#[test]
fn expansion_weight_dampens_mega_domains() {
    let facebook = expansion_weight(TargetKind::Domain, 1.0, "facebook.com", false);
    let specific = expansion_weight(TargetKind::Domain, 1.0, "target-company.com.au", false);
    assert!(
        specific > facebook * 5.0,
        "target-specific domain ({specific:.1}) should far outrank facebook ({facebook:.1})"
    );
}

#[test]
fn expansion_weight_address_beats_mega_domain() {
    let addr = expansion_weight(TargetKind::Address, 0.80, "Brisbane, QLD", false);
    let fb = expansion_weight(TargetKind::Domain, 1.0, "facebook.com", false);
    assert!(
        addr > fb,
        "validated address ({addr:.1}) should outrank dampened mega-domain ({fb:.1})"
    );
}

#[test]
fn cidr_is_geo_convergent_and_outranks_its_parent_asn() {
    // A CIDR enumerates into host IPs that geo-resolve, so it must carry a
    // geo-proximity boost — not fall through to the non-geo 1.0 default, which
    // ranked it BELOW the ASN that produced it (inverted ordering, since a Cidr
    // is one hop CLOSER to coordinates than its ASN). At equal confidence the
    // geo-convergence ladder must read ASN < Cidr < IpAddress.
    let asn = expansion_weight(TargetKind::Asn, 0.8, "AS13335", false);
    let cidr = expansion_weight(TargetKind::Cidr, 0.8, "192.0.2.0/24", false);
    let ip = expansion_weight(TargetKind::IpAddress, 0.8, "192.0.2.10", false);
    assert!(
        asn < cidr && cidr < ip,
        "geo-convergence ladder must be ASN ({asn:.2}) < Cidr ({cidr:.2}) < IP ({ip:.2})"
    );
    // And a Cidr must beat a non-geo terminal kind of equal confidence — proof
    // it is no longer treated as non-geo (boost 1.0).
    let crypto = expansion_weight(TargetKind::CryptoAddress, 0.8, "bc1qxyz", false);
    assert!(
        cidr > crypto,
        "Cidr ({cidr:.2}) is geo-convergent vs crypto ({crypto:.2})"
    );
}

#[test]
fn expansion_weight_respects_confidence() {
    let high = expansion_weight(TargetKind::Domain, 0.90, "example.com", false);
    let low = expansion_weight(TargetKind::Domain, 0.45, "example.com", false);
    assert!(high > low * 1.9);
}

#[test]
fn convex_budget_lifts_identity_above_saturated_infrastructure() {
    // Completes the convex (optionality / barbell) budget feature: proves the
    // engine's exact composition — base weight × optionality_multiplier — does
    // what the flag claims, not just that the multiplier math is right in
    // isolation. Models the canonical case the feature exists for: a cheap,
    // information-rich, uncertain, single-source IDENTITY lead vs an expensive,
    // saturated, heavily-corroborated INFRASTRUCTURE domain.
    use crate::core::convex::optionality_multiplier;
    let strat = ExpansionStrategy::BreadthFirst;

    // Base ranking (no --convex-budget): the engine multiplies the strategy
    // weight by the corroboration prior. Expected value favours the saturated,
    // well-corroborated domain over the uncertain single-source email.
    let id_base = expansion_weight_for_strategy(
        strat,
        TargetKind::Email,
        0.55,
        "jordan@gmail.com",
        false,
        0.9,
    ) * corroboration_prior(1);
    let infra_base =
        expansion_weight_for_strategy(strat, TargetKind::Domain, 0.95, "example.com", false, 0.6)
            * corroboration_prior(6);
    assert!(
        infra_base > id_base,
        "without convex budget, expected value ranks infra above identity ({infra_base:.3} vs {id_base:.3})"
    );

    // With --convex-budget the engine multiplies in the optionality factor
    // (convexity premium ÷ dispatch cost). It must flip the order — and the tilt
    // toward identity is monotone (the identity:infra ratio strictly increases).
    let id_final = id_base * optionality_multiplier(TargetKind::Email, 1, 0.55, 0.9);
    let infra_final = infra_base * optionality_multiplier(TargetKind::Domain, 6, 0.95, 0.6);
    assert!(
        id_final > infra_final,
        "convex budget must lift the cheap rich identity lead above saturated infra ({id_final:.3} vs {infra_final:.3})"
    );
    assert!(
        id_final / infra_final > id_base / infra_base,
        "convex re-weighting must strictly increase the identity:infra ratio"
    );
}

#[test]
fn corroboration_prior_is_neutral_at_one_source_and_grows_diminishingly() {
    // Single source must not penalise vs today's behaviour: exactly 1.0.
    assert!((corroboration_prior(1) - 1.0).abs() < 1e-12);
    // 0 is floored to 1 (defensive).
    assert!((corroboration_prior(0) - 1.0).abs() < 1e-12);
    // Strictly increasing with independent sources…
    assert!(corroboration_prior(2) > corroboration_prior(1));
    assert!(corroboration_prior(4) > corroboration_prior(2));
    assert!(corroboration_prior(8) > corroboration_prior(4));
    // …with diminishing returns (concave: each doubling adds a constant,
    // shrinking increment relative to the level).
    let d_1_2 = corroboration_prior(2) - corroboration_prior(1);
    let d_2_4 = corroboration_prior(4) - corroboration_prior(2);
    assert!((d_1_2 - d_2_4).abs() < 1e-9, "ln doubling steps are equal");
    assert!(corroboration_prior(4) - corroboration_prior(2) < d_1_2 * 1.0 + 1e-9);
}

#[test]
fn corroboration_prior_refines_within_tier_never_overrides_geo() {
    // A heavily-corroborated FAR entity must still rank below a
    // single-source geo-proximate IP — corroboration refines order within
    // a geo tier, it does not invert the geo-convergence priority.
    let far_8src =
        expansion_weight(TargetKind::Organisation, 0.80, "x", false) * corroboration_prior(8);
    let ip_1src =
        expansion_weight(TargetKind::IpAddress, 0.80, "8.8.8.8", false) * corroboration_prior(1);
    assert!(
        ip_1src > far_8src,
        "geo-proximate IP ({ip_1src:.1}) must outrank corroborated org ({far_8src:.1})"
    );
    // But within the SAME kind, corroboration breaks the c_eff=1.0 tie.
    let a = expansion_weight(TargetKind::Email, 1.0, "a@x.com", true) * corroboration_prior(6);
    let b = expansion_weight(TargetKind::Email, 1.0, "b@x.com", true) * corroboration_prior(1);
    assert!(a > b, "6-source email must outrank 1-source at equal c_eff");
}

#[test]
fn mega_domain_list_catches_common_noise() {
    assert!(domain_expansion_factor("facebook.com") < 0.5);
    assert!(domain_expansion_factor("www.reddit.com") < 0.5);
    assert!(domain_expansion_factor("whitepages.com") < 0.5);
    assert!((domain_expansion_factor("target-specific.com.au") - 1.0).abs() < 1e-9);
}

#[test]
fn target_kind_round_trips_via_entity_kind() {
    for tk in [
        TargetKind::Email,
        TargetKind::Username,
        TargetKind::Phone,
        TargetKind::FullName,
        TargetKind::IpAddress,
        TargetKind::Domain,
        TargetKind::Url,
        TargetKind::Asn,
        TargetKind::Coordinates,
        TargetKind::Address,
        TargetKind::Organisation,
        TargetKind::AbnAcn,
        TargetKind::ApiKey,
    ] {
        let ek = tk.to_entity_kind();
        assert_eq!(TargetKind::from_entity_kind(&ek), Some(tk));
    }
}

#[test]
fn unscannable_entity_kinds_return_none() {
    assert!(TargetKind::from_entity_kind(&EntityKind::Password).is_none());
    assert!(TargetKind::from_entity_kind(&EntityKind::Credential).is_none());
}

#[test]
fn mac_address_entity_expands() {
    assert_eq!(
        TargetKind::from_entity_kind(&EntityKind::MacAddress),
        Some(TargetKind::MacAddress)
    );
}

#[test]
fn api_key_entity_expands() {
    assert_eq!(
        TargetKind::from_entity_kind(&EntityKind::ApiKey),
        Some(TargetKind::ApiKey)
    );
}

#[test]
fn options_round_trip_json() {
    let o = ScanOptions {
        modules: Some(vec!["hibp".into(), "crtsh".into()]),
        throttle_ms: 250,
        free_only: true,
        ..Default::default()
    };
    let s = serde_json::to_string(&o).unwrap();
    let back: ScanOptions = serde_json::from_str(&s).unwrap();
    assert_eq!(back.modules.as_ref().unwrap().len(), 2);
    assert_eq!(back.throttle_ms, 250);
    assert!(back.free_only);
}

#[test]
fn scan_request_round_trip() {
    let req = ScanRequest {
        kind: Some(TargetKind::Email),
        value: "x@y.com".into(),
        options: ScanOptions::default(),
    };
    let s = serde_json::to_string(&req).unwrap();
    assert!(s.contains("\"kind\":\"email\""));

    // Omitted kind → None → auto-detected; the field is skipped on the wire.
    let auto: ScanRequest = serde_json::from_str(r#"{"value":"x@y.com"}"#).unwrap();
    assert_eq!(auto.kind, None);
    assert_eq!(auto.resolved_kind(), TargetKind::Email);
    assert!(!serde_json::to_string(&auto).unwrap().contains("kind"));
}

// ── TargetKind::detect — unified-scan auto-detection ──────────────────────

#[test]
fn detect_classifies_structured_kinds() {
    use TargetKind::*;
    let cases = [
        ("https://example.com/page", Url),
        ("http://x.io", Url),
        ("alice@example.com", Email),
        ("8.8.8.8", IpAddress),
        ("2001:4860:4860::8888", IpAddress),
        ("aa:bb:cc:dd:ee:ff", MacAddress),
        ("AA-BB-CC-DD-EE-FF", MacAddress),
        // Cisco dotted form — accepted by Target::validate(MacAddress), so
        // detect must classify it too (it previously fell through to Domain
        // for letters-only hex, or Username when a group carried a digit).
        ("aabb.ccdd.eeff", MacAddress),
        ("AB12.CD34.EF56", MacAddress),
        ("-33.8688,151.2093", Coordinates),
        // Self-evident rich coordinate notations now auto-detect too (the
        // handle-shaped Maidenhead and bare space-separated decimals do not).
        ("27°28'35.8\"S 153°00'59.8\"E", Coordinates), // degrees-minutes-seconds
        ("geo:-27.4766,153.0166", Coordinates),        // RFC 5870 geo: URI
        ("8FVC9G8F+6X", Coordinates),                  // Plus Code / Open Location Code
        ("AS13335", Asn),
        ("as15169", Asn),
        ("51824753556", AbnAcn),    // valid ABN (ATO worked example)
        ("51 824 753 556", AbnAcn), // spaced ABN
        ("+61 400 123 456", Phone),
        ("(07) 3000 1234", Phone),
        // CIDR — checked after a bare IP, before domain.
        ("192.0.2.0/24", Cidr),
        ("2001:db8::/48", Cidr),
        // Crypto wallet addresses — checked before the free-text fallback so a
        // pasted address is never mis-bucketed as a Username.
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", CryptoAddress), // BTC P2PKH (genesis)
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", CryptoAddress), // BTC bech32
        ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", CryptoAddress), // ETH
        ("example.com", Domain),
        ("sub.example.co.uk", Domain),
    ];
    for (value, want) in cases {
        assert_eq!(TargetKind::detect(value), want, "detect({value:?})");
    }
}

#[test]
fn rich_coordinate_notations_normalise_to_canonical_decimal() {
    // A self-evident notation auto-detects AND its value is canonicalised to the
    // 6-dp "lat,lon" every downstream geo consumer already speaks.
    let dms = Target::detect("27°28'35.8\"S 153°00'59.8\"E");
    assert_eq!(dms.kind, TargetKind::Coordinates);
    assert_eq!(dms.value, "-27.476611,153.016611");

    let geo = Target::detect("geo:-27.4766,153.0166");
    assert_eq!(geo.kind, TargetKind::Coordinates);
    assert_eq!(geo.value, "-27.476600,153.016600");

    // A Maidenhead locator is handle-shaped, so it is NOT auto-detected …
    assert_ne!(TargetKind::detect("QG62kn"), TargetKind::Coordinates);
    // … yet an explicit `--kind coordinates` accepts and normalises it.
    let grid = Target::new(TargetKind::Coordinates, "QG62kn");
    assert_eq!(grid.value, "-27.437500,152.875000");
}

#[test]
fn detect_classifies_free_text() {
    use TargetKind::*;
    assert_eq!(TargetKind::detect("jsmith"), Username);
    assert_eq!(TargetKind::detect("shinigami_jerome"), Username);
    assert_eq!(TargetKind::detect("Jordan Avery"), FullName);
    assert_eq!(TargetKind::detect("Acme Pty Ltd"), Organisation);
    assert_eq!(TargetKind::detect("Globex Corporation"), Organisation);
    assert_eq!(TargetKind::detect("123 Main St, Springfield"), Address);
}

#[test]
fn detect_disambiguates_overlapping_shapes() {
    // Dotted-but-valid IP beats domain.
    assert_eq!(TargetKind::detect("8.8.8.8"), TargetKind::IpAddress);
    // 11 digits that are NOT a valid ABN fall through to phone.
    assert_eq!(TargetKind::detect("12345678901"), TargetKind::Phone);
    // A valid ABN of the same length is recognised as the registry id.
    assert_eq!(TargetKind::detect("51824753556"), TargetKind::AbnAcn);
    // '+' is valid only once and only leading: a stray internal '+' is not
    // a phone, but a normal international number still is.
    assert_ne!(TargetKind::detect("+123+4567"), TargetKind::Phone);
    assert_eq!(TargetKind::detect("+61400123456"), TargetKind::Phone);
}

#[test]
fn detect_never_panics_on_junk() {
    let big = "x".repeat(2000);
    let junk = [
        "",
        "   ",
        "@",
        "a@b",
        "...",
        "::::::",
        "+",
        "AS",
        "9999",
        "🦀",
        "a b c d e f",
        "-",
        big.as_str(),
    ];
    for v in junk {
        let _ = TargetKind::detect(v); // must not panic
    }
}

#[test]
fn detect_then_validate_round_trips_clean_values() {
    // A value detected from a clean input must pass Target::validate, so the
    // unified path never produces a target the engine would reject.
    // Real (non-placeholder) values: `validate` rejects reserved
    // documentation domains like example.com, so use live ones here.
    for v in [
        "alice@proton.me",
        "cloudflare.com",
        "8.8.8.8",
        "AS13335",
        "+61400123456",
        "Jordan Avery",
        "jsmith",
        "https://cloudflare.com/p",
    ] {
        let t = Target::detect(v);
        assert!(
            t.validate().is_ok(),
            "detect+validate failed for {v:?}: {t:?}"
        );
    }
}

#[test]
fn target_detect_resolves_and_normalises() {
    let t = Target::detect("Alice@Example.Com");
    assert_eq!(t.kind, TargetKind::Email);
    assert_eq!(t.value, "alice@example.com"); // email normalisation lowercases
    // Quoted name: detection sees through the quotes; value is sanitised.
    let t2 = Target::detect("\"Jordan Avery\"");
    assert_eq!(t2.kind, TargetKind::FullName);
    assert_eq!(t2.value, "Jordan Avery");
}

#[test]
fn auto_detect_sanitises_before_classifying() {
    // Regression (PR #102 review): the auto-detect paths must sanitise paste
    // artifacts (surrounding quotes + trailing separators) BEFORE
    // classifying, exactly as `Target::new` sanitises the stored value —
    // otherwise a pasted `"https://x.com",` is classed `Username` while the
    // stored value is a URL, routing the scan through the wrong modules.
    let dirty = "\"https://cloudflare.com\",";
    assert_eq!(detect_kind(dirty), TargetKind::Url);
    assert_eq!(Target::detect(dirty).kind, TargetKind::Url);
    // The shared helper is what every entry point uses:
    let req = ScanRequest {
        kind: None,
        value: dirty.to_string(),
        options: ScanOptions::default(),
    };
    assert_eq!(req.resolved_kind(), TargetKind::Url);
    // And the detected kind agrees with the value the target will store.
    assert_eq!(Target::detect(dirty).value, "https://cloudflare.com");
}

// ── Target::validate ────────────────────────────────────────────────────
#[test]
fn validate_rejects_empty_and_oversize() {
    assert!(Target::new(TargetKind::Email, "").validate().is_err());
    assert!(
        Target::new(TargetKind::Email, "x".repeat(2000))
            .validate()
            .is_err()
    );
}

#[test]
fn validate_rejects_control_chars() {
    assert!(
        Target::new(TargetKind::Email, "x@y\ncom")
            .validate()
            .is_err()
    );
}

#[test]
fn validate_rejects_mixed_script_homograph() {
    // A Cyrillic-`а` `pаypal.com` reads as the ASCII brand but is a distinct
    // entity — the classic homograph spoof — and must be rejected.
    assert!(
        Target::new(TargetKind::Domain, "p\u{0430}ypal.com")
            .validate()
            .is_err()
    );
    // The clean ASCII seed passes (no behavioural change for legitimate input).
    assert!(
        Target::new(TargetKind::Domain, "paypal.com")
            .validate()
            .is_ok()
    );
}

#[test]
fn sanitise_strips_invisible_unicode() {
    // A zero-width joiner padded into a value is removed at the ingestion
    // boundary so the two spellings finally normalise to one (fixes silent
    // non-dedup); clean input is unchanged.
    assert_eq!(sanitise_target_input("jo\u{200D}hn"), "john");
    assert_eq!(sanitise_target_input("john"), "john");
}

#[test]
fn validate_email() {
    assert!(Target::new(TargetKind::Email, "a@b.com").validate().is_ok());
    assert!(
        Target::new(TargetKind::Email, "noatsign")
            .validate()
            .is_err()
    );
    assert!(Target::new(TargetKind::Email, "@b.com").validate().is_err());
    assert!(Target::new(TargetKind::Email, "a@b").validate().is_err()); // no dot
}

#[test]
fn validate_abn_acn_requires_9_or_11_digits() {
    // ABN (11) / ACN (9), spaces & punctuation ignored.
    assert!(
        Target::new(TargetKind::AbnAcn, "51824753556")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::AbnAcn, "51 824 753 556")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::AbnAcn, "004085616")
            .validate()
            .is_ok()
    );
    // Non-registry junk (e.g. a handle) must fail fast, not dispatch a no-op.
    assert!(
        Target::new(TargetKind::AbnAcn, "Kylo4kylo")
            .validate()
            .is_err()
    );
    assert!(Target::new(TargetKind::AbnAcn, "12345").validate().is_err());
}

#[test]
fn validate_mac_requires_six_hex_octets() {
    assert!(
        Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE:FF")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::MacAddress, "aa-bb-cc-dd-ee-ff")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::MacAddress, "aabbccddeeff")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::MacAddress, "Kylo4kylo")
            .validate()
            .is_err()
    );
    assert!(
        Target::new(TargetKind::MacAddress, "AA:BB:CC:DD:EE")
            .validate()
            .is_err()
    ); // 5 octets
    assert!(
        Target::new(TargetKind::MacAddress, "ZZ:BB:CC:DD:EE:FF")
            .validate()
            .is_err()
    ); // non-hex
}

#[test]
fn validate_domain() {
    assert!(
        Target::new(TargetKind::Domain, "cloudflare.com")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::Domain, "single")
            .validate()
            .is_err()
    ); // no dot
    assert!(
        Target::new(TargetKind::Domain, "bad domain.com")
            .validate()
            .is_err()
    ); // space
    // Reserved/placeholder domains are rejected at the seed boundary.
    assert!(
        Target::new(TargetKind::Domain, "example.com")
            .validate()
            .is_err(),
        "example.com is a reserved placeholder — must not be scannable"
    );
    assert!(
        Target::new(TargetKind::Email, "jordan@example.com")
            .validate()
            .is_err(),
        "placeholder email host must be rejected"
    );
}

#[test]
fn validate_ip() {
    assert!(
        Target::new(TargetKind::IpAddress, "1.1.1.1")
            .validate()
            .is_ok()
    );
    assert!(Target::new(TargetKind::IpAddress, "::1").validate().is_ok());
    assert!(
        Target::new(TargetKind::IpAddress, "999.999.999.999")
            .validate()
            .is_err()
    );
}

#[test]
fn validate_asn() {
    assert!(Target::new(TargetKind::Asn, "AS13335").validate().is_ok());
    assert!(Target::new(TargetKind::Asn, "13335").validate().is_ok());
    assert!(Target::new(TargetKind::Asn, "BS13335").validate().is_err());
}

#[test]
fn validate_phone() {
    assert!(
        Target::new(TargetKind::Phone, "+1-234-567-8901")
            .validate()
            .is_ok()
    );
    assert!(Target::new(TargetKind::Phone, "+1").validate().is_err()); // too short
}

#[test]
fn validate_coordinates() {
    assert!(
        Target::new(TargetKind::Coordinates, "-33.8688,151.2093")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::Coordinates, "91,0")
            .validate()
            .is_err()
    ); // lat out of range
    assert!(
        Target::new(TargetKind::Coordinates, "0,181")
            .validate()
            .is_err()
    ); // lon out of range
    assert!(
        Target::new(TargetKind::Coordinates, "not-coords")
            .validate()
            .is_err()
    );
}

// ── ExpansionStrategy ───────────────────────────────────────────────────

#[test]
fn expansion_strategy_default_is_geo_converge() {
    assert_eq!(ExpansionStrategy::default(), ExpansionStrategy::GeoConverge);
    assert_eq!(ExpansionStrategy::default().as_str(), "geo_converge");
}

#[test]
fn target_kind_canonical_str_matches_serde() {
    // CONVENTIONS.md §3: canonical_str is the persisted `scans.target_kind`
    // column, a scan_id hash input, and the event/API wire label — and its
    // doc explicitly promises it equals the serde form. Pin every variant so
    // a future TargetKind rename can't split the hand-written string from the
    // derive. Iterates the canonical list, so a new variant is forced through.
    for &k in crate::core::dependency::ALL_TARGET_KINDS {
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json.trim_matches('"'), k.canonical_str(), "{k:?}");
    }
}

#[test]
fn scan_status_as_str_matches_serde() {
    // §3 pin. as_str is the persisted `scans.status` value AND
    // `latest_completed_scan` hard-codes the string in its SQL
    // `json_extract(...) = 'complete'` probe — a drift between as_str and the
    // serde form would silently break that query (no Complete scan found).
    for st in [
        ScanStatus::Pending,
        ScanStatus::Running,
        ScanStatus::Complete,
        ScanStatus::Failed,
        ScanStatus::Aborted,
    ] {
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(json.trim_matches('"'), st.as_str(), "{st:?}");
    }
}

#[test]
fn expansion_strategy_round_trips_json() {
    for s in [
        ExpansionStrategy::GeoConverge,
        ExpansionStrategy::BreadthFirst,
        ExpansionStrategy::DepthFirst,
        ExpansionStrategy::RichestFirst,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json.trim_matches('"'), s.as_str());
        let back: ExpansionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn expansion_strategy_from_str_accepts_every_variant() {
    for s in [
        ExpansionStrategy::GeoConverge,
        ExpansionStrategy::BreadthFirst,
        ExpansionStrategy::DepthFirst,
        ExpansionStrategy::RichestFirst,
    ] {
        let parsed: ExpansionStrategy = s.as_str().parse().unwrap();
        assert_eq!(parsed, s);
    }
}

#[test]
fn expansion_strategy_from_str_treats_empty_as_default() {
    let parsed: ExpansionStrategy = "".parse().unwrap();
    assert_eq!(parsed, ExpansionStrategy::default());
}

#[test]
fn expansion_strategy_from_str_rejects_unknown_with_useful_message() {
    let err = "wat".parse::<ExpansionStrategy>().unwrap_err();
    assert!(err.contains("wat"));
    assert!(err.contains("geo_converge"));
    assert!(err.contains("breadth_first"));
    assert!(err.contains("depth_first"));
    assert!(err.contains("richest_first"));
}

#[test]
fn strategy_geo_converge_matches_legacy_weight_at_full_richness() {
    let legacy = expansion_weight(TargetKind::Domain, 0.8, "example.com", false);
    let strat = expansion_weight_for_strategy(
        ExpansionStrategy::GeoConverge,
        TargetKind::Domain,
        0.8,
        "example.com",
        false,
        1.0,
    );
    assert!((legacy - strat).abs() < 1e-9);
}

#[test]
fn strategy_breadth_first_is_geo_agnostic() {
    // BreadthFirst should rank IP and Domain similarly when c_eff
    // matches — geo_proximity_boost no longer dominates.
    let ip = expansion_weight_for_strategy(
        ExpansionStrategy::BreadthFirst,
        TargetKind::IpAddress,
        0.8,
        "1.1.1.1",
        false,
        0.5,
    );
    let domain = expansion_weight_for_strategy(
        ExpansionStrategy::BreadthFirst,
        TargetKind::Domain,
        0.8,
        "example.com",
        false,
        0.5,
    );
    // Same c_eff and richness → identical weight under BreadthFirst.
    assert!((ip - domain).abs() < 1e-9);
}

#[test]
fn strategy_richest_first_prioritises_high_richness() {
    let rich = expansion_weight_for_strategy(
        ExpansionStrategy::RichestFirst,
        TargetKind::Email,
        0.6,
        "a@b.com",
        false,
        1.0,
    );
    let poor = expansion_weight_for_strategy(
        ExpansionStrategy::RichestFirst,
        TargetKind::Email,
        0.9,
        "a@b.com",
        false,
        0.1,
    );
    // Richer entity wins despite lower confidence.
    assert!(rich > poor);
}

#[test]
fn strategy_depth_first_sorts_by_confidence() {
    let high = expansion_weight_for_strategy(
        ExpansionStrategy::DepthFirst,
        TargetKind::Domain,
        0.95,
        "example.com",
        false,
        0.5,
    );
    let low = expansion_weight_for_strategy(
        ExpansionStrategy::DepthFirst,
        TargetKind::Domain,
        0.55,
        "example.com",
        false,
        1.0,
    );
    // c_eff dominates even when low-confidence has max richness.
    assert!(high > low);
}

#[test]
fn scan_options_default_uses_geo_converge() {
    let opts = ScanOptions::default();
    assert_eq!(opts.expansion_strategy, ExpansionStrategy::GeoConverge);
}

#[test]
fn scan_options_serde_round_trips_expansion_strategy() {
    let opts = ScanOptions {
        expansion_strategy: ExpansionStrategy::RichestFirst,
        ..Default::default()
    };
    let json = serde_json::to_string(&opts).unwrap();
    let back: ScanOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(back.expansion_strategy, ExpansionStrategy::RichestFirst);
}

#[test]
fn validate_url() {
    assert!(
        Target::new(TargetKind::Url, "https://example.com/path")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::Url, "http://x.com")
            .validate()
            .is_ok()
    );
    assert!(
        Target::new(TargetKind::Url, "ftp://nope.com")
            .validate()
            .is_err()
    );
    assert!(
        Target::new(TargetKind::Url, "not-a-url")
            .validate()
            .is_err()
    );
}

/// An `options` object that omits a field must behave like omitting the whole
/// `options` object: both are "operator expressed no preference". The depth
/// field already had this guard (default_scan_depth); max_concurrent silently
/// fell back to 0/sequential from `"options": {}` while an options-less
/// request ran at the product default of 2.
#[test]
fn empty_options_object_matches_product_defaults() {
    let from_empty: ScanOptions = serde_json::from_str("{}").unwrap();
    let product = ScanOptions::default();
    assert_eq!(
        from_empty.max_concurrent, product.max_concurrent,
        "omitted max_concurrent must deserialise to the product default"
    );
    assert_eq!(from_empty.regional_search, product.regional_search);
    // depth, min_expand_confidence and max_entities are the DOCUMENTED
    // divergences: the library `Default` stays inert/deterministic for
    // programmatic callers (depth 0, floor 0.50, uncapped) while the serde field
    // defaults apply the COMPREHENSIVE product values so an API/web request that
    // omits them is as thorough as `hse scan`.
    assert_eq!(from_empty.depth, DEFAULT_SCAN_DEPTH);
    assert!((from_empty.min_expand_confidence - DEFAULT_MIN_EXPAND_CONFIDENCE).abs() < 1e-9);
    assert_eq!(from_empty.max_entities, Some(DEFAULT_MAX_ENTITIES));
    // An explicit 0 is still honoured as fully-sequential.
    let explicit: ScanOptions = serde_json::from_str(r#"{"max_concurrent":0}"#).unwrap();
    assert_eq!(explicit.max_concurrent, 0);
}

/// Locks the DECOUPLING of the library default from the serde field defaults.
/// The library `ScanOptions::default()` — used by programmatic callers and the
/// test suite — must STAY conservative (depth 0 single-round, expansion floor
/// 0.50 Probable, uncapped) for determinism, even though the CLI/API/web product
/// surface now defaults to the comprehensive depth 3 / floor 0.20 / cap 2500.
#[test]
fn library_default_stays_conservative_and_decoupled_from_serde() {
    let d = ScanOptions::default();
    assert_eq!(d.depth, 0, "library default is single-round");
    assert!(
        (d.min_expand_confidence - 0.50).abs() < 1e-9,
        "library default expansion floor stays at the conservative 0.50"
    );
    assert_eq!(d.max_entities, None, "library default stays uncapped");
    // …and these MUST differ from the comprehensive product/serde defaults,
    // i.e. the decoupling is real, not an accidental equality.
    assert_ne!(d.depth, DEFAULT_SCAN_DEPTH);
    assert!((d.min_expand_confidence - DEFAULT_MIN_EXPAND_CONFIDENCE).abs() > 1e-9);
    assert_ne!(d.max_entities, Some(DEFAULT_MAX_ENTITIES));
}

/// A `ScanRequest` deserialised either with the whole `options` object omitted
/// or with a present-but-empty `options:{}` must yield the SAME comprehensive
/// product defaults as `hse scan`: depth 3, expansion floor 0.20, entity cap
/// 2500. This is the API/SPA-thoroughness guarantee.
#[test]
fn scan_request_defaults_to_comprehensive_options() {
    for body in [r#"{"value":"x"}"#, r#"{"value":"x","options":{}}"#] {
        let req: ScanRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.options.depth, DEFAULT_SCAN_DEPTH, "depth for {body}");
        assert_eq!(req.options.depth, 3, "depth literal for {body}");
        assert!(
            (req.options.min_expand_confidence - DEFAULT_MIN_EXPAND_CONFIDENCE).abs() < 1e-9,
            "expansion floor for {body}"
        );
        assert!(
            (req.options.min_expand_confidence - 0.20).abs() < 1e-9,
            "expansion floor literal for {body}"
        );
        assert_eq!(
            req.options.max_entities,
            Some(DEFAULT_MAX_ENTITIES),
            "entity cap for {body}"
        );
        assert_eq!(
            req.options.max_entities,
            Some(2500),
            "entity cap literal for {body}"
        );
    }
}
