use super::*;

    /// Every real `EndpointCall` variant — the single list both tests below
    /// share, so there is exactly one place to update when a variant is
    /// added or removed.
    const ALL_ENDPOINT_CALLS: [EndpointCall; 17] = [
        EndpointCall::EmailCheck,
        EndpointCall::SocialAggregate,
        EndpointCall::GithubProfile,
        EndpointCall::TwitterProfile,
        EndpointCall::RedditProfile,
        EndpointCall::TiktokProfile,
        EndpointCall::UsernameHistory,
        EndpointCall::RobloxProfile,
        EndpointCall::XboxProfile,
        EndpointCall::MinecraftProfile,
        EndpointCall::SteamProfile,
        EndpointCall::DiscordUser,
        EndpointCall::DiscordToRoblox,
        EndpointCall::PhoneInfo,
        EndpointCall::IpInfo,
        EndpointCall::DomainIntel,
        EndpointCall::Whois,
    ];

    #[test]
    fn endpoint_call_labels_are_unique() {
        // Sanity check: every variant must have a distinct label so
        // the dispatch + geo extractor can route by string identity.
        // Previously omitted `SteamProfile` (16 of the real 17 variants) —
        // a label collision involving Steam specifically would have gone
        // uncaught. `ALL_ENDPOINT_CALLS` is now the one shared list so this
        // can't silently drift from the real enum again.
        let mut labels: Vec<&str> = ALL_ENDPOINT_CALLS.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), ALL_ENDPOINT_CALLS.len(), "duplicate endpoint labels");
    }

    #[test]
    fn endpoint_call_count_matches_the_documented_wired_total() {
        // `util::see_know::integration_tests`'s endpoint ledger asserts 18
        // of the 24 documented SeekNow endpoints are actually wired — 17
        // `EndpointCall` variants plus the separate `/search` universal
        // call (not an `EndpointCall` variant; dispatched directly by
        // `modules::see_know::Module::process()`). This is the
        // architecturally-correct place to pin that number (`util` cannot
        // depend on `modules`, so the ledger itself can't check this
        // directly) — if this assertion breaks, update BOTH this count and
        // `util::see_know::integration_tests`'s ledger together.
        assert_eq!(
            ALL_ENDPOINT_CALLS.len(),
            17,
            "17 EndpointCall variants + /search (dispatched separately, not \
             an EndpointCall) = 18 real wired endpoints"
        );
    }

    #[test]
    fn plan_email_addon_is_only_email_check() {
        // Breach/stealer/external all come from the universal `/search` (run
        // separately), so the email plan adds only the distinct account/service
        // existence map. The dead, redundant `/stealer` + `/breachhub/search`
        // endpoints (live-verified 404) must NOT be planned.
        let plan = plan_endpoints(TargetKind::Email, "a@b.com");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        assert!(labels.contains(&"email_check"), "got {labels:?}");
        assert!(!labels.contains(&"stealer"), "404 endpoint must be gone");
        assert!(!labels.contains(&"breachhub"), "404 endpoint must be gone");
    }

    #[test]
    fn plan_username_covers_social_and_gaming_endpoints() {
        // Regression guard so we don't accidentally trim the username breadth.
        // The dead `/stealer` + `/breachhub/search` (404) are gone — their
        // breach/stealer coverage is served by the universal `/search`.
        let plan = plan_endpoints(TargetKind::Username, "alice");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        for ep in [
            "social",
            "github",
            "twitter",
            "reddit",
            "tiktok",
            "username_history",
            "roblox",
            "xbox",
            "minecraft",
        ] {
            assert!(
                labels.contains(&ep),
                "username plan missing endpoint {ep}; got {labels:?}"
            );
        }
        assert!(!labels.contains(&"stealer"), "404 endpoint must be gone");
        assert!(!labels.contains(&"breachhub"), "404 endpoint must be gone");
    }

    #[test]
    fn effective_plan_fires_the_full_username_matrix() {
        // Maximisation directive: SeekNow's 5,000-daily quota is effectively
        // unlimited for a single-operator deployment — every endpoint that adds
        // platform-specific profile depth or breach context must fire. The old
        // FREE_COVERED_SINGLE_ORIGIN filter that dropped github/twitter/… has
        // been removed; effective_plan() now returns the complete matrix and
        // relies solely on the budget cap (300/scan) as the rate limiter.
        let labels: Vec<&str> = effective_plan(TargetKind::Username, "alice", "test-full-matrix")
            .iter()
            .map(|c| c.label())
            .collect();
        // Full platform coverage — every endpoint that adds profile+breach depth.
        for expected in [
            "social",
            "github",
            "twitter",
            "reddit",
            "tiktok",
            "username_history",
            "roblox",
            "xbox",
            "minecraft",
        ] {
            assert!(
                labels.contains(&expected),
                "effective plan must include '{expected}' (max-coverage mode); got {labels:?}"
            );
        }
    }

    #[test]
    fn effective_plan_keeps_id_resolution_pivots() {
        // Discord/Steam ID resolution is cross-platform identity linkage, NOT
        // single-origin enumeration — it survives the filter even though the
        // paths live under discord/ and gaming/.
        let labels: Vec<&str> = effective_plan(
            TargetKind::Username,
            "359023095012345678",
            "test-id-pivots",
        )
        .iter()
        .map(|c| c.label())
        .collect();
        assert!(
            labels.contains(&"discord_user") && labels.contains(&"discord_to_roblox"),
            "ID-resolution pivots must survive; got {labels:?}"
        );
    }

    #[test]
    fn plan_username_with_discord_id_prepends_discord_endpoints() {
        // 18-digit discord snowflake (typical len 17–19).
        let plan = plan_endpoints(TargetKind::Username, "359023095012345678");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        // discord_user + discord_to_roblox should be at the head of the
        // plan so they run even if the per-scan budget cuts the tail.
        assert_eq!(labels[0], "discord_user");
        assert_eq!(labels[1], "discord_to_roblox");
    }

    #[test]
    fn effective_plan_orders_high_value_endpoints_first() {
        // The live HVQS ordering must place higher value/cost (ROI) endpoints
        // ahead of low-pivot leaf lookups, while preserving the full set. For a
        // username, the social aggregate (pivot 70, broad coverage) must rank
        // ahead of username history and a single-platform gaming leaf.
        let plan = effective_plan(TargetKind::Username, "alice", "test-roi-order");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();

        let idx = |l: &str| labels.iter().position(|x| *x == l);
        let social = idx("social").expect("social present");
        let history = idx("username_history").expect("history present");
        let minecraft = idx("minecraft").expect("minecraft present");
        assert!(
            social < history && social < minecraft,
            "high-value 'social' must precede low-pivot leaves; got {labels:?}"
        );

        // Set preserved: reordering never drops or adds an endpoint.
        assert_eq!(
            plan.len(),
            plan_endpoints(TargetKind::Username, "alice").len(),
            "ROI ordering must preserve the endpoint set"
        );
    }

    #[test]
    fn plan_domain_covers_intel_and_whois() {
        let plan = plan_endpoints(TargetKind::Domain, "example.com");
        let labels: Vec<&str> = plan.iter().map(|c| c.label()).collect();
        assert!(labels.contains(&"domain_intel"));
        assert!(labels.contains(&"whois"));
    }

    #[tokio::test]
    async fn dispatch_plan_returns_empty_for_empty_plan() {
        // An empty plan never reaches the util layer; this path must
        // short-circuit without any HTTP regardless of budget state.
        // (Per-endpoint budget gating is exercised by the util-level
        // tests in `crate::util::see_know::tests`.)
        let out = dispatch_plan("key", "alice", &[]).await;
        assert!(out.is_empty());
    }

    #[test]
    fn plan_username_with_steam_id_prepends_steam_endpoint() {
        let plan = plan_endpoints(TargetKind::Username, "76561198000000000");
        let first = plan.first().expect("steam plan must be non-empty");
        assert_eq!(first.label(), "steam");
    }

    #[test]
    fn endpoint_call_steam_round_trips_via_label() {
        // Ensure the new variant appears in the unique-label set.
        let labels: Vec<&str> = [
            EndpointCall::EmailCheck,
            EndpointCall::SocialAggregate,
            EndpointCall::GithubProfile,
            EndpointCall::TwitterProfile,
            EndpointCall::RedditProfile,
            EndpointCall::TiktokProfile,
            EndpointCall::UsernameHistory,
            EndpointCall::RobloxProfile,
            EndpointCall::XboxProfile,
            EndpointCall::MinecraftProfile,
            EndpointCall::SteamProfile,
            EndpointCall::DiscordUser,
            EndpointCall::DiscordToRoblox,
            EndpointCall::PhoneInfo,
            EndpointCall::IpInfo,
            EndpointCall::DomainIntel,
            EndpointCall::Whois,
        ]
        .iter()
        .map(|c| c.label())
        .collect();
        assert!(labels.contains(&"steam"));
    }
