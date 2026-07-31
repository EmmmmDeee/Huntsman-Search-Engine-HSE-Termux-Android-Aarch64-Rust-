//! Honest coverage ledger for SeekNow's documented API surface (24 endpoints
//! per `docs/SEEKNOW_SETUP.md`) against what HSE actually calls.
//!
//! This file previously claimed ("Comprehensive integration tests for all 24
//! SeekNow API endpoints... validate endpoint availability... across the
//! entire API surface") while every `#[test]` here only ever asserted
//! properties of its own hand-written [`ENDPOINTS`] table against itself —
//! it never touched `search()`, `get_path()`, or any real client function,
//! so it could not catch drift between "endpoints we claim to support" and
//! "endpoints we actually call." Of the 24 documented endpoints, 19 are
//! actually invoked; `/stealer` was tried and found to live-verified-404
//! (correctly removed — see
//! `modules::see_know::endpoints::tests::plan_email_addon_is_only_email_check`);
//! the three `/enterprise/discord/*` and `/status` were never built at all.
//!
//! Being hand-maintained, this table then drifted exactly the way it was
//! written to prevent: `/search/deep` was wired (dispatched by
//! `modules::see_know` when a typed fast `/search` draws a blank, implemented
//! as a real `POST` in [`super::endpoints::search_deep`]) while the ledger
//! still recorded it as `NotImplemented` and asserted 18 wired against
//! `docs/SEEKNOW_SETUP.md`'s correct 19. The tests below can only check this
//! table's *internal* bookkeeping — `util::see_know` cannot reach
//! `modules::see_know::endpoints`'s `EndpointCall` enum to check the real
//! thing, since `modules` depends on `util` and never the reverse. So the
//! external check lives outside the layering entirely, in
//! `tests/architecture.rs`'s `see_know_endpoint_ledger_matches_the_dispatch_code`,
//! which reads both sides as source text and fails when a `Wired::Yes` here
//! isn't actually requested (or vice versa). Update this table and that guard
//! agrees, or it stops the build. A companion regression test pinning
//! `EndpointCall`'s real variant count lives where it belongs:
//! `modules::see_know::endpoints::tests`.
//!
//! `HUNTSMAN_SEEKNOW_KEY`, `get_api_key()`, and `live_api_connectivity_test`
//! are kept as scaffolding for a genuine live smoke test an operator could
//! write by hand against their own key — but that test's own body was
//! always a `println!` plus an explicit comment admitting no HTTP call is
//! made, and it is `#[ignore]`d — its docstring below says so honestly
//! rather than implying otherwise.

#[cfg(test)]
mod seeknow_full_integration {
    use std::env;

    /// Test if a SeekNow API key is available for a genuine live smoke test
    /// (not currently exercised by anything in this file — see the module
    /// doc comment).
    fn get_api_key() -> Option<String> {
        env::var("HUNTSMAN_SEEKNOW_KEY")
            .ok()
            .filter(|k| !k.is_empty())
    }

    /// Whether HSE actually calls this endpoint, and why/why not — every
    /// variant cites its evidence so this table can't silently drift from
    /// reality again the way the "all 24 endpoints... tested" claim did.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Wired {
        /// A real call site exists and is reachable from
        /// `modules::see_know::Module::process()`.
        Yes,
        /// Tried, found to return HTTP 404 against the real live API, and
        /// deliberately removed — `modules::see_know::endpoints::tests`
        /// pins the removal as a regression guard (`"404 endpoint must be
        /// gone"`). Its data still arrives via `/search`'s stealer-shaped
        /// response, flattened by
        /// `util::see_know::endpoints::flatten_victims`.
        RemovedLiveVerified404,
        /// Documented but never built — no client function, no dispatch
        /// entry, zero call sites anywhere in the crate.
        NotImplemented,
    }

    /// Test metadata: endpoint name, target type, credit cost, expected
    /// response shape, and REAL wiring status (see [`Wired`]).
    ///
    /// `path`/`method`/`description` are the ledger's documentation payload —
    /// read by a human auditing this ledger against `docs/SEEKNOW_SETUP.md`,
    /// not by any assertion below — so `#[expect(dead_code)]` on them is
    /// deliberate rather than a fixable lint; deleting the fields would
    /// silently drop the citation each `ENDPOINTS` entry exists to record.
    #[expect(dead_code)]
    struct EndpointSpec {
        name: &'static str,
        path: &'static str,
        method: &'static str,
        credits: u32,
        target_type: &'static str,
        description: &'static str,
        wired: Wired,
    }

    /// The 24 SeekNow API endpoints named in `docs/SEEKNOW_SETUP.md`, each
    /// with its REAL, live-verified-or-code-confirmed wiring status — not an
    /// assumption. Cross-checked against the dispatch code by
    /// `tests/architecture.rs`'s
    /// `see_know_endpoint_ledger_matches_the_dispatch_code`.
    const ENDPOINTS: &[EndpointSpec] = &[
        // Search (2 endpoints documented, both actually wired)
        EndpointSpec {
            name: "Search (Fast)",
            path: "/search",
            method: "POST",
            credits: 1,
            target_type: "email|username|phone|domain|ip|name",
            description: "Fast breach search (~5s), local DB + low-latency sources",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Search (Deep)",
            path: "/search/deep",
            method: "POST",
            credits: 1,
            target_type: "email|username|phone|domain|ip|name",
            description: "Deep search (~40s), max coverage including slow sources",
            wired: Wired::Yes,
        },
        // Stealer (1 endpoint documented, removed after live-verified 404)
        EndpointSpec {
            name: "Stealer Logs",
            path: "/stealer",
            method: "POST",
            credits: 2,
            target_type: "email|username|domain|ip",
            description: "RedLine, Raccoon, Vidar logs with machine fingerprints",
            wired: Wired::RemovedLiveVerified404,
        },
        // Social/Gaming (9 endpoints, all wired)
        EndpointSpec {
            name: "Discord User",
            path: "/discord/user",
            method: "GET",
            credits: 1,
            target_type: "discord_id",
            description: "Discord profile lookup, linked emails, breach mentions",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Discord to Roblox",
            path: "/discord/to-roblox",
            method: "GET",
            credits: 1,
            target_type: "discord_id",
            description: "Map Discord ID to linked Roblox via Bloxlink/RoVer",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "GitHub Profile",
            path: "/username/github",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "GitHub profile, public repos, email leaks",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Twitter Profile",
            path: "/username/twitter",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "Twitter/X profile, followers, verification status",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "TikTok Profile",
            path: "/username/tiktok",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "TikTok metadata, followers, video count",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Reddit Profile",
            path: "/username/reddit",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "Reddit karma, age, top subreddits",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Universal Social Search",
            path: "/username/social",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "Fan out across 70+ social platforms in one call",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Username History",
            path: "/username/history",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "Past usernames (Discord, Roblox, etc.)",
            wired: Wired::Yes,
        },
        // Network (3 endpoints, all wired)
        EndpointSpec {
            name: "IP Intelligence",
            path: "/network/ip",
            method: "GET",
            credits: 1,
            target_type: "ip",
            description: "Geolocation, ASN, ISP, abuse flags, VPN/Tor, breach correlation",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Email Verification",
            path: "/network/email-check",
            method: "GET",
            credits: 1,
            target_type: "email",
            description: "Email validity, deliverability, disposable, breach count",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Phone OSINT",
            path: "/network/phone",
            method: "GET",
            credits: 1,
            target_type: "phone",
            description: "Carrier, country, line type, breach mentions",
            wired: Wired::Yes,
        },
        // Domain (2 endpoints, all wired)
        EndpointSpec {
            name: "Domain Intelligence",
            path: "/domain/intel",
            method: "GET",
            credits: 1,
            target_type: "domain",
            description: "DNS records, MX, subdomains, tech stack, breach mentions",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "WHOIS Lookup",
            path: "/domain/whois",
            method: "GET",
            credits: 1,
            target_type: "domain",
            description: "Registrar, registration date, expiry, registrant info",
            wired: Wired::Yes,
        },
        // Gaming (3 endpoints, all wired)
        EndpointSpec {
            name: "Xbox Live",
            path: "/gaming/xbox",
            method: "GET",
            credits: 1,
            target_type: "gamertag",
            description: "Xbox Live gamertag, gamerscore, achievements",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Roblox Profile",
            path: "/gaming/roblox",
            method: "GET",
            credits: 1,
            target_type: "username|user_id",
            description: "Roblox username/ID, join date, badges, friends",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Minecraft Profile",
            path: "/gaming/minecraft",
            method: "GET",
            credits: 1,
            target_type: "username",
            description: "Minecraft Java/Bedrock UUID, skin metadata",
            wired: Wired::Yes,
        },
        // Enterprise (3 endpoints documented, none built — Enterprise-plan
        // gated, and HSE's embedded default/typical operator keys are not
        // confirmed Enterprise-tier, so building against an unverifiable
        // plan gate was deferred rather than shipped blind)
        EndpointSpec {
            name: "Discord History (Full)",
            path: "/enterprise/discord/history",
            method: "GET",
            credits: 5,
            target_type: "discord_id",
            description: "Complete Discord history, messages, DMs, server activity (Enterprise-only)",
            wired: Wired::NotImplemented,
        },
        EndpointSpec {
            name: "Discord Messages Only",
            path: "/enterprise/discord/messages",
            method: "GET",
            credits: 5,
            target_type: "discord_id",
            description: "Raw message content from Discord (Enterprise-only)",
            wired: Wired::NotImplemented,
        },
        EndpointSpec {
            name: "Discord History Export (ZIP)",
            path: "/enterprise/discord/export",
            method: "GET",
            credits: 5,
            target_type: "discord_id",
            description: "ZIP archive download of Discord history (Enterprise-only)",
            wired: Wired::NotImplemented,
        },
        // Meta (2 endpoints documented, 1 wired)
        EndpointSpec {
            name: "Credits Check",
            path: "/credits",
            method: "GET",
            credits: 0,
            target_type: "none",
            description: "Get current credit balance, daily limit, reset time",
            wired: Wired::Yes,
        },
        EndpointSpec {
            name: "Service Status",
            path: "/status",
            method: "GET",
            credits: 0,
            target_type: "none",
            description: "Upstream data source status (snusbase, leakcheck, etc.)",
            wired: Wired::NotImplemented,
        },
    ];

    #[test]
    fn endpoint_ledger_matches_the_24_documented_and_19_actually_wired() {
        assert_eq!(
            ENDPOINTS.len(),
            24,
            "SeekNow's published API surface is exactly 24 endpoints"
        );
        let wired = ENDPOINTS.iter().filter(|e| e.wired == Wired::Yes).count();
        let removed_404 = ENDPOINTS
            .iter()
            .filter(|e| e.wired == Wired::RemovedLiveVerified404)
            .count();
        let not_implemented = ENDPOINTS
            .iter()
            .filter(|e| e.wired == Wired::NotImplemented)
            .count();
        assert_eq!(
            wired, 19,
            "19 of the 24 documented endpoints are actually called"
        );
        assert_eq!(
            removed_404, 1,
            "exactly /stealer was live-verified 404 and removed"
        );
        assert_eq!(
            not_implemented, 4,
            "the 3 /enterprise/discord/* + /status were never built"
        );
        assert_eq!(wired + removed_404 + not_implemented, ENDPOINTS.len());
    }

    #[test]
    fn credit_cost_calculation_covers_every_documented_endpoint() {
        // This counts documented cost regardless of wiring status — it
        // describes the vendor's published price list, not what HSE spends
        // (HSE only ever pays the 19 `Wired::Yes` entries' costs).
        let free = ENDPOINTS.iter().filter(|e| e.credits == 0).count();
        let paid = ENDPOINTS.iter().filter(|e| e.credits > 0).count();
        assert_eq!(free, 2, "exactly 2 free endpoints (meta)");
        assert_eq!(paid, 22, "exactly 22 paid endpoints");
    }

    #[test]
    fn endpoint_coverage_by_target_type() {
        use std::collections::HashMap;

        let mut coverage: HashMap<&str, Vec<&str>> = HashMap::new();
        for endpoint in ENDPOINTS.iter().filter(|e| e.wired == Wired::Yes) {
            for target in endpoint.target_type.split('|') {
                coverage.entry(target).or_default().push(endpoint.name);
            }
        }
        // Every target kind HSE actually dispatches SeekNow endpoints for
        // (see `modules::see_know::endpoints::plan_endpoints`) must have at
        // least one WIRED (not merely documented) endpoint backing it.
        for target in ["email", "username", "phone", "domain", "ip"] {
            assert!(
                coverage.get(target).is_some_and(|v| !v.is_empty()),
                "target type {target} has no actually-wired endpoint"
            );
        }
    }

    #[test]
    #[ignore = "no HTTP client seam exists to drive this against a mock; \
                run by hand against a real HUNTSMAN_SEEKNOW_KEY if needed"]
    fn live_api_connectivity_test() {
        // Honestly still a stub, not a real network test: `CurlClient`
        // shells out to `curl` directly with no injectable transport, so
        // there is no seam here to call `search()`/`get_path()` against
        // without a genuine live HTTP round-trip. This function documents
        // the intent (and gives an operator with a real key a place to
        // hand-extend into a real check) rather than pretending a call
        // happens when it doesn't.
        if get_api_key().is_none() {
            println!("SeekNow key not set — nothing to check");
        }
    }
}
