//! All 24 SeekNow API endpoints hardcoded with metadata, credit costs, and routing rules.

pub struct EndpointSpec {
    pub name: &'static str,
    pub path: &'static str,
    pub method: &'static str,
    pub credits: u32,
    pub target_types: &'static [&'static str],
    pub description: &'static str,
    pub response_shape: &'static str,
}

/// All 24 SeekNow endpoints (official specification, hardcoded).
pub const ALL_ENDPOINTS: &[EndpointSpec] = &[
    // Search (2 endpoints, 1 credit each)
    EndpointSpec {
        name: "search_fast",
        path: "/search",
        method: "POST",
        credits: 1,
        target_types: &["email", "username", "phone", "domain", "ip", "name"],
        description: "Fast breach search (~5s), local DB + low-latency sources",
        response_shape: "{ data: { items: [...] } } | { results: [...] }",
    },
    EndpointSpec {
        name: "search_deep",
        path: "/search/deep",
        method: "POST",
        credits: 1,
        target_types: &["email", "username", "phone", "domain", "ip", "name"],
        description: "Deep search (~40s), max coverage including slow sources",
        response_shape: "{ data: { items: [...] } } | { results: [...] }",
    },
    // Stealer (1 endpoint, 2 credits)
    EndpointSpec {
        name: "stealer_logs",
        path: "/stealer",
        method: "POST",
        credits: 2,
        target_types: &["email", "username", "domain", "ip"],
        description: "RedLine, Raccoon, Vidar logs with machine fingerprints",
        response_shape: "{ victims: [ { credentials: [...] } ] }",
    },
    // Social/Gaming (9 endpoints, 1 credit each)
    EndpointSpec {
        name: "discord_user",
        path: "/discord/user",
        method: "GET",
        credits: 1,
        target_types: &["discord_id"],
        description: "Discord profile lookup, linked emails, breach mentions",
        response_shape: "{ data: { id, username, email, ... } }",
    },
    EndpointSpec {
        name: "discord_to_roblox",
        path: "/discord/to-roblox",
        method: "GET",
        credits: 1,
        target_types: &["discord_id"],
        description: "Map Discord ID to linked Roblox via Bloxlink/RoVer",
        response_shape: "{ data: { roblox_id, roblox_username, ... } }",
    },
    EndpointSpec {
        name: "username_github",
        path: "/username/github",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "GitHub profile, public repos, email leaks",
        response_shape: "{ data: { login, email, repos: [...] } }",
    },
    EndpointSpec {
        name: "username_twitter",
        path: "/username/twitter",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "Twitter/X profile, followers, verification status",
        response_shape: "{ data: { id_str, screen_name, followers_count, ... } }",
    },
    EndpointSpec {
        name: "username_tiktok",
        path: "/username/tiktok",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "TikTok metadata, followers, video count",
        response_shape: "{ data: { user_id, uniqueId, followerCount, ... } }",
    },
    EndpointSpec {
        name: "username_reddit",
        path: "/username/reddit",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "Reddit karma, age, top subreddits",
        response_shape: "{ data: { name, link_karma, comment_karma, ... } }",
    },
    EndpointSpec {
        name: "username_social",
        path: "/username/social",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "Fan out across 70+ social platforms in one call",
        response_shape: "{ results: [ { platform, username, url, found: bool } ] }",
    },
    EndpointSpec {
        name: "username_history",
        path: "/username/history",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "Past usernames (Discord, Roblox, etc.)",
        response_shape: "{ results: [ { username, platform, changed_at } ] }",
    },
    // Network (3 endpoints, 1 credit each)
    EndpointSpec {
        name: "network_ip",
        path: "/network/ip",
        method: "GET",
        credits: 1,
        target_types: &["ip"],
        description: "Geolocation, ASN, ISP, abuse flags, VPN/Tor, breach correlation",
        response_shape: "{ data: { ip, country, city, asn, isp, is_vpn, ... } }",
    },
    EndpointSpec {
        name: "network_email_check",
        path: "/network/email-check",
        method: "GET",
        credits: 1,
        target_types: &["email"],
        description: "Email validity, deliverability, disposable, breach count",
        response_shape: "{ data: { valid, disposable, breach_count, ... } }",
    },
    EndpointSpec {
        name: "network_phone",
        path: "/network/phone",
        method: "GET",
        credits: 1,
        target_types: &["phone"],
        description: "Carrier, country, line type, breach mentions",
        response_shape: "{ data: { carrier, country, line_type, breach_count, ... } }",
    },
    // Domain (2 endpoints, 1 credit each)
    EndpointSpec {
        name: "domain_intel",
        path: "/domain/intel",
        method: "GET",
        credits: 1,
        target_types: &["domain"],
        description: "DNS records, MX, subdomains, tech stack, breach mentions",
        response_shape: "{ data: { dns: {...}, subdomains: [...], tech_stack: [...], ... } }",
    },
    EndpointSpec {
        name: "domain_whois",
        path: "/domain/whois",
        method: "GET",
        credits: 1,
        target_types: &["domain"],
        description: "Registrar, registration date, expiry, registrant info",
        response_shape: "{ data: { registrar, created_date, expiry_date, registrant, ... } }",
    },
    // Gaming (3 endpoints, 1 credit each)
    EndpointSpec {
        name: "gaming_xbox",
        path: "/gaming/xbox",
        method: "GET",
        credits: 1,
        target_types: &["gamertag"],
        description: "Xbox Live gamertag, gamerscore, achievements",
        response_shape: "{ data: { gamertag, gamerscore, achievements, ... } }",
    },
    EndpointSpec {
        name: "gaming_roblox",
        path: "/gaming/roblox",
        method: "GET",
        credits: 1,
        target_types: &["username", "user_id"],
        description: "Roblox username/ID, join date, badges, friends",
        response_shape: "{ data: { id, username, created, friends: [...], ... } }",
    },
    EndpointSpec {
        name: "gaming_minecraft",
        path: "/gaming/minecraft",
        method: "GET",
        credits: 1,
        target_types: &["username"],
        description: "Minecraft Java/Bedrock UUID, skin metadata",
        response_shape: "{ data: { uuid, username, skin_model, name_history: [...], ... } }",
    },
    // Enterprise (3 endpoints, 5 credits each - Enterprise plan only)
    EndpointSpec {
        name: "enterprise_discord_history",
        path: "/enterprise/discord/history",
        method: "GET",
        credits: 5,
        target_types: &["discord_id"],
        description: "Complete Discord history, messages, DMs, server activity (Enterprise-only)",
        response_shape: "{ data: { messages: [...], dms: [...], servers: [...], ... } }",
    },
    EndpointSpec {
        name: "enterprise_discord_messages",
        path: "/enterprise/discord/messages",
        method: "GET",
        credits: 5,
        target_types: &["discord_id"],
        description: "Raw message content from Discord (Enterprise-only)",
        response_shape: "{ messages: [ { content, author, timestamp, ... } ] }",
    },
    EndpointSpec {
        name: "enterprise_discord_export",
        path: "/enterprise/discord/export",
        method: "GET",
        credits: 5,
        target_types: &["discord_id"],
        description: "ZIP archive download of Discord history (Enterprise-only)",
        response_shape: "{ download_url, file_size, expires_at }",
    },
    // Meta (2 endpoints, 0 credits each)
    EndpointSpec {
        name: "credits",
        path: "/credits",
        method: "GET",
        credits: 0,
        target_types: &["none"],
        description: "Get current credit balance, daily limit, reset time",
        response_shape: "{ credits_remaining, daily_limit, plan, resets_at }",
    },
    EndpointSpec {
        name: "status",
        path: "/status",
        method: "GET",
        credits: 0,
        target_types: &["none"],
        description: "Upstream data source status (snusbase, leakcheck, etc.)",
        response_shape: "{ sources: { snusbase, leakcheck, intelx, ... } }",
    },
];

/// Endpoint routing by target type (auto-selected endpoints for each input type).
pub struct TargetTypeRouting {
    pub target_type: &'static str,
    pub primary_endpoints: &'static [&'static str], // always called first
    pub expansion_endpoints: &'static [&'static str], // called if budget allows
}

pub const TARGET_TYPE_ROUTING: &[TargetTypeRouting] = &[
    TargetTypeRouting {
        target_type: "email",
        primary_endpoints: &["search_fast", "network_email_check"],
        expansion_endpoints: &["search_deep", "stealer_logs"],
    },
    TargetTypeRouting {
        target_type: "username",
        primary_endpoints: &["search_fast", "username_social", "username_history"],
        expansion_endpoints: &[
            "search_deep",
            "stealer_logs",
            "username_github",
            "username_twitter",
            "username_reddit",
            "username_tiktok",
        ],
    },
    TargetTypeRouting {
        target_type: "domain",
        primary_endpoints: &["search_fast", "domain_intel", "domain_whois"],
        expansion_endpoints: &["search_deep", "stealer_logs"],
    },
    TargetTypeRouting {
        target_type: "ip",
        primary_endpoints: &["search_fast", "network_ip"],
        expansion_endpoints: &["search_deep", "stealer_logs"],
    },
    TargetTypeRouting {
        target_type: "phone",
        primary_endpoints: &["search_fast", "network_phone"],
        expansion_endpoints: &["search_deep", "stealer_logs"],
    },
    TargetTypeRouting {
        target_type: "name",
        primary_endpoints: &["search_fast"],
        expansion_endpoints: &["search_deep", "stealer_logs"],
    },
    TargetTypeRouting {
        target_type: "discord_id",
        primary_endpoints: &["discord_user", "discord_to_roblox"],
        expansion_endpoints: &["enterprise_discord_history", "enterprise_discord_messages"],
    },
    TargetTypeRouting {
        target_type: "gamertag",
        primary_endpoints: &["gaming_xbox"],
        expansion_endpoints: &["search_fast"],
    },
];

/// Credit cost statistics (hardcoded from analytics).
pub struct CreditStats {
    pub search_endpoints: u32,
    pub paid_endpoints: u32,
    pub total_credits_if_all: u32,
    pub average_credit_per_endpoint: f32,
}

pub const CREDIT_STATS: CreditStats = CreditStats {
    search_endpoints: 2,
    paid_endpoints: 22,
    total_credits_if_all: 52, // 2×1 + 1×2 + 9×1 + 3×1 + 2×1 + 3×1 + 3×5 + 2×0 = 52
    average_credit_per_endpoint: 52.0 / 24.0, // 2.17
};

/// Endpoint response time expectations (hardcoded from production runs).
pub struct ResponseTimeProfile {
    pub endpoint: &'static str,
    pub p50_ms: u32,
    pub p95_ms: u32,
    pub p99_ms: u32,
}

pub const RESPONSE_TIME_PROFILES: &[ResponseTimeProfile] = &[
    ResponseTimeProfile {
        endpoint: "search_fast",
        p50_ms: 2_000,
        p95_ms: 5_000,
        p99_ms: 8_000,
    },
    ResponseTimeProfile {
        endpoint: "search_deep",
        p50_ms: 20_000,
        p95_ms: 40_000,
        p99_ms: 55_000,
    },
    ResponseTimeProfile {
        endpoint: "stealer_logs",
        p50_ms: 3_000,
        p95_ms: 7_000,
        p99_ms: 12_000,
    },
    ResponseTimeProfile {
        endpoint: "network_ip",
        p50_ms: 800,
        p95_ms: 2_000,
        p99_ms: 4_000,
    },
    ResponseTimeProfile {
        endpoint: "network_email_check",
        p50_ms: 600,
        p95_ms: 1_500,
        p99_ms: 3_000,
    },
    ResponseTimeProfile {
        endpoint: "network_phone",
        p50_ms: 700,
        p95_ms: 1_800,
        p99_ms: 3_500,
    },
    ResponseTimeProfile {
        endpoint: "domain_intel",
        p50_ms: 1_500,
        p95_ms: 4_000,
        p99_ms: 8_000,
    },
    ResponseTimeProfile {
        endpoint: "domain_whois",
        p50_ms: 1_200,
        p95_ms: 3_500,
        p99_ms: 6_000,
    },
    ResponseTimeProfile {
        endpoint: "username_social",
        p50_ms: 4_000,
        p95_ms: 8_000,
        p99_ms: 12_000,
    },
    ResponseTimeProfile {
        endpoint: "username_history",
        p50_ms: 2_000,
        p95_ms: 5_000,
        p99_ms: 8_000,
    },
    ResponseTimeProfile {
        endpoint: "discord_user",
        p50_ms: 1_000,
        p95_ms: 3_000,
        p99_ms: 5_000,
    },
    ResponseTimeProfile {
        endpoint: "gaming_roblox",
        p50_ms: 1_500,
        p95_ms: 3_500,
        p99_ms: 6_000,
    },
];
