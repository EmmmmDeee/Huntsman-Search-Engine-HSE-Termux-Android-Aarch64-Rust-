/// Subdomain brute-force dictionary — covers the most common public-facing
/// subdomains operators want to discover. Ordered roughly by frequency so
/// cancellation during a partial run still surfaces the highest-value names
/// first. 146 labels spanning core web, mail, API, DevOps, cloud, and modern
/// SaaS/org infrastructure.
pub(super) const SUBDOMAINS: &[&str] = &[
    // Core web & mail
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "pop3",
    "webmail",
    // DNS name-servers
    "ns",
    "ns1",
    "ns2",
    "ns3",
    // Legacy protocols
    "mx",
    "mx1",
    "ftp",
    // Web application infrastructure
    "admin",
    "blog",
    "api",
    "dev",
    "staging",
    "stage",
    "test",
    "beta",
    "alpha",
    "qa",
    "secure",
    "vpn",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "docs",
    "support",
    "help",
    "status",
    // Applications & portals
    "shop",
    "store",
    "portal",
    "app",
    "apps",
    "my",
    "login",
    "auth",
    "sso",
    "files",
    "upload",
    "download",
    "backup",
    // Source control & collaboration
    "git",
    "gitlab",
    "github",
    "jira",
    "wiki",
    "forum",
    "community",
    // Environment qualifiers
    "old",
    "new",
    "m",
    "mobile",
    "internal",
    "prod",
    "production",
    // cPanel / email-client autodiscovery
    "cpanel",
    "autodiscover",
    "autoconfig",
    "webdisk",
    // CI/CD & DevOps
    "ci",
    "cd",
    "jenkins",
    "drone",
    // Container & orchestration
    "k8s",
    "registry",
    "docker",
    // Monitoring & observability
    "grafana",
    "prometheus",
    "kibana",
    "sentry",
    "monitoring",
    "logs",
    "metrics",
    // Database & cache
    "db",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elastic",
    // Cloud & remote access
    "cloud",
    "remote",
    "demo",
    "sandbox",
    "uat",
    "preview",
    "intranet",
    // Modern API & real-time transport
    "graphql",
    "webhooks",
    "webhook",
    "ws",
    "socket",
    // Large-org / SaaS platform subdomains (GitHub, GitLab, Atlassian, etc.)
    "gist",
    "pages",
    "raw",
    "education",
    "enterprise",
    "classroom",
    "lab",
    "copilot",
    "avatars",
    "objects",
    "alive",
    "collector",
    "resources",
    "developer",
    "developers",
    "explore",
    "marketplace",
    // Customer account & billing infrastructure
    "account",
    "accounts",
    "billing",
    "payment",
    "checkout",
    "dashboard",
    "console",
    // Build, deploy & artefact management
    "build",
    "deploy",
    "release",
    "packages",
    "npm",
    "charts",
    "artifacts",
    "artifact",
    // Health & readiness probes (Kubernetes et al.)
    "health",
    "healthz",
    "ping",
    "ready",
    // Security & secrets management
    "vault",
    "security",
    "trust",
    // Data & analytics
    "data",
    "analytics",
    // Geographic / regional shards
    "us",
    "eu",
    "ap",
    "us1",
    "eu1",
    "ap1",
];

/// Spamhaus ZEN, the one zone here whose answer codes include policy
/// (non-reputation) listings — see `resolve::is_spamhaus_abuse_listing`.
pub(super) const SPAMHAUS_ZEN: &str = "zen.spamhaus.org";

/// The CBL — operated by Spamhaus (`www.abuseat.org` redirects to Spamhaus's
/// Exploits Blocklist; its data is ZEN's XBL `127.0.0.4`).
pub(super) const SPAMHAUS_CBL: &str = "cbl.abuseat.org";

/// The zones Spamhaus answers, which share its reserved error range
/// `127.255.255.0/24` — "ERRORS (not implying a 'listed' response)", for "Any"
/// Spamhaus zone (Spamhaus DNSBL usage FAQ). Every other list follows RFC 5782,
/// where any `127/8` value may be a listing (`resolve::dnsbl_code`).
pub(super) const SPAMHAUS_ZONES: &[&str] = &[SPAMHAUS_ZEN, SPAMHAUS_CBL];

/// DNS-based blocklists — zone + human label.
pub(super) const BLOCKLISTS: &[(&str, &str)] = &[
    (SPAMHAUS_ZEN, "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("b.barracudacentral.org", "Barracuda"),
    (SPAMHAUS_CBL, "CBL"),
    ("dnsbl-1.uceprotect.net", "UCEPROTECT-1"),
    ("psbl.surriel.com", "PSBL"),
    ("all.s5h.net", "S5H"),
];
