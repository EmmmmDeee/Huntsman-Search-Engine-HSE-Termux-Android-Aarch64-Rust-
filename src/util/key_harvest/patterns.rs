//! API-key prefix lookup table.
//!
//! Extracted from `key_harvest::mod.rs` so the table doesn't dominate
//! the file. Pure data — adding a new pattern means appending one
//! `KeyPattern` literal here, nothing else. The detector in
//! `identify_api_key` iterates this table in declaration order, so
//! more-specific prefixes (e.g. `sk-svcacct-`) MUST come before the
//! generic stem (`sk-`) for correct service mapping.

pub(super) struct KeyPattern {
    pub(super) prefix: &'static str,
    pub(super) service: &'static str,
    pub(super) min_len: usize,
}

pub(super) const KEY_PATTERNS: &[KeyPattern] = &[
    KeyPattern {
        prefix: "sk-ant-",
        service: "anthropic",
        min_len: 40,
    },
    KeyPattern {
        prefix: "sk-proj-",
        service: "openai",
        min_len: 40,
    },
    // OpenAI service-account + admin tokens (added 2025-2026).
    // Order matters: these specific prefixes must come BEFORE the
    // generic `sk-` catch-all, otherwise the loop in
    // `identify_api_key` short-circuits on the wrong service.
    KeyPattern {
        prefix: "sk-svcacct-",
        service: "openai_svc",
        min_len: 40,
    },
    KeyPattern {
        prefix: "sk-admin-",
        service: "openai_admin",
        min_len: 40,
    },
    // OpenRouter keys are `sk-or-…`; this specific prefix MUST precede the
    // generic `sk-` stem below or every OpenRouter key is mis-attributed to
    // `openai_or_stripe` (caught by `pattern_table_is_structurally_sound`).
    KeyPattern {
        prefix: "sk-or-",
        service: "openrouter",
        min_len: 40,
    },
    KeyPattern {
        prefix: "sk-",
        service: "openai_or_stripe",
        min_len: 20,
    },
    KeyPattern {
        prefix: "AIzaSy",
        service: "google",
        min_len: 30,
    },
    KeyPattern {
        prefix: "AKIA",
        service: "aws",
        min_len: 16,
    },
    KeyPattern {
        prefix: "ASIA",
        service: "aws_sts",
        min_len: 16,
    },
    KeyPattern {
        prefix: "ghp_",
        service: "github",
        min_len: 36,
    },
    KeyPattern {
        prefix: "gho_",
        service: "github_oauth",
        min_len: 36,
    },
    KeyPattern {
        prefix: "ghs_",
        service: "github_app",
        min_len: 36,
    },
    KeyPattern {
        prefix: "github_pat_",
        service: "github",
        min_len: 40,
    },
    KeyPattern {
        prefix: "SG.",
        service: "sendgrid",
        min_len: 20,
    },
    KeyPattern {
        prefix: "xkeysib-",
        service: "brevo",
        min_len: 40,
    },
    KeyPattern {
        prefix: "key-",
        service: "mailgun",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sk_live_",
        service: "stripe",
        min_len: 24,
    },
    KeyPattern {
        prefix: "pk_live_",
        service: "stripe_pub",
        min_len: 24,
    },
    KeyPattern {
        prefix: "sk_test_",
        service: "stripe_test",
        min_len: 24,
    },
    KeyPattern {
        prefix: "hf_",
        service: "huggingface",
        min_len: 30,
    },
    KeyPattern {
        prefix: "r8_",
        service: "replicate",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pplx-",
        service: "perplexity",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sntrys_",
        service: "sentry",
        min_len: 20,
    },
    KeyPattern {
        prefix: "glc_",
        service: "grafana",
        min_len: 20,
    },
    KeyPattern {
        prefix: "NRAK-",
        service: "newrelic",
        min_len: 20,
    },
    KeyPattern {
        prefix: "dapi",
        service: "databricks",
        min_len: 30,
    },
    KeyPattern {
        prefix: "cfut_",
        service: "cloudflare",
        min_len: 40,
    },
    KeyPattern {
        prefix: "cfat_",
        service: "cloudflare_acct",
        min_len: 40,
    },
    KeyPattern {
        prefix: "shpat_",
        service: "shopify",
        min_len: 30,
    },
    KeyPattern {
        prefix: "ntn_",
        service: "notion",
        min_len: 40,
    },
    KeyPattern {
        prefix: "lin_api_",
        service: "linear",
        min_len: 30,
    },
    KeyPattern {
        prefix: "tfp_",
        service: "typeform",
        min_len: 30,
    },
    KeyPattern {
        prefix: "fo1_",
        service: "flyio",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sbp_",
        service: "supabase",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pul-",
        service: "pulumi",
        min_len: 30,
    },
    KeyPattern {
        prefix: "ATATT3",
        service: "atlassian",
        min_len: 40,
    },
    KeyPattern {
        prefix: "xoxb-",
        service: "slack_bot",
        min_len: 30,
    },
    KeyPattern {
        prefix: "xoxp-",
        service: "slack_user",
        min_len: 30,
    },
    KeyPattern {
        prefix: "xapp-",
        service: "slack_app",
        min_len: 30,
    },
    KeyPattern {
        prefix: "EAA",
        service: "facebook",
        min_len: 40,
    },
    KeyPattern {
        prefix: "AC",
        service: "twilio",
        min_len: 34,
    },
    KeyPattern {
        prefix: "dop_v1_",
        service: "digitalocean",
        min_len: 60,
    },
    KeyPattern {
        prefix: "do-api-",
        service: "digitalocean",
        min_len: 30,
    },
    KeyPattern {
        prefix: "nvapi-",
        service: "nvidia",
        min_len: 30,
    },
    KeyPattern {
        prefix: "AGE-SECRET-KEY-",
        service: "age_encryption",
        min_len: 60,
    },
    KeyPattern {
        prefix: "eyJ",
        service: "jwt_token",
        min_len: 30,
    },
    KeyPattern {
        prefix: "npm_",
        service: "npm",
        min_len: 36,
    },
    KeyPattern {
        prefix: "pypi-",
        service: "pypi",
        min_len: 30,
    },
    KeyPattern {
        prefix: "op_",
        service: "1password",
        min_len: 20,
    },
    KeyPattern {
        prefix: "rk_live_",
        service: "stripe_restricted",
        min_len: 24,
    },
    KeyPattern {
        prefix: "whsec_",
        service: "stripe_webhook",
        min_len: 24,
    },
    KeyPattern {
        prefix: "sq0atp-",
        service: "square",
        min_len: 20,
    },
    KeyPattern {
        prefix: "sk_live_51",
        service: "stripe",
        min_len: 90,
    },
    KeyPattern {
        prefix: "ya29.",
        service: "google_oauth",
        min_len: 40,
    },
    KeyPattern {
        prefix: "goog_",
        service: "google_service",
        min_len: 40,
    },
    KeyPattern {
        prefix: "mc-",
        service: "mailchimp",
        min_len: 30,
    },
    KeyPattern {
        prefix: "dcbot.",
        service: "discord_bot",
        min_len: 50,
    },
    KeyPattern {
        prefix: "ODk",
        service: "discord_bot",
        min_len: 50,
    },
    KeyPattern {
        prefix: "MT",
        service: "discord_bot",
        min_len: 50,
    },
    // ── 2025-2026 AI/ML provider prefixes (ported from APIKeyScanner) ──
    // GitGuardian's State-of-Secrets-Sprawl-2025 reports 28.65M secrets
    // leaked on GitHub in 2025 (+34% YoY) with sub-4-minute median
    // exploitation time, so the long-tail AI provider tokens below are
    // now a meaningful chunk of the breach corpus.
    // (`sk-svcacct-` and `sk-admin-` are declared above the generic
    // `sk-` prefix earlier in the table — see the OpenAI block.)
    KeyPattern {
        prefix: "xai-",
        service: "xai_grok",
        min_len: 24,
    },
    // ── Modern dev-tooling tokens (also from APIKeyScanner) ────────────
    KeyPattern {
        prefix: "ghu_",
        service: "github_user_server",
        min_len: 36,
    },
    KeyPattern {
        prefix: "ghr_",
        service: "github_refresh",
        min_len: 36,
    },
    KeyPattern {
        prefix: "glpat-",
        service: "gitlab_pat",
        min_len: 20,
    },
    KeyPattern {
        prefix: "figd_",
        service: "figma",
        min_len: 40,
    },
    KeyPattern {
        prefix: "lsv2_",
        service: "langsmith",
        min_len: 40,
    },
    // Airtable PATs are `pat<14 alnum>.<64 hex>`. We match on the
    // dot-separator-bearing prefix to avoid the bare 3-letter `pat`
    // colliding with the English word; the in-module candidate filter
    // checks total length ≥ 79 to gate further.
    KeyPattern {
        prefix: "pat",
        service: "airtable",
        min_len: 79,
    },
    // ── Vercel — five sibling prefixes for project / integration / etc.
    KeyPattern {
        prefix: "vcp_",
        service: "vercel_project",
        min_len: 24,
    },
    KeyPattern {
        prefix: "vci_",
        service: "vercel_integration",
        min_len: 24,
    },
    KeyPattern {
        prefix: "vca_",
        service: "vercel_account",
        min_len: 24,
    },
    KeyPattern {
        prefix: "vcr_",
        service: "vercel_runtime",
        min_len: 24,
    },
    KeyPattern {
        prefix: "vck_",
        service: "vercel_kv",
        min_len: 24,
    },
    // ── Analytics / observability ─────────────────────────────────────
    KeyPattern {
        prefix: "phc_",
        service: "posthog",
        min_len: 40,
    },
    // ── Slack — third token variant ──────────────────────────────────
    KeyPattern {
        prefix: "xoxa-",
        service: "slack_app",
        min_len: 24,
    },
    // ── Twilio API SID — sibling of AC. Strict 34-char limit
    // (SK + 32 hex chars) to avoid generic-word collisions.
    KeyPattern {
        prefix: "SK",
        service: "twilio_api_sid",
        min_len: 34,
    },
    // ── Modern SaaS prefixes ported from momenbasel/keyFinder ──────────
    // 668-star browser extension claims 80+ patterns; ~17 of its
    // service prefixes weren't in HSE's table prior to this commit.
    // Each is a high-signal token format used by infrastructure /
    // collaboration / DB SaaS that frequently leaks into stealer logs
    // and GitHub pushes.
    // ── Square (additional sibling prefixes — `sq0atp-` is above)
    KeyPattern {
        prefix: "sq0idp-",
        service: "square_oauth_id",
        min_len: 20,
    },
    KeyPattern {
        prefix: "sq0csp-",
        service: "square_app_secret",
        min_len: 24,
    },
    // ── PlanetScale (DB platform) — password + token forms
    KeyPattern {
        prefix: "pscale_pw_",
        service: "planetscale_password",
        min_len: 40,
    },
    KeyPattern {
        prefix: "pscale_tkn_",
        service: "planetscale_token",
        min_len: 40,
    },
    // ── Doppler (secrets manager) — 4 token classes
    KeyPattern {
        prefix: "dp.pt.",
        service: "doppler_personal",
        min_len: 40,
    },
    KeyPattern {
        prefix: "dp.ct.",
        service: "doppler_cli",
        min_len: 40,
    },
    KeyPattern {
        prefix: "dp.sa.",
        service: "doppler_service_acct",
        min_len: 40,
    },
    KeyPattern {
        prefix: "dp.st.",
        service: "doppler_service_token",
        min_len: 40,
    },
    // ── Docker Hub PAT
    KeyPattern {
        prefix: "dckr_pat_",
        service: "docker_hub_pat",
        min_len: 36,
    },
    // ── HashiCorp Vault — service vs batch token classes
    KeyPattern {
        prefix: "hvs.",
        service: "vault_service",
        min_len: 90,
    },
    KeyPattern {
        prefix: "hvb.",
        service: "vault_batch",
        min_len: 90,
    },
    // ── Bitbucket — OAuth + app-password tokens
    KeyPattern {
        prefix: "BBDC-",
        service: "bitbucket_oauth",
        min_len: 32,
    },
    KeyPattern {
        prefix: "ATBB-",
        service: "bitbucket_app_password",
        min_len: 32,
    },
    // ── Prefixes from gitleaks default + Titus / apkscan rule sets ─────
    // praetorian-inc/titus ships 487 rules from NoseyParker + Kingfisher;
    // ~15 of its highest-leverage prefixes weren't in HSE's table.
    // Each below is a high-signal token shape that frequently leaks via
    // stealer logs and GitHub pushes (per GitGuardian SOSS-2025 + Titus
    // empirical data).
    KeyPattern {
        prefix: "ATCT",
        service: "atlassian_config",
        min_len: 32,
    },
    KeyPattern {
        prefix: "dt0c01.",
        service: "dynatrace",
        min_len: 60,
    },
    KeyPattern {
        prefix: "fio-u-",
        service: "frameio",
        min_len: 30,
    },
    KeyPattern {
        prefix: "PMAK-",
        service: "postman",
        min_len: 40,
    },
    KeyPattern {
        prefix: "rzp_test_",
        service: "razorpay_test",
        min_len: 24,
    },
    KeyPattern {
        prefix: "rzp_live_",
        service: "razorpay_live",
        min_len: 24,
    },
    KeyPattern {
        prefix: "rdme_",
        service: "readme",
        min_len: 40,
    },
    KeyPattern {
        prefix: "shippo_test_",
        service: "shippo_test",
        min_len: 32,
    },
    KeyPattern {
        prefix: "shippo_live_",
        service: "shippo_live",
        min_len: 32,
    },
    // ── Shopify siblings (HSE has `shpat_` already)
    KeyPattern {
        prefix: "shppa_",
        service: "shopify_partner",
        min_len: 32,
    },
    KeyPattern {
        prefix: "shpca_",
        service: "shopify_custom_app",
        min_len: 32,
    },
    KeyPattern {
        prefix: "shpss_",
        service: "shopify_shared_secret",
        min_len: 32,
    },
    KeyPattern {
        prefix: "NRJS-",
        service: "newrelic_browser",
        min_len: 20,
    },
    KeyPattern {
        prefix: "sl.",
        service: "dropbox_short_lived",
        min_len: 45,
    },
    KeyPattern {
        prefix: "CLOJARS_",
        service: "clojars_deploy",
        min_len: 60,
    },
    // ── Database connection URIs (sibling of redis://, mysql://, etc.)
    // HSE already has `postgres://` and `mongodb+srv://`; these are
    // the bare-form variants KeyFinder also tracks.
    KeyPattern {
        prefix: "mongodb://",
        service: "mongodb_uri",
        min_len: 16,
    },
    KeyPattern {
        prefix: "postgresql://",
        service: "postgres_uri",
        min_len: 16,
    },
    // ── Webhook URLs (operationally as sensitive as keys — anyone
    // with the URL can post into the channel). Matched as bare-URL
    // prefixes since they typically appear that way in app configs
    // and cookie storage.
    KeyPattern {
        prefix: "https://hooks.slack.com/services/",
        service: "slack_webhook_url",
        min_len: 60,
    },
    KeyPattern {
        prefix: "https://discord.com/api/webhooks/",
        service: "discord_webhook_url",
        min_len: 50,
    },
    KeyPattern {
        prefix: "https://discordapp.com/api/webhooks/",
        service: "discord_webhook_url",
        min_len: 50,
    },
    // ── OSINT / Security APIs ──────────────────────────────────
    KeyPattern {
        prefix: "d0a2df",
        service: "shodan",
        min_len: 32,
    },
    KeyPattern {
        prefix: "aWD4bm",
        service: "censys",
        min_len: 30,
    },
    KeyPattern {
        prefix: "bp0_",
        service: "binaryedge",
        min_len: 30,
    },
    KeyPattern {
        prefix: "rl_",
        service: "riskiq",
        min_len: 30,
    },
    // SeekNow (see-know.icu) breach/stealer API keys are `seek-` + 48 lowercase
    // hex chars (53 total; every embedded default and rotated-out key observed to
    // date fits this exactly — see `keys::constants::SEEKNOW_*`). The `see_know`
    // service is poolable (`service_defs`) and is the same name the domain router
    // (`service_domains`) maps `see-know.icu` to, so a raw key harvested here folds
    // straight into the same rotation pool as a stealer-log credential — a direct
    // path to a second live enterprise key (double the 15k/day quota) when one
    // leaks into the breach corpus. `min_len` 48 leaves comfortable margin under
    // the real 53 while the entropy gate rejects a low-signal `seek-…` phrase.
    KeyPattern {
        prefix: "seek-",
        service: "see_know",
        min_len: 48,
    },
    // ── Cloud / Infrastructure ─────────────────────────────────
    KeyPattern {
        prefix: "AZURE",
        service: "azure",
        min_len: 40,
    },
    KeyPattern {
        prefix: "az_",
        service: "azure_devops",
        min_len: 50,
    },
    KeyPattern {
        prefix: "AGC",
        service: "alibaba_cloud",
        min_len: 20,
    },
    KeyPattern {
        prefix: "LTAI",
        service: "alibaba_cloud",
        min_len: 16,
    },
    KeyPattern {
        prefix: "GOOG",
        service: "gcp_service",
        min_len: 20,
    },
    // (Removed an accidental duplicate `glpat-` → `gitlab` entry here: it had the
    // same prefix and min_len as the earlier `glpat-` → `gitlab_pat`, so it was
    // unreachable. `gitlab_pat` is the precise label — glpat- is a GitLab
    // Personal Access Token.)
    KeyPattern {
        prefix: "gldt-",
        service: "gitlab_deploy",
        min_len: 20,
    },
    KeyPattern {
        prefix: "glrt-",
        service: "gitlab_runner",
        min_len: 20,
    },
    KeyPattern {
        prefix: "gloas-",
        service: "gitlab_oauth",
        min_len: 40,
    },
    KeyPattern {
        prefix: "phc_",
        service: "posthog",
        min_len: 30,
    },
    KeyPattern {
        prefix: "phx_",
        service: "posthog",
        min_len: 30,
    },
    KeyPattern {
        prefix: "rnd_",
        service: "render",
        min_len: 30,
    },
    KeyPattern {
        prefix: "tvly-",
        service: "tavily",
        min_len: 30,
    },
    KeyPattern {
        prefix: "v2_",
        service: "vercel_v2",
        min_len: 20,
    },
    KeyPattern {
        prefix: "nf_",
        service: "netlify",
        min_len: 36,
    },
    KeyPattern {
        prefix: "re_",
        service: "resend",
        min_len: 30,
    },
    KeyPattern {
        prefix: "mlc_",
        service: "mailersend",
        min_len: 30,
    },
    KeyPattern {
        prefix: "aptible_",
        service: "aptible",
        min_len: 40,
    },
    KeyPattern {
        prefix: "flg_",
        service: "flagsmith",
        min_len: 30,
    },
    KeyPattern {
        prefix: "prj_",
        service: "railway",
        min_len: 30,
    },
    KeyPattern {
        prefix: "fly_",
        service: "flyio",
        min_len: 30,
    },
    // ── AI / ML ────────────────────────────────────────────────
    KeyPattern {
        prefix: "sess-",
        service: "openai_session",
        min_len: 40,
    },
    KeyPattern {
        prefix: "gsk_",
        service: "groq",
        min_len: 40,
    },
    KeyPattern {
        prefix: "LA-",
        service: "lightning_ai",
        min_len: 30,
    },
    KeyPattern {
        prefix: "co-",
        service: "cohere",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pplx-",
        service: "perplexity",
        min_len: 30,
    },
    KeyPattern {
        prefix: "ant-",
        service: "anthropic",
        min_len: 40,
    },
    KeyPattern {
        prefix: "mis-",
        service: "mistral",
        min_len: 30,
    },
    KeyPattern {
        prefix: "cmpl-",
        service: "mistral",
        min_len: 30,
    },
    KeyPattern {
        prefix: "tok_",
        service: "together_ai",
        min_len: 40,
    },
    KeyPattern {
        prefix: "fal_",
        service: "fal_ai",
        min_len: 30,
    },
    KeyPattern {
        prefix: "w&b_",
        service: "wandb",
        min_len: 30,
    },
    // ── Payment / Fintech ──────────────────────────────────────
    KeyPattern {
        prefix: "pay_",
        service: "paystack",
        min_len: 30,
    },
    KeyPattern {
        prefix: "rzp_",
        service: "razorpay",
        min_len: 20,
    },
    KeyPattern {
        prefix: "pi_",
        service: "stripe_pi",
        min_len: 24,
    },
    KeyPattern {
        prefix: "sub_",
        service: "stripe_sub",
        min_len: 24,
    },
    KeyPattern {
        prefix: "cus_",
        service: "stripe_customer",
        // Real Stripe customer IDs are `cus_` + ~24-char random
        // suffix; raised from 14 to 16 to clear the global
        // `identify_api_key` length gate (which rejects anything
        // < 16 chars before even attempting prefix-match).
        min_len: 16,
    },
    KeyPattern {
        prefix: "ch_",
        service: "stripe_charge",
        min_len: 20,
    },
    // ── Communication / Messaging ──────────────────────────────
    KeyPattern {
        prefix: "xoxe-",
        service: "slack_enterprise",
        min_len: 30,
    },
    KeyPattern {
        prefix: "xoxr-",
        service: "slack_refresh",
        min_len: 30,
    },
    KeyPattern {
        prefix: "Bearer fob-",
        service: "fibery",
        min_len: 40,
    },
    KeyPattern {
        prefix: "api-",
        service: "postmark",
        min_len: 30,
    },
    KeyPattern {
        prefix: "tgp_",
        service: "telegram_bot",
        min_len: 30,
    },
    // ── Database / Storage ─────────────────────────────────────
    KeyPattern {
        prefix: "mongodb+srv://",
        service: "mongodb_atlas",
        min_len: 30,
    },
    KeyPattern {
        prefix: "postgres://",
        service: "postgres_uri",
        min_len: 20,
    },
    // Connection URI prefixes — raised from 15 → 16 so they clear
    // the global length gate. Real URIs of these schemes are
    // typically `redis://[user[:pass]@]host[:port][/db]` etc., so 16
    // is still a generous lower bound.
    KeyPattern {
        prefix: "redis://",
        service: "redis_uri",
        min_len: 16,
    },
    KeyPattern {
        prefix: "mysql://",
        service: "mysql_uri",
        min_len: 16,
    },
    KeyPattern {
        prefix: "amqp://",
        service: "rabbitmq_uri",
        min_len: 16,
    },
    // ── Mapping / OSINT Geolocation ────────────────────────────
    KeyPattern {
        prefix: "pk.eyJ",
        service: "mapbox",
        min_len: 60,
    },
    KeyPattern {
        prefix: "sk.eyJ",
        service: "mapbox_secret",
        min_len: 60,
    },
    KeyPattern {
        prefix: "geo_",
        service: "geocodio",
        min_len: 30,
    },
    // ── CI / DevOps ────────────────────────────────────────────
    KeyPattern {
        prefix: "circle_",
        service: "circleci",
        min_len: 30,
    },
    KeyPattern {
        prefix: "dsn_",
        service: "sentry_dsn",
        min_len: 30,
    },
    KeyPattern {
        prefix: "wrkr_",
        service: "cloudflare_worker",
        min_len: 30,
    },
    KeyPattern {
        prefix: "aio_",
        service: "adafruit_io",
        min_len: 20,
    },
    KeyPattern {
        prefix: "kf_",
        service: "kinde",
        min_len: 30,
    },
    KeyPattern {
        prefix: "sk_prod_",
        service: "clerk",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pk_test_",
        service: "clerk_pub",
        min_len: 30,
    },
    KeyPattern {
        prefix: "pk_live_",
        service: "clerk_pub_live",
        min_len: 30,
    },
    // ── Additional high-value providers (precise, prefix-anchored; distinct
    //    stems, so order vs the generic entries above doesn't matter). ──
    // Fly.io's current macaroon format (`fo1_`/`fly_` cover the older tokens).
    KeyPattern {
        prefix: "fm2_",
        service: "flyio",
        min_len: 40,
    },
    // Grafana service-account token (`glsa_<base62>_<8 hex>`).
    KeyPattern {
        prefix: "glsa_",
        service: "grafana",
        min_len: 40,
    },
    // Tailscale auth/API key (`tskey-auth-…` / `tskey-api-…`).
    KeyPattern {
        prefix: "tskey-",
        service: "tailscale",
        min_len: 36,
    },
    // Google OAuth 2.0 client secret.
    KeyPattern {
        prefix: "GOCSPX-",
        service: "google_oauth_secret",
        min_len: 28,
    },
    // Sourcegraph access token (`sgp_<40 hex>` / `sgp_<instance>_<40 hex>`).
    KeyPattern {
        prefix: "sgp_",
        service: "sourcegraph",
        min_len: 40,
    },
    // DigitalOcean OAuth token (`dop_v1_` above is the personal access token).
    KeyPattern {
        prefix: "doo_v1_",
        service: "digitalocean_oauth",
        min_len: 70,
    },
];
