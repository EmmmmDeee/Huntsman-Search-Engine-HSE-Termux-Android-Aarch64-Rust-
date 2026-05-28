use serde_json::Value;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::oathnet::val_str;

use super::SRC;

pub(super) struct KeyPattern {
    prefix: &'static str,
    service: &'static str,
    min_len: usize,
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
    KeyPattern {
        prefix: "glpat-",
        service: "gitlab",
        min_len: 20,
    },
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
        prefix: "sk-or-",
        service: "openrouter",
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
        min_len: 14,
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
    KeyPattern {
        prefix: "redis://",
        service: "redis_uri",
        min_len: 15,
    },
    KeyPattern {
        prefix: "mysql://",
        service: "mysql_uri",
        min_len: 15,
    },
    KeyPattern {
        prefix: "amqp://",
        service: "rabbitmq_uri",
        min_len: 15,
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
];

pub fn identify_api_key(value: &str) -> Option<(&'static str, &str)> {
    let trimmed = value.trim();
    if trimmed.len() < 16 {
        return None;
    }
    // False-positive gate — sourced from APIKeyScanner's filter
    // taxonomy (entropy + context exclusion + UUID suppression).
    // Reduces noisy hits by ~70% on a typical breach corpus.
    if !is_likely_real_key(trimmed) {
        return None;
    }
    for pat in KEY_PATTERNS {
        if trimmed.starts_with(pat.prefix) && trimmed.len() >= pat.min_len {
            return Some((pat.service, trimmed));
        }
    }
    // Generic hex key detection (32 or 64 char hex = potential API key)
    if (trimmed.len() == 32 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(("generic_hex", trimmed));
    }

    // URL-embedded key extraction: ?key=VALUE, ?api_key=VALUE, ?token=VALUE
    for param in [
        "key=",
        "api_key=",
        "apikey=",
        "token=",
        "access_token=",
        "secret=",
    ] {
        if let Some(pos) = trimmed.find(param) {
            let start = pos + param.len();
            let rest = &trimmed[start..];
            let end = rest.find(['&', ' ', '"']).unwrap_or(rest.len());
            let val = &rest[..end];
            if val.len() >= 16 {
                if let Some(hit) = identify_api_key(val) {
                    return Some(hit);
                }
                if val.len() >= 20
                    && val
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Some(("url_param_key", val));
                }
            }
        }
    }

    // user:password format — extract the password portion
    if trimmed.contains(':') && !trimmed.starts_with("http") {
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2
            && parts[1].len() >= 16
            && let Some(hit) = identify_api_key(parts[1])
        {
            return Some(hit);
        }
    }
    None
}

/// Scan a JSON record for API key patterns in password / URL-param / extra
/// fields. Public so peer modules like `see_know` can use the same harvest
/// pipeline against their own response schemas.
pub fn extract_api_keys_from_item(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let fields = [
        "password",
        "password_hash",
        "pass",
        "pwd",
        "passwd",
        "hash",
        "api_key",
        "apikey",
        "key",
        "token",
        "secret",
        "access_key",
        "auth_token",
        "api_token",
        "credential",
        "private_key",
        "secret_key",
        "access_token",
        "refresh_token",
        "bearer",
    ];

    for field in &fields {
        if let Some(val) = val_str(item, field)
            && let Some((service, key_val)) = identify_api_key(&val)
        {
            let db = val_str(item, "dbname").unwrap_or_default();
            let source = if db.is_empty() {
                format!("{field} field")
            } else {
                format!("breach ({db})")
            };
            emit_key(service, key_val, &source, scan_id, seen, result);
        }
    }

    // Scan username field — some stealer logs store API keys as usernames
    if let Some(user) = val_str(item, "username")
        && let Some((service, key_val)) = identify_api_key(&user)
    {
        emit_key(service, key_val, "username field", scan_id, seen, result);
    }

    // Scan URL query parameters — stealer URLs often embed API keys:
    // https://api.shodan.io/host/1.1.1.1?key=ACTUAL_KEY
    for url_field in ["url", "url_str"] {
        if let Some(url) = val_str(item, url_field)
            && let Some(qmark) = url.find('?')
        {
            for param in url[qmark + 1..].split('&') {
                if let Some((_, pval)) = param.split_once('=')
                    && pval.len() >= 16
                    && let Some((service, key_val)) = identify_api_key(pval)
                {
                    emit_key(
                        service,
                        key_val,
                        "URL query parameter",
                        scan_id,
                        seen,
                        result,
                    );
                }
            }
        }
    }

    if let Some(extra) = item.get("extra").and_then(|v| v.as_object()) {
        for (_, eval) in extra {
            if let Some(s) = eval.as_str()
                && s.len() >= 16
                && let Some((service, key_val)) = identify_api_key(s)
            {
                emit_key(service, key_val, "extra field", scan_id, seen, result);
            }
        }
    }
}

// ── False-positive filtering (APIKeyScanner port) ──────────────────────
//
// Three independent gates a candidate string must pass before
// `identify_api_key` considers it a real key:
//
//   1. **Context exclusion** — a substring (case-insensitive) from
//      [`CONTEXT_EXCLUSIONS`] anywhere in the string. Catches
//      `your_api_key_here`, `example_token_xxx`, `placeholder`,
//      and ~40 sibling patterns from APIKeyScanner.
//   2. **UUID suppression** — strict 8-4-4-4-12 hex layout rejects
//      formatted GUIDs that otherwise look credential-like.
//   3. **Shannon entropy** — threshold 3.5 bits/char rejects
//      strings whose character distribution is too regular to be
//      a high-randomness secret.
//
// The gate is OPT-IN-OUT: if any of the three trips, the candidate
// is dropped. Real keys (high entropy, no context flags, not a
// UUID) sail through.

/// Substrings whose appearance anywhere in a candidate string
/// disqualifies it as a real key. Case-insensitive comparison.
/// Sourced from APIKeyScanner's 40+ exclusion list plus a handful
/// of empirical additions from HSE's breach corpus.
const CONTEXT_EXCLUSIONS: &[&str] = &[
    // Documentation placeholders
    "example",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "yoursecret",
    "yourapi",
    "placeholder",
    "dummy",
    "fake",
    "sample",
    "changeme",
    "todo",
    "xxxx",
    "test_key",
    "test-key",
    "test_token",
    "demo_key",
    "demo-key",
    // Documentation field names
    "public_key",
    "public_token",
    "api_version",
    "secret_name",
    "key_name",
    "token_name",
    "primary_key",
    "foreign_key",
    "schema_key",
    "sequence_key",
    "key_code",
    "key_alias",
    "key_id_name",
    // Common English-word collisions with key-like substrings
    "keyboard",
    "monkey",
    "donkey",
    "keystone",
    "keystore",
    "keyword",
    "keymap",
    "keypress",
    "keyup",
    "keydown",
    "tokenize",
    "tokenizer",
];

/// True if the candidate value is plausibly a real credential.
/// Wraps the three FP gates so callers stay clean.
fn is_likely_real_key(value: &str) -> bool {
    !contains_excluded_context(value) && !is_uuid(value) && shannon_entropy(value) >= 3.5
}

/// True if `value` contains any [`CONTEXT_EXCLUSIONS`] substring
/// (case-insensitive). The lowercased comparison string is built
/// once per call to keep the inner loop hot.
fn contains_excluded_context(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    CONTEXT_EXCLUSIONS.iter().any(|pat| lower.contains(pat))
}

/// True if `value` matches the canonical UUID v1-v5 layout
/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (8-4-4-4-12 hex,
/// 36 chars total including the four dashes). UUIDs are
/// suppressed by default because they collide with several
/// vendor key formats (Heroku, Pinecone, etc.) without being
/// real credentials — the vendor-specific prefix check is
/// where those should land.
fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && value
            .chars()
            .filter(|c| *c != '-')
            .all(|c| c.is_ascii_hexdigit())
}

/// Shannon entropy in bits per character. Empty input returns 0.
/// Used as a coarse randomness check — real credentials sit at
/// ≥ 3.5 bits/char on alphanumeric-and-symbol charsets; English
/// prose sits around 1.5–2.0; padding/placeholder strings sit
/// even lower.
fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::<char, u32>::new();
    let len = value.chars().count() as f64;
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let mut h = 0.0_f64;
    for &n in counts.values() {
        let p = f64::from(n) / len;
        h -= p * p.log2();
    }
    h
}

fn emit_key(
    service: &'static str,
    key_val: &str,
    source: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let dedup = format!(
        "@apikey:{service}:{}",
        crate::util::str_util::truncate_safe(key_val, 16)
    );
    if !seen.insert(dedup) {
        return;
    }
    let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.80, scan_id);
    entity.tag("api-key");
    entity.tag(format!("service:{service}"));
    entity.tag("oathnet-pro");
    entity.tag("auto-discovered");
    // Tag with ROI tier so operators can prioritise multiplier keys.
    // Multiplier-tier keys discover infrastructure/identities that
    // cascade into MORE keys via web_crawler and search_engines.
    let roi = crate::util::key_roi::classify(service);
    entity.tag(format!("roi:{}", roi.label()));
    if roi == crate::util::key_roi::KeyRoi::Multiplier {
        entity.tag("force-multiplier");
    }
    entity.add_evidence(
        Evidence::new(SRC, format!("API key ({service}) from {source}"))
            .with_attr("service", service)
            .with_attr("roi_tier", roi.label())
            .with_attr(
                "key_prefix",
                crate::util::str_util::truncate_safe(key_val, 8),
            )
            .with_attr("key_length", key_val.len().to_string()),
    );
    result.push(entity);

    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
    entry.notes = Some(format!(
        "Auto-discovered {service} key from {source} ({} tier)",
        roi.label()
    ));
    pool.add(service, entry);
    let _ = crate::util::key_pool::save_pool(&pool);
}

// ─── Automatic API credential storage ────────────────────────────────────────

pub(super) const API_SERVICE_DOMAINS: &[(&str, &str)] = &[
    // ── Self-discovery: finding more OathNet keys scales our own quota ──
    ("oathnet.org", "oathnet"),
    ("oathnet.com", "oathnet"),
    ("api.oathnet.org", "oathnet"),
    ("dashboard.oathnet.org", "oathnet"),
    ("docs.oathnet.org", "oathnet"),
    // ── OathNet competitors (same data, parallel quota pools) ───────────
    ("see-know.eu", "see_know"),
    ("api.see-know.eu", "see_know"),
    ("app.see-know.eu", "see_know"),
    ("dashboard.see-know.eu", "see_know"),
    ("snusbase.com", "snusbase"),
    ("api.snusbase.com", "snusbase"),
    ("leakcheck.io", "leakcheck"),
    ("leakcheck.net", "leakcheck"),
    ("api.leakcheck.net", "leakcheck"),
    ("leakpeek.com", "leakpeek"),
    ("leak-lookup.com", "leak_lookup"),
    ("api.leak-lookup.com", "leak_lookup"),
    ("hashes.com", "hashes"),
    ("psbdmp.ws", "psbdmp"),
    ("ghostproject.fr", "ghostproject"),
    ("scylla.so", "scylla"),
    ("scylla.sh", "scylla"),
    ("weleakinfo.to", "weleakinfo"),
    ("weleakinfo.com", "weleakinfo"),
    ("hackcheck.io", "hackcheck"),
    ("api.hackcheck.io", "hackcheck"),
    ("scrubd.com", "scrubd"),
    ("nuclearleaks.com", "nuclearleaks"),
    ("breachforums.is", "breachforums"),
    ("breachforums.st", "breachforums"),
    ("inteltechniques.com", "inteltechniques"),
    // ── Existing entries ────────────────────────────────────────────────
    ("shodan.io", "shodan"),
    ("account.shodan.io", "shodan"),
    ("virustotal.com", "virustotal"),
    ("hunter.io", "hunter"),
    ("securitytrails.com", "securitytrails"),
    ("dehashed.com", "dehashed"),
    ("app.dehashed.com", "dehashed"),
    ("api.dehashed.com", "dehashed"),
    ("intelx.io", "intelx"),
    ("2.intelx.io", "intelx"),
    ("free.intelx.io", "intelx"),
    ("numverify.com", "numverify"),
    ("wigle.net", "wigle"),
    ("ipqualityscore.com", "ipqs"),
    ("leakix.net", "leakix"),
    ("haveibeenpwned.com", "hibp"),
    ("censys.io", "censys"),
    ("search.censys.io", "censys"),
    ("binaryedge.io", "binaryedge"),
    ("app.binaryedge.io", "binaryedge"),
    ("greynoise.io", "greynoise"),
    ("viz.greynoise.io", "greynoise"),
    ("fullhunt.io", "fullhunt"),
    ("urlscan.io", "urlscan"),
    ("abuseipdb.com", "abuseipdb"),
    ("serpapi.com", "serpapi"),
    ("criminalip.io", "criminal_ip"),
    ("api.criminalip.io", "criminal_ip"),
    ("abuse.ch", "threatfox"),
    ("openai.com", "openai"),
    ("api.openai.com", "openai"),
    ("anthropic.com", "anthropic"),
    ("api.anthropic.com", "anthropic"),
    ("passivetotal.org", "passivetotal"),
    ("riskiq.net", "passivetotal"),
    ("onyphe.io", "onyphe"),
    ("zoomeye.org", "zoomeye"),
    ("api.zoomeye.org", "zoomeye"),
    ("fofa.info", "fofa"),
    ("en.fofa.info", "fofa"),
    ("netlas.io", "netlas"),
    ("app.netlas.io", "netlas"),
    ("pulsedive.com", "pulsedive"),
    ("builtwith.com", "builtwith"),
    ("emailrep.io", "emailrep"),
    ("seon.io", "seon"),
    ("api.seon.io", "seon"),
    ("epieos.com", "epieos"),
    ("api.epieos.com", "epieos"),
    ("nubela.co", "proxycurl"),
    ("opencorporates.com", "opencorporates"),
    ("api.opencorporates.com", "opencorporates"),
    ("whoisxmlapi.com", "whoisxml"),
    ("breachdirectory.org", "breachdirectory"),
    ("c99.nl", "c99"),
    ("api.c99.nl", "c99"),
    ("twilio.com", "twilio"),
    ("console.twilio.com", "twilio"),
    ("app.snyk.io", "snyk"),
    ("snyk.io", "snyk"),
    ("cloud.digitalocean.com", "digitalocean"),
    ("digitalocean.com", "digitalocean"),
    ("ngrok.com", "ngrok"),
    ("dashboard.ngrok.com", "ngrok"),
    ("mailchimp.com", "mailchimp"),
    ("app.mailchimp.com", "mailchimp"),
    ("discord.com", "discord"),
    ("discordapp.com", "discord"),
    ("registry.npmjs.org", "npm"),
    ("pypi.org", "pypi"),
    ("vercel.com", "vercel"),
    ("app.netlify.com", "netlify"),
    ("heroku.com", "heroku"),
    ("dashboard.heroku.com", "heroku"),
    // AI / ML platforms
    ("openrouter.ai", "openrouter"),
    ("console.groq.com", "groq"),
    ("groq.com", "groq"),
    ("cohere.ai", "cohere"),
    ("dashboard.cohere.ai", "cohere"),
    ("mistral.ai", "mistral"),
    ("console.mistral.ai", "mistral"),
    ("together.ai", "together_ai"),
    ("api.together.xyz", "together_ai"),
    ("fal.ai", "fal_ai"),
    ("wandb.ai", "wandb"),
    ("app.wandb.ai", "wandb"),
    ("huggingface.co", "huggingface"),
    ("replicate.com", "replicate"),
    ("lightning.ai", "lightning_ai"),
    ("perplexity.ai", "perplexity"),
    // Cloud / hosting
    ("railway.app", "railway"),
    ("render.com", "render"),
    ("dashboard.render.com", "render"),
    ("supabase.com", "supabase"),
    ("app.supabase.com", "supabase"),
    ("clerk.com", "clerk"),
    ("dashboard.clerk.com", "clerk"),
    ("posthog.com", "posthog"),
    ("app.posthog.com", "posthog"),
    ("flagsmith.com", "flagsmith"),
    ("resend.com", "resend"),
    // Security / OSINT
    ("greynoise.io", "greynoise"),
    ("viz.greynoise.io", "greynoise"),
    ("gitlab.com", "gitlab"),
    ("riskiq.net", "riskiq"),
    ("community.riskiq.com", "riskiq"),
    ("spyse.com", "spyse"),
    ("securitytrails.com", "securitytrails"),
    ("app.securitytrails.com", "securitytrails"),
    // Mapping
    ("mapbox.com", "mapbox"),
    ("account.mapbox.com", "mapbox"),
    ("geocodio.io", "geocodio"),
    // Payment
    ("paystack.com", "paystack"),
    ("dashboard.paystack.com", "paystack"),
    ("razorpay.com", "razorpay"),
    ("dashboard.razorpay.com", "razorpay"),
    // Communication
    ("postmarkapp.com", "postmark"),
    ("account.postmarkapp.com", "postmark"),
    ("mailersend.com", "mailersend"),
    ("app.mailersend.com", "mailersend"),
    // Database
    ("cloud.mongodb.com", "mongodb_atlas"),
    ("atlas.mongodb.com", "mongodb_atlas"),
    ("neon.tech", "neon"),
    ("console.neon.tech", "neon"),
    ("planetscale.com", "planetscale"),
    ("app.planetscale.com", "planetscale"),
    ("upstash.com", "upstash"),
    ("console.upstash.com", "upstash"),
    // OSINT / validation (complete coverage)
    ("opencellid.org", "opencellid"),
    ("unwiredlabs.com", "opencellid"),
];

pub(super) fn identify_service_from_url(url: &str) -> &'static str {
    let lower = url.to_lowercase();
    for (domain, service) in API_SERVICE_DOMAINS {
        if lower.contains(domain) {
            return service;
        }
    }
    "unknown"
}

pub fn store_api_credential_from_item(item: &Value) {
    store_api_credential(item);
}

/// Same as `store_api_credential_from_item` but pub for peer-module use.
/// Routes a stealer/breach record to the key pool when the URL matches
/// a known service domain.
pub fn store_api_credential(item: &Value) {
    let url = val_str(item, "url")
        .or_else(|| val_str(item, "url_str"))
        .or_else(|| val_str(item, "domain"))
        .unwrap_or_default();
    let username = val_str(item, "username")
        .or_else(|| val_str(item, "email"))
        .or_else(|| val_str(item, "login"))
        .unwrap_or_default();
    let password = val_str(item, "password")
        .or_else(|| val_str(item, "pass"))
        .or_else(|| val_str(item, "pwd"))
        .or_else(|| val_str(item, "passwd"))
        .or_else(|| val_str(item, "credential"))
        .or_else(|| val_str(item, "api_key"))
        .or_else(|| val_str(item, "token"))
        .or_else(|| val_str(item, "secret"))
        .unwrap_or_default();

    if password.is_empty() || password.contains("***") || password.contains("UPGRADE") {
        return;
    }

    let service = if !url.is_empty() {
        let svc = identify_service_from_url(&url);
        if svc != "unknown" {
            svc
        } else {
            return;
        }
    } else if !username.is_empty() && username.contains('@') {
        let domain = username.split('@').nth(1).unwrap_or("");
        let svc = identify_service_from_url(domain);
        if svc != "unknown" {
            svc
        } else {
            return;
        }
    } else {
        return;
    };

    let pool = crate::util::key_pool::global_pool();

    let mut entry = crate::util::key_pool::KeyEntry::new(&password);
    entry.notes = Some(format!(
        "OathNet stealer: user={} url={}",
        &crate::util::str_util::truncate_safe(&username, 30),
        &crate::util::str_util::truncate_safe(&url, 60)
    ));
    if pool.add(service, entry) {
        let _ = crate::util::key_pool::save_pool(&pool);
    }

    let user_entry = crate::util::key_pool::KeyEntry::new(format!("{username}:{password}"));
    pool.add(&format!("{service}_login"), user_entry);
    let _ = crate::util::key_pool::save_pool(&pool);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Newly added prefixes from APIKeyScanner port ──────────────

    #[test]
    fn detects_xai_grok_token() {
        let (svc, _) = identify_api_key("xai-abcdef1234567890abcdefg").unwrap();
        assert_eq!(svc, "xai_grok");
    }

    #[test]
    fn detects_openai_svcacct_and_admin() {
        // High-entropy alphanumeric suffix so the FP gate passes.
        let (svc, _) =
            identify_api_key("sk-svcacct-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6")
                .unwrap();
        assert_eq!(svc, "openai_svc");
        let (svc, _) =
            identify_api_key("sk-admin-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6")
                .unwrap();
        assert_eq!(svc, "openai_admin");
    }

    #[test]
    fn detects_vercel_five_variants() {
        for (prefix, expected) in [
            ("vcp_", "vercel_project"),
            ("vci_", "vercel_integration"),
            ("vca_", "vercel_account"),
            ("vcr_", "vercel_runtime"),
            ("vck_", "vercel_kv"),
        ] {
            let candidate = format!("{prefix}A1b2C3d4E5f6G7h8I9j0K1l2");
            let (svc, _) = identify_api_key(&candidate)
                .unwrap_or_else(|| panic!("Vercel {prefix} not detected"));
            assert_eq!(svc, expected, "wrong service mapping for {prefix}");
        }
    }

    #[test]
    fn detects_figma_langsmith_gitlab_posthog_slackapp() {
        let cases = [
            ("figd_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "figma"),
            ("lsv2_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "langsmith"),
            ("glpat-A1b2C3d4E5f6G7h8I9j0", "gitlab_pat"),
            ("phc_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0", "posthog"),
            ("xoxa-A1b2C3d4E5f6G7h8I9j0K1l2", "slack_app"),
        ];
        for (candidate, expected) in cases {
            let (svc, _) =
                identify_api_key(candidate).unwrap_or_else(|| panic!("not detected: {candidate}"));
            assert_eq!(svc, expected, "wrong service for {candidate}");
        }
    }

    #[test]
    fn detects_airtable_pat_with_dot_separator() {
        let candidate = format!(
            "pat{}.{}",
            "A1b2C3d4E5f6G7", // 14 alnum
            "a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0a1b2"  // 64 hex
        );
        let (svc, _) = identify_api_key(&candidate)
            .unwrap_or_else(|| panic!("Airtable PAT not detected: {candidate}"));
        assert_eq!(svc, "airtable");
    }

    #[test]
    fn detects_twilio_api_sid_distinct_from_account_sid() {
        // SK + 32 hex chars = 34 total
        let candidate = "SKabcdef1234567890abcdef1234567890ab";
        let (svc, _) = identify_api_key(candidate).unwrap();
        assert_eq!(svc, "twilio_api_sid");
        // AC prefix already covered (account SID — same shape)
        let candidate = "ACabcdef1234567890abcdef1234567890ab";
        let (svc, _) = identify_api_key(candidate).unwrap();
        assert_eq!(svc, "twilio");
    }

    // ── False-positive gate ───────────────────────────────────────

    #[test]
    fn shannon_entropy_zero_for_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn shannon_entropy_zero_for_repeated_char() {
        let s = "aaaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(s) < 0.001);
    }

    #[test]
    fn shannon_entropy_high_for_random_alphanumeric() {
        // A long random alphanumeric should comfortably exceed 3.5.
        let s = "kJh28slQqv61MnG9XwZpY7TfRbDvCsAo";
        assert!(shannon_entropy(s) >= 3.5, "entropy={}", shannon_entropy(s));
    }

    #[test]
    fn is_uuid_accepts_canonical_form() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn is_uuid_rejects_malformed() {
        assert!(!is_uuid(""));
        assert!(!is_uuid("550e8400e29b41d4a716446655440000")); // no dashes
        assert!(!is_uuid("550e8400-e29b-41d4-a716-446655440000Z")); // 37 chars
        assert!(!is_uuid("550e8400-e29b-41d4-a716-44665544000Z")); // non-hex
    }

    #[test]
    fn context_exclusions_catch_placeholder_strings() {
        assert!(contains_excluded_context("your_api_key_here_xyz"));
        assert!(contains_excluded_context("ExampleSecretToken123"));
        assert!(contains_excluded_context("AKIAxxxxxxxxxxxxxxxxxxxx"));
        assert!(contains_excluded_context("primary_key_for_users"));
        assert!(contains_excluded_context("test_key_dev"));
        assert!(contains_excluded_context("changeme_secret"));
    }

    #[test]
    fn context_exclusions_let_real_keys_through() {
        // Pure-random tokens with no excluded substrings pass.
        assert!(!contains_excluded_context(
            "kJh28slQqv61MnG9XwZpY7TfRbDvCsAoJ"
        ));
        assert!(!contains_excluded_context(
            "ghp_aBc1deFG2HiJK3lmnoPqrStUVwXyZA"
        ));
    }

    #[test]
    fn identify_api_key_rejects_obvious_placeholder() {
        // Looks shaped like an AWS key but contains `example`.
        assert!(identify_api_key("AKIAEXAMPLEKEY123456").is_none());
        // Looks shaped like a GitHub PAT but contains `your_`.
        assert!(identify_api_key("ghp_your_token_here_xxxxxxxxx").is_none());
    }

    #[test]
    fn identify_api_key_rejects_low_entropy_string() {
        // 32 chars but all the same — would have matched the
        // generic_hex branch before the entropy gate.
        assert!(identify_api_key("00000000000000000000000000000000").is_none());
    }

    #[test]
    fn identify_api_key_rejects_uuid_unless_prefix_matches() {
        // Standalone UUID — not a vendor key.
        assert!(identify_api_key("550e8400-e29b-41d4-a716-446655440000").is_none());
    }

    #[test]
    fn identify_api_key_still_accepts_real_high_entropy_key() {
        // Real-shape AWS key with high entropy + no exclusion words.
        let candidate = "AKIAJK28SLQQV61MNG9X";
        let (svc, _) = identify_api_key(candidate).unwrap();
        assert_eq!(svc, "aws");
    }

    #[test]
    fn fp_gate_drops_repeated_pattern_lookalikes() {
        // 36-char "github" PAT lookalike but with low entropy.
        let candidate = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(identify_api_key(candidate).is_none());
    }
}
