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

pub(super) fn extract_api_keys_from_item(
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
            let dedup = format!(
                "@apikey:{service}:{}",
                crate::util::str_util::truncate_safe(key_val, 16)
            );
            if !seen.insert(dedup) {
                continue;
            }

            // Emit as Credential entity tagged for api_key_probe expansion
            let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.80, scan_id);
            entity.tag("api-key");
            entity.tag(format!("service:{service}"));
            entity.tag("oathnet-pro");
            entity.tag("auto-discovered");

            let db = val_str(item, "dbname").unwrap_or_default();
            entity.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "API key discovered ({service}) in {}",
                        if db.is_empty() { "stealer log" } else { &db }
                    ),
                )
                .with_attr("service", service)
                .with_attr(
                    "key_prefix",
                    crate::util::str_util::truncate_safe(key_val, 8),
                )
                .with_attr("key_length", key_val.len().to_string()),
            );
            result.push(entity);

            // Auto-store in key pool
            let pool = crate::util::key_pool::global_pool();
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!(
                "Auto-discovered {service} key from OathNet breach/stealer data"
            ));
            pool.add(service, entry);
            let _ = crate::util::key_pool::save_pool(&pool);
        }
    }

    // Also scan the username field — some stealer logs store API keys as usernames
    if let Some(user) = val_str(item, "username")
        && let Some((service, key_val)) = identify_api_key(&user)
    {
        let dedup = format!(
            "@apikey:{service}:{}",
            crate::util::str_util::truncate_safe(key_val, 16)
        );
        if seen.insert(dedup) {
            let mut entity = Entity::new(EntityKind::ApiKey, key_val, 0.75, scan_id);
            entity.tag("api-key");
            entity.tag(format!("service:{service}"));
            entity.tag("oathnet-pro");
            entity.add_evidence(
                Evidence::new(SRC, format!("API key in username field ({service})"))
                    .with_attr("service", service),
            );
            result.push(entity);

            let pool = crate::util::key_pool::global_pool();
            let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
            entry.notes = Some(format!("Auto-discovered {service} key (username field)"));
            pool.add(service, entry);
            let _ = crate::util::key_pool::save_pool(&pool);
        }
    }
}

// ─── Automatic API credential storage ────────────────────────────────────────

pub(super) const API_SERVICE_DOMAINS: &[(&str, &str)] = &[
    ("shodan.io", "shodan"),
    ("account.shodan.io", "shodan"),
    ("virustotal.com", "virustotal"),
    ("hunter.io", "hunter"),
    ("securitytrails.com", "securitytrails"),
    ("dehashed.com", "dehashed"),
    ("intelx.io", "intelx"),
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

pub(super) fn store_api_credential(item: &Value) {
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
