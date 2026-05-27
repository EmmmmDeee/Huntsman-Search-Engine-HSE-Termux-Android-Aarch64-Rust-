use std::collections::HashSet;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::oathnet::{self, paths, val_str};


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
];

pub(super) fn identify_api_key(value: &str) -> Option<(&'static str, &str)> {
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
        "api_key",
        "token",
        "secret",
        "access_key",
        "auth_token",
        "api_token",
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
                    "oathnet_pro",
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
                Evidence::new(
                    "oathnet_pro",
                    format!("API key in username field ({service})"),
                )
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
];

pub(super) const HARVEST_TARGETS: &[(&str, &str)] = &[
    ("shodan.io", "shodan"),
    ("virustotal.com", "virustotal"),
    ("hunter.io", "hunter"),
    ("securitytrails.com", "securitytrails"),
    ("dehashed.com", "dehashed"),
    ("intelx.io", "intelx"),
    ("ipqualityscore.com", "ipqs"),
    ("leakix.net", "leakix"),
    ("haveibeenpwned.com", "hibp"),
    ("censys.io", "censys"),
    ("binaryedge.io", "binaryedge"),
    ("greynoise.io", "greynoise"),
    ("fullhunt.io", "fullhunt"),
    ("urlscan.io", "urlscan"),
    ("abuseipdb.com", "abuseipdb"),
    ("criminalip.io", "criminal_ip"),
    ("numverify.com", "numverify"),
    ("wigle.net", "wigle"),
    ("serpapi.com", "serpapi"),
    ("openai.com", "openai"),
    ("anthropic.com", "anthropic"),
    ("passivetotal.org", "passivetotal"),
    ("riskiq.net", "passivetotal"),
    ("onyphe.io", "onyphe"),
    ("zoomeye.org", "zoomeye"),
    ("fofa.info", "fofa"),
    ("netlas.io", "netlas"),
    ("pulsedive.com", "pulsedive"),
    ("builtwith.com", "builtwith"),
    ("emailrep.io", "emailrep"),
    ("seon.io", "seon"),
    ("epieos.com", "epieos"),
    ("nubela.co", "proxycurl"),
    ("opencorporates.com", "opencorporates"),
    ("whoisxmlapi.com", "whoisxml"),
    ("breachdirectory.org", "breachdirectory"),
    ("c99.nl", "c99"),
    ("twilio.com", "twilio"),
    ("snyk.io", "snyk"),
    ("digitalocean.com", "digitalocean"),
    ("ngrok.com", "ngrok"),
    ("mailchimp.com", "mailchimp"),
    ("discord.com", "discord"),
    ("npmjs.org", "npm"),
    ("pypi.org", "pypi"),
    ("vercel.com", "vercel"),
    ("netlify.com", "netlify"),
    ("heroku.com", "heroku"),
];

pub(super) async fn harvest_api_credentials_from_stealer(key: &str) {
    let pool = crate::util::key_pool::global_pool();
    let mut stored = 0u32;
    let mut seen: HashSet<String> = HashSet::new();

    // ── PRECISE QUERIES ONLY ──
    // Live-tested: only domain= and password= return domain-relevant results.
    // All other field params (q=, username=, email=) return generic data.

    // Phase 1: domain= queries — 100% precise (verified live).
    for (domain, service) in HARVEST_TARGETS {
        if pool.active_count(service) >= 5 {
            continue;
        }
        if let Ok(items) = oathnet::search(key, paths::STEALER, "domain", domain, 20).await {
            stored += store_unique_stealer_keys(&items, domain, service, &pool, &mut seen);
        }
    }

    // Phase 2: password= queries — 100% precise (verified live).
    for (domain, service) in HARVEST_TARGETS {
        if pool.active_count(service) >= 5 {
            continue;
        }
        if let Ok(items) = oathnet::search(key, paths::STEALER, "password", domain, 10).await {
            for item in &items {
                let pw = val_str(item, "password").unwrap_or_default();
                let user = val_str(item, "username").unwrap_or_default();
                let url = val_str(item, "url").unwrap_or_default();
                if user.is_empty() || pw.is_empty() || !seen.insert(format!("pw:{service}:{user}"))
                {
                    continue;
                }
                let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
                entry.notes = Some(format!(
                    "OathNet password-match [{service}]: user={} url={}",
                    &crate::util::str_util::truncate_safe(&user, 25),
                    &crate::util::str_util::truncate_safe(&url, 50)
                ));
                pool.add(service, entry);
                pool.add(
                    &format!("{service}_login"),
                    crate::util::key_pool::KeyEntry::new(format!("{user}:{pw}")),
                );
                stored += 1;
            }
        }
    }

    // Phase 3: username= field-name capture — returns entries where form
    // field names like "api_key" were stored as the username. The password
    // field contains the actual key value. NOT domain-precise, but the
    // values are API-key-shaped (28+ chars, mixed alphanumeric).
    const KEY_FIELD_NAMES: &[&str] = &[
        "api_key",
        "apikey",
        "api-key",
        "apiKey",
        "access_key",
        "secret_key",
        "api_token",
        "auth_token",
        "token",
        "access_token",
        "x-api-key",
        "x-key",
        "SHODAN_API_KEY",
        "VT_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "STRIPE_SECRET_KEY",
        "SENDGRID_API_KEY",
        "HIBP_API_KEY",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "GREYNOISE_API_KEY",
        "HUNTER_API_KEY",
        "INTELX_API_KEY",
        "LEAKIX_API_KEY",
        "URLSCAN_API_KEY",
        "ABUSEIPDB_KEY",
        "BINARYEDGE_API_KEY",
        "FULLHUNT_API_KEY",
        "SECURITYTRAILS_API_KEY",
        "CRIMINALIP_API_KEY",
        "TWILIO_AUTH_TOKEN",
        "TWILIO_ACCOUNT_SID",
        "MAILCHIMP_API_KEY",
        "DISCORD_TOKEN",
        "DISCORD_BOT_TOKEN",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "HEROKU_API_KEY",
        "VERCEL_TOKEN",
        "NETLIFY_AUTH_TOKEN",
        "DIGITALOCEAN_TOKEN",
        "NGROK_AUTHTOKEN",
        "SNYK_TOKEN",
        "DATABRICKS_TOKEN",
        "CLOUDFLARE_API_TOKEN",
        "SUPABASE_KEY",
        "NOTION_TOKEN",
        "LINEAR_API_KEY",
        "SENTRY_AUTH_TOKEN",
        "GRAFANA_API_KEY",
        "NEWRELIC_API_KEY",
        "PAGERDUTY_TOKEN",
        "DATADOG_API_KEY",
    ];
    for field_name in KEY_FIELD_NAMES {
        if pool.total_keys() > 500 {
            break;
        }
        if let Ok(items) = oathnet::search(key, paths::STEALER, "username", field_name, 10).await {
            for item in &items {
                let pw = val_str(item, "password").unwrap_or_default();
                let url = val_str(item, "url").unwrap_or_default();
                if pw.len() < 10 || !seen.insert(format!("fn:{field_name}:{pw}")) {
                    continue;
                }
                let service = identify_service_from_url(&url);
                let label = if service != "unknown" {
                    service
                } else {
                    "discovered_api_key"
                };
                let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
                entry.notes = Some(format!(
                    "OathNet field-capture [{field_name}->{label}]: url={}",
                    &crate::util::str_util::truncate_safe(&url, 50)
                ));
                pool.add(label, entry);
                stored += 1;
            }
        }
    }

    // Phase 4: Breach domain= pattern scan with 37-prefix scanner.
    for (domain, service) in HARVEST_TARGETS.iter().take(25) {
        if pool.total_keys() > 500 {
            break;
        }
        if let Ok(items) = oathnet::search(key, paths::BREACH, "domain", domain, 20).await {
            for item in &items {
                for field in ["password", "password_hash", "username"] {
                    if let Some(val) = val_str(item, field)
                        && let Some((svc, key_val)) = identify_api_key(&val)
                        && seen.insert(format!(
                            "br:{svc}:{}",
                            crate::util::str_util::truncate_safe(key_val, 12)
                        ))
                    {
                        let mut entry = crate::util::key_pool::KeyEntry::new(key_val);
                        entry.notes = Some(format!(
                            "OathNet breach [{svc}]: field={field} via={service}"
                        ));
                        pool.add(svc, entry);
                        stored += 1;
                    }
                }
            }
        }
    }

    if stored > 0 {
        let _ = crate::util::key_pool::save_pool(&pool);
    }
}

pub(super) fn store_unique_stealer_keys(
    items: &[Value],
    domain: &str,
    service: &str,
    pool: &crate::util::key_pool::KeyPool,
    seen: &mut HashSet<String>,
) -> u32 {
    let mut stored = 0u32;
    for item in items {
        let url = val_str(item, "url").unwrap_or_default();
        let user = val_str(item, "username").unwrap_or_default();
        let pw = val_str(item, "password").unwrap_or_default();
        if user.is_empty() || pw.is_empty() {
            continue;
        }
        if !seen.insert(format!("{service}:{pw}")) {
            continue;
        }

        let url_lower = url.to_lowercase();
        let domains_field: Vec<String> = item
            .get("domain")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();

        let url_matches =
            url_lower.contains(domain) || domains_field.iter().any(|d| d.contains(domain));

        if url_matches {
            let mut entry = crate::util::key_pool::KeyEntry::new(&pw);
            entry.notes = Some(format!(
                "OathNet stealer [{}]: user={} url={}",
                service,
                &crate::util::str_util::truncate_safe(&user, 30),
                &crate::util::str_util::truncate_safe(&url, 60)
            ));
            if pool.add(service, entry) {
                stored += 1;
            }
        }

        let login_entry = crate::util::key_pool::KeyEntry::new(format!("{user}:{pw}"));
        pool.add(&format!("{service}_login"), login_entry);
        stored += 1;
    }
    stored
}

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
        .unwrap_or_default();
    let username = val_str(item, "username").unwrap_or_default();
    let password = val_str(item, "password").unwrap_or_default();

    if username.is_empty() || password.is_empty() || url.is_empty() {
        return;
    }

    let service = identify_service_from_url(&url);
    if service == "unknown" {
        return;
    }

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

