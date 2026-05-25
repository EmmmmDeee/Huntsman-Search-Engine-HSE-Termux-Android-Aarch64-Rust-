use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    entity::Evidence,
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{fetch_json_or_404, urlencode};

pub struct HudsonRock;

#[derive(Deserialize)]
struct CavalierResp {
    #[serde(default)]
    stealers: Vec<Stealer>,
}

#[derive(Deserialize)]
struct Stealer {
    computer_name: Option<String>,
    operating_system: Option<String>,
    date_compromised: Option<String>,
    date_uploaded: Option<String>,
    stealer_family: Option<String>,
    ip: Option<String>,
    malware_path: Option<String>,
    #[serde(default)]
    credentials: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

const BASE_CONFIDENCE: f64 = 0.85;
const FRESH_CONFIDENCE: f64 = 0.92;
const FRESHNESS_WINDOW_DAYS: u64 = 90;

#[async_trait]
impl Module for HudsonRock {
    fn name(&self) -> &'static str {
        "hudsonrock"
    }

    fn description(&self) -> &'static str {
        "Free stealer-log lookup via HudsonRock Cavalier"
    }

    fn priority(&self) -> u8 {
        130
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email | TargetKind::Username | TargetKind::Domain
        )
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let url = match target.kind {
            TargetKind::Email | TargetKind::Username => format!(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-login?username={}",
                urlencode(&target.value)
            ),
            TargetKind::Domain => format!(
                "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={}",
                urlencode(&target.value)
            ),
            _ => return Ok(ModuleResult::new()),
        };

        let Some(data): Option<CavalierResp> =
            fetch_json_or_404(&ctx.http, "hudsonrock", &url).await?
        else {
            return Ok(ModuleResult::new());
        };

        if data.stealers.is_empty() {
            return Ok(ModuleResult::new());
        }

        let confidence = compute_confidence(&data.stealers);
        let mut entity = target.to_entity(confidence, &ctx.scan_id);
        entity.tag(tags::BREACH);
        entity.tag(tags::STEALER_LOG);

        let mut seen_families: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut seen_hosts: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();

        for stealer in &data.stealers {
            let cred_count = stealer.credentials.len();
            let family = stealer.stealer_family.as_deref().unwrap_or("-");

            if let Some(f) = stealer.stealer_family.as_deref() {
                seen_families.insert(f);
            }
            if let Some(h) = stealer.computer_name.as_deref() {
                seen_hosts.insert(h);
            }

            let mut stealer_ev = Evidence::new(
                "hudsonrock",
                format!("Stealer log: {cred_count} credentials on compromised machine"),
            )
            .with_attr(
                "computer_name",
                stealer.computer_name.as_deref().unwrap_or("-"),
            )
            .with_attr(
                "operating_system",
                stealer.operating_system.as_deref().unwrap_or("-"),
            )
            .with_attr(
                "date_compromised",
                stealer.date_compromised.as_deref().unwrap_or("-"),
            )
            .with_attr("stealer_family", family)
            .with_attr(
                "malware_path",
                stealer.malware_path.as_deref().unwrap_or("-"),
            )
            .with_attr("credential_count", cred_count.to_string())
            .with_opt_attr("date_uploaded", stealer.date_uploaded.as_deref())
            .with_opt_attr("victim_ip", stealer.ip.as_deref());
            for (k, v) in &stealer.extra {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                stealer_ev = stealer_ev.with_attr(format!("hudsonrock_{k}"), val_str);
            }
            entity.add_evidence(stealer_ev);
        }

        for family in &seen_families {
            entity.tag(format!("stealer:{}", family.to_lowercase()));
        }
        entity.tag_if(seen_hosts.len() >= 2, tags::MULTI_DEVICE);
        entity.tag(format!("stealer-count:{}", data.stealers.len()));

        let mut result = ModuleResult::new();

        // Extract victim IPs as separate IpAddress entities
        let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for stealer in &data.stealers {
            if let Some(ip) = stealer.ip.as_deref()
                && ip.len() >= 7
                && seen_ips.insert(ip.to_string())
            {
                let mut ip_entity = crate::core::entity::Entity::new(
                    crate::core::entity::EntityKind::IpAddress,
                    ip,
                    0.55,
                    &ctx.scan_id,
                );
                ip_entity.tag(tags::STEALER_LOG);
                ip_entity.tag(tags::VICTIM_MACHINE);
                ip_entity.add_evidence(
                    Evidence::new(
                        "hudsonrock",
                        "Victim machine IP from stealer log".to_string(),
                    )
                    .with_attr("source", "stealer")
                    .with_opt_attr("computer_name", stealer.computer_name.as_deref())
                    .with_opt_attr("os", stealer.operating_system.as_deref())
                    .with_opt_attr("stealer_family", stealer.stealer_family.as_deref()),
                );
                result.push(ip_entity);
            }
        }

        // Extract compromised service URLs from credential data
        let mut seen_cred_urls: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for stealer in &data.stealers {
            for cred in &stealer.credentials {
                if let Some(url) = cred.get("url").and_then(|v| v.as_str())
                    && url.starts_with("http")
                    && seen_cred_urls.insert(url.to_lowercase())
                    && let Ok(parsed) = url::Url::parse(url)
                    && let Some(host) = parsed.host_str()
                {
                    let domain = host.to_lowercase();
                    if domain.contains('.') && seen_cred_urls.insert(format!("@dom:{domain}")) {
                        let mut d = crate::core::entity::Entity::new(
                            crate::core::entity::EntityKind::Domain,
                            &domain,
                            0.50,
                            &ctx.scan_id,
                        );
                        d.tag(tags::STEALER_LOG);
                        d.tag(tags::COMPROMISED_SERVICE);
                        d.add_evidence(
                            Evidence::new("hudsonrock", format!("Stolen credential for {domain}"))
                                .with_attr("source", "stealer")
                                .with_attr("credential_url", url),
                        );
                        result.push(d);
                    }
                }
            }
        }

        // Extract individual credentials as Credential + Password entities
        let mut seen_creds: std::collections::HashSet<String> = std::collections::HashSet::new();
        for stealer in &data.stealers {
            for cred in &stealer.credentials {
                let cred_url = cred.get("url").and_then(|v| v.as_str()).unwrap_or("");
                let cred_user = cred.get("username").and_then(|v| v.as_str()).unwrap_or("");
                let cred_pass = cred.get("password").and_then(|v| v.as_str()).unwrap_or("");

                if !cred_user.is_empty() && !cred_url.is_empty() {
                    let cred_val = format!("{cred_user}@{cred_url}");
                    if seen_creds.insert(cred_val.to_lowercase()) {
                        let mut ce = crate::core::entity::Entity::new(
                            crate::core::entity::EntityKind::Credential,
                            &cred_val,
                            0.60,
                            &ctx.scan_id,
                        );
                        ce.tag(tags::STEALER_LOG);
                        ce.tag("credential-exposed");
                        ce.add_evidence(
                            Evidence::new(
                                "hudsonrock",
                                format!("Stolen credential for {cred_url}"),
                            )
                            .with_attr("source", "stealer")
                            .with_attr("username", cred_user)
                            .with_attr("password", cred_pass)
                            .with_attr("url", cred_url)
                            .with_opt_attr("stealer_family", stealer.stealer_family.as_deref()),
                        );
                        if !cred_pass.is_empty() {
                            crate::util::keyledger::append_key(
                                cred_url
                                    .split('/')
                                    .nth(2)
                                    .unwrap_or("unknown")
                                    .trim_start_matches("www."),
                                cred_user,
                                cred_pass,
                                cred_url,
                                "hudsonrock",
                                &ctx.scan_id,
                                "credential",
                                &["stealer-log".into()],
                            );
                        }
                        result.push(ce);
                    }
                }

                // Create Password entity for cross-correlation pivoting
                if cred_pass.len() >= 4
                    && seen_creds.insert(format!("@pw:{}", cred_pass.to_lowercase()))
                {
                    let mut pe = crate::core::entity::Entity::new(
                        crate::core::entity::EntityKind::Password,
                        cred_pass,
                        0.55,
                        &ctx.scan_id,
                    );
                    pe.tag(tags::STEALER_LOG);
                    pe.tag(tags::PASSWORD_AT_RISK);
                    pe.add_evidence(
                        Evidence::new("hudsonrock", "Password from stealer log")
                            .with_attr("source", "stealer")
                            .with_attr("credential_url", cred_url),
                    );
                    crate::util::keyledger::append_key(
                        cred_url
                            .split('/')
                            .nth(2)
                            .unwrap_or("unknown")
                            .trim_start_matches("www."),
                        cred_user,
                        cred_pass,
                        cred_url,
                        "hudsonrock",
                        &ctx.scan_id,
                        "password",
                        &["stealer-log".into()],
                    );
                    result.push(pe);
                }

                // Create Email entities from credential usernames that look like emails
                if cred_user.contains('@')
                    && cred_user.len() >= 5
                    && seen_creds.insert(format!("@cred-email:{}", cred_user.to_lowercase()))
                {
                    let mut email_ent = crate::core::entity::Entity::new(
                        crate::core::entity::EntityKind::Email,
                        cred_user,
                        0.60,
                        &ctx.scan_id,
                    );
                    email_ent.tag(tags::STEALER_LOG);
                    email_ent.tag(tags::BREACH);
                    email_ent.tag(tags::PASSWORD_AT_RISK);
                    email_ent.add_evidence(
                        Evidence::new(
                            "hudsonrock",
                            format!("Email credential stolen from {cred_url}"),
                        )
                        .with_attr("source", "stealer")
                        .with_attr("password", cred_pass)
                        .with_attr("url", cred_url),
                    );
                    result.push(email_ent);
                }
            }
        }

        // OathNet stealer cross-reference for deeper breach intel
        let key = crate::util::oathnet::resolve_key(ctx.key_opt(crate::util::oathnet::KEY_ENV));
        if !ctx.cancel.is_cancelled() {
            let oathnet_field = match target.kind {
                TargetKind::Email => "email",
                TargetKind::Username => "username",
                TargetKind::Domain => "domain",
                _ => "",
            };
            if !oathnet_field.is_empty()
                && let Ok(items) = crate::util::oathnet::search(
                    key,
                    crate::util::oathnet::paths::STEALER,
                    oathnet_field,
                    &target.value,
                    20,
                )
                .await
                && !items.is_empty()
            {
                let mut summary_parts: Vec<String> = Vec::new();
                for item in items.iter().take(5) {
                    if let Some(url) = crate::util::oathnet::val_str(item, "url_str") {
                        summary_parts.push(url);
                    }
                }
                entity.add_evidence(
                    Evidence::new(
                        "hudsonrock:oathnet",
                        format!("OathNet: {} additional stealer record(s)", items.len()),
                    )
                    .with_attr("oathnet_stealer_hits", items.len().to_string())
                    .with_opt_attr(
                        "compromised_urls",
                        if summary_parts.is_empty() {
                            None
                        } else {
                            Some(summary_parts.join(" | "))
                        },
                    ),
                );
            }
        }

        // OathNet IP geolocation for victim IPs discovered by HudsonRock
        if !ctx.cancel.is_cancelled() {
            let victim_ips: Vec<String> = data
                .stealers
                .iter()
                .filter_map(|s| s.ip.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .take(2)
                .collect();
            for ip in &victim_ips {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Ok(Some(info)) = crate::util::oathnet::osint_opt(
                    key,
                    crate::util::oathnet::paths::IP_INFO,
                    "ip",
                    ip,
                )
                .await
                {
                    let city = info.get("city").and_then(|v| v.as_str());
                    let country = info.get("country").and_then(|v| v.as_str());
                    if city.is_some() || country.is_some() {
                        let loc = [city, country]
                            .iter()
                            .flatten()
                            .copied()
                            .collect::<Vec<&str>>()
                            .join(", ");
                        entity.add_evidence(
                            Evidence::new(
                                "hudsonrock:oathnet",
                                format!("Victim IP {ip} geolocated: {loc}"),
                            )
                            .with_attr("source", "ip-info")
                            .with_attr("victim_ip", ip)
                            .with_opt_attr("city", city)
                            .with_opt_attr("country", country)
                            .with_opt_attr("isp", info.get("isp").and_then(|v| v.as_str())),
                        );
                    }
                }
            }
        }

        result.push(entity);
        Ok(result)
    }
}

fn compute_confidence(stealers: &[Stealer]) -> f64 {
    let now_secs = crate::core::entity::unix_now();
    let cutoff = now_secs.saturating_sub(FRESHNESS_WINDOW_DAYS * 86400);

    let has_recent = stealers.iter().any(|s| {
        s.date_compromised
            .as_deref()
            .and_then(parse_iso_epoch)
            .is_some_and(|ts| ts >= cutoff)
    });

    if has_recent {
        FRESH_CONFIDENCE
    } else {
        BASE_CONFIDENCE
    }
}

fn parse_iso_epoch(s: &str) -> Option<u64> {
    let date_part = s.split('T').next()?;
    let mut parts = date_part.split('-');
    let year: u64 = parts.next()?.parse().ok()?;
    let month: u64 = parts.next()?.parse().ok()?;
    let day: u64 = parts.next()?.parse().ok()?;
    if year < 2000 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days_approx = (year - 1970) * 365 + (month - 1) * 30 + day;
    Some(days_approx * 86400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_username_and_domain() {
        let m = HudsonRock;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "x")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn fresh_compromise_gets_higher_confidence() {
        let recent = Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some("2026-05-01T00:00:00Z".into()),
            date_uploaded: None,
            stealer_family: Some("Lumma".into()),
            ip: None,
            malware_path: None,
            credentials: vec![],
            extra: HashMap::new(),
        };
        assert!((compute_confidence(&[recent]) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn old_compromise_gets_base_confidence() {
        let old = Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some("2020-01-01T00:00:00Z".into()),
            date_uploaded: None,
            stealer_family: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
            extra: HashMap::new(),
        };
        assert!((compute_confidence(&[old]) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn parse_iso_epoch_works() {
        assert!(parse_iso_epoch("2025-06-15T12:00:00Z").is_some());
        assert!(parse_iso_epoch("2025-06-15").is_some());
        assert!(parse_iso_epoch("garbage").is_none());
        assert!(parse_iso_epoch("").is_none());
    }
}
