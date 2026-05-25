use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::oathnet::{self, paths, val_str, val_str_or, val_array_strings};

pub struct OathnetPro;

#[async_trait]
impl Module for OathnetPro {
    fn name(&self) -> &'static str {
        "oathnet_pro"
    }

    fn description(&self) -> &'static str {
        "Full-spectrum breach, stealer, OSINT & gaming-platform intelligence via OathNet API"
    }

    fn priority(&self) -> u8 {
        128
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Paid
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::Email
                | TargetKind::Username
                | TargetKind::Phone
                | TargetKind::IpAddress
                | TargetKind::Domain
                | TargetKind::FullName
                | TargetKind::ApiKey
                | TargetKind::Regex
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        45_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = oathnet::resolve_key(ctx.key_opt(oathnet::KEY_ENV));

        // Regex targets use dedicated regex search endpoint
        if target.kind == TargetKind::Regex {
            return self.process_regex(target, ctx, key).await;
        }

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());

        let field = match target.kind {
            TargetKind::Email => "email",
            TargetKind::Username => "username",
            TargetKind::Phone => "phone",
            TargetKind::IpAddress => "ip",
            TargetKind::Domain => "domain",
            TargetKind::FullName => "full_name",
            TargetKind::ApiKey => "q",
            _ => return Ok(result),
        };

        // Phase 1: breach search
        let items = oathnet::search(key, paths::BREACH, field, &target.value, 50).await?;

        if !items.is_empty() {
            let total = items.len();
            let top_dbs = oathnet::top_dbnames(&items, 5);

            let mut pw_count = 0u32;
            let mut hash_count = 0u32;
            for item in &items {
                if val_str(item, "password").is_some() {
                    pw_count += 1;
                }
                if val_str(item, "password_hash").is_some() {
                    hash_count += 1;
                }
            }

            let mut parent = target.to_entity(0.85, &ctx.scan_id);
            parent.tag(tags::BREACH);
            parent.tag("oathnet-pro");
            parent.tag_if(pw_count > 0, tags::PASSWORD_AT_RISK);
            parent.tag_if(hash_count > 0, "hash-exposed");

            let mut ev = Evidence::new(
                "oathnet_pro",
                format!("OathNet: {total} breach record(s) — {}", top_dbs.join(", ")),
            )
            .with_attr("hits", total.to_string())
            .with_attr("top_dbnames", top_dbs.join(", "));

            if pw_count > 0 {
                ev = ev.with_attr("passwords_found", pw_count.to_string());
            }
            if hash_count > 0 {
                ev = ev.with_attr("hashes_found", hash_count.to_string());
            }

            {
                let mut countries: Vec<String> = Vec::new();
                let mut names: Vec<String> = Vec::new();
                let mut genders: Vec<String> = Vec::new();
                let mut dobs: Vec<String> = Vec::new();
                for item in &items {
                    if let Some(c) = val_str(item, "country") {
                        if !countries.contains(&c) { countries.push(c); }
                    }
                    if let Some(n) = val_str(item, "full_name") {
                        if !names.contains(&n) { names.push(n); }
                    }
                    if let Some(g) = val_str(item, "gender") {
                        if !genders.contains(&g) { genders.push(g); }
                    }
                    if let Some(d) = val_str(item, "date_birth") {
                        if !dobs.contains(&d) { dobs.push(d); }
                    }
                }
                ev = ev
                    .with_opt_attr("countries", if countries.is_empty() { None } else { Some(countries.join(", ")) })
                    .with_opt_attr("full_names", if names.is_empty() { None } else { Some(names.join(", ")) })
                    .with_opt_attr("genders", if genders.is_empty() { None } else { Some(genders.join(", ")) })
                    .with_opt_attr("dates_of_birth", if dobs.is_empty() { None } else { Some(dobs.join(", ")) });
            }
            parent.add_evidence(ev);
            result.push(parent);

            for item in &items {
                extract_breach_entities(item, &target.value, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // Phase 2: stealer logs
        if !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) =
                oathnet::search(key, paths::STEALER, field, &target.value, 50).await
        {
            if !stealer_items.is_empty() {
                let stl_count = stealer_items.len();
                for item in &stealer_items {
                    extract_stealer_entities(item, &ctx.scan_id, &mut seen, &mut result);
                }

                // Aggregate stealer statistics
                let mut unique_urls: HashSet<String> = HashSet::new();
                let mut families: HashSet<String> = HashSet::new();
                for item in &stealer_items {
                    if let Some(url) = val_str(item, "url_str") {
                        unique_urls.insert(url);
                    }
                    if let Some(f) = val_str_or(item, &["stealer_family", "malware", "stealer"]) {
                        families.insert(f.to_lowercase());
                    }
                }

                // Tag the target entity with stealer-log for correlator AU-009
                for e in &mut result.entities {
                    if e.value.to_lowercase() == target.value.to_lowercase()
                        && !e.has_tag(tags::STEALER_LOG)
                    {
                        e.tag(tags::STEALER_LOG);
                        e.add_evidence(
                            Evidence::new(
                                "oathnet_pro",
                                format!("{stl_count} stealer log entries"),
                            )
                            .with_attr("stealer_hits", stl_count.to_string())
                            .with_attr("unique_compromised_services", unique_urls.len().to_string())
                            .with_opt_attr(
                                "stealer_families",
                                if families.is_empty() {
                                    None
                                } else {
                                    Some(families.into_iter().collect::<Vec<_>>().join(", "))
                                },
                            ),
                        );
                        break;
                    }
                }
            }
        }

        // Phase 3: ransomware victims (domain targets)
        let mut victim_hits = Vec::new();
        if target.kind == TargetKind::Domain && !ctx.cancel.is_cancelled() {
            if let Ok(victims) =
                oathnet::search(key, paths::VICTIMS, "domain", &target.value, 20).await
            {
                victim_hits = victims.clone();
                extract_victims(&victims, &target.value, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // Phase 3b: search victim domain employees in stealer/breach data
        if !ctx.cancel.is_cancelled() && !victim_hits.is_empty() {
            let common_prefixes = ["info", "admin", "contact", "support", "hr", "security"];
            for prefix in &common_prefixes {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                let employee_email = format!("{prefix}@{}", target.value);
                if let Ok(emp_items) = oathnet::search(
                    key,
                    paths::STEALER,
                    "email",
                    &employee_email,
                    5,
                )
                .await
                {
                    if !emp_items.is_empty()
                        && seen.insert(employee_email.to_lowercase())
                    {
                        let mut e =
                            Entity::new(EntityKind::Email, &employee_email, 0.55, &ctx.scan_id);
                        e.tag(tags::BREACH);
                        e.tag("oathnet-pro");
                        e.tag(tags::STEALER_LOG);
                        e.tag("employee-credential");
                        e.add_evidence(
                            Evidence::new(
                                "oathnet_pro",
                                format!(
                                    "{} stealer record(s) for employee {employee_email}",
                                    emp_items.len()
                                ),
                            )
                            .with_attr("stealer_hits", emp_items.len().to_string()),
                        );
                        result.push(e);
                    }
                }
            }
        }

        // Phase 4: Holehe email enumeration (email targets)
        if target.kind == TargetKind::Email && !ctx.cancel.is_cancelled() {
            if let Ok(holehe) =
                oathnet::osint(key, paths::HOLEHE, "email", &target.value).await
            {
                extract_holehe(holehe, &target.value, &ctx.scan_id, &mut result);
            }
        }

        // Phase 5: GHunt Google account recon (email targets)
        if target.kind == TargetKind::Email && !ctx.cancel.is_cancelled() {
            if let Ok(Some(ghunt)) =
                oathnet::osint_opt(key, paths::GHUNT, "email", &target.value).await
            {
                extract_ghunt(ghunt, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // Phase 6: gaming & social platform lookups (username targets)
        if target.kind == TargetKind::Username && !ctx.cancel.is_cancelled() {
            let username = &target.value;

            if !ctx.cancel.is_cancelled() {
                if let Ok(Some(data)) =
                    oathnet::osint_opt(key, paths::DISCORD_USER, "username", username).await
                {
                    extract_discord(data, &ctx.scan_id, &mut seen, &mut result);
                }
            }

            if !ctx.cancel.is_cancelled() {
                if let Ok(Some(data)) =
                    oathnet::osint_opt(key, paths::STEAM, "username", username).await
                {
                    extract_steam(data, &ctx.scan_id, &mut seen, &mut result);
                }
            }

            if !ctx.cancel.is_cancelled() {
                if let Ok(Some(data)) =
                    oathnet::osint_opt(key, paths::XBOX, "username", username).await
                {
                    extract_xbox(data, username, &ctx.scan_id, &mut result);
                }
            }

            if !ctx.cancel.is_cancelled() {
                if let Ok(Some(data)) =
                    oathnet::osint_opt(key, paths::ROBLOX, "username", username).await
                {
                    extract_roblox(data, &ctx.scan_id, &mut seen, &mut result);
                }
            }
        }

        // Phase 7: IP geolocation enrichment for discovered IPs
        if !ctx.cancel.is_cancelled() {
            let ips: Vec<String> = result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::IpAddress)
                .map(|e| e.value.clone())
                .collect();
            for ip in ips.iter().take(3) {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Ok(info) = oathnet::osint(key, paths::IP_INFO, "ip", ip).await {
                    extract_ip_info(info, ip, &ctx.scan_id, &mut result);
                }
            }
        }

        // Phase 8: credential exposure detection — check if the target
        // organisation's OSINT service API keys appear in stealer dumps.
        // Reports THAT keys are compromised (for rotation) without storing
        // actual key values.
        if target.kind == TargetKind::Domain && !ctx.cancel.is_cancelled() {
            let svc_domains = [
                ("shodan.io", "shodan"),
                ("virustotal.com", "virustotal"),
                ("securitytrails.com", "securitytrails"),
                ("dehashed.com", "dehashed"),
                ("intelx.io", "intelx"),
                ("leakix.net", "leakix"),
                ("ipqualityscore.com", "ipqs"),
                ("haveibeenpwned.com", "hibp"),
            ];
            for (svc_domain, svc_tag) in &svc_domains {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Ok(hits) =
                    oathnet::search(key, paths::STEALER, "domain", svc_domain, 3).await
                {
                    let relevant: Vec<&Value> = hits
                        .iter()
                        .filter(|item| {
                            val_str(item, "email")
                                .or_else(|| {
                                    item.get("email")
                                        .and_then(|v| v.as_array())
                                        .and_then(|a| a.first())
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string())
                                })
                                .map_or(false, |e| {
                                    e.to_lowercase()
                                        .ends_with(&format!("@{}", target.value.to_lowercase()))
                                })
                        })
                        .collect();
                    if !relevant.is_empty()
                        && seen.insert(format!("@svc-cred:{svc_tag}"))
                    {
                        let mut e = Entity::new(
                            EntityKind::ApiKey,
                            format!("{svc_tag}:credential@{}", target.value),
                            0.70,
                            &ctx.scan_id,
                        );
                        e.tag("oathnet-pro");
                        e.tag(tags::STEALER_LOG);
                        e.tag(tags::API_KEY_EXPOSED);
                        e.tag(tags::SERVICE_CREDENTIAL);
                        e.tag(format!("service:{svc_tag}"));
                        e.add_evidence(
                            Evidence::new(
                                "oathnet_pro",
                                format!(
                                    "Compromised {svc_tag} credential detected for {}",
                                    target.value
                                ),
                            )
                            .with_attr("service", *svc_tag)
                            .with_attr("source", "stealer")
                            .with_attr("hits", relevant.len().to_string()),
                        );
                        result.push(e);
                    }
                }
            }
        }

        // Phase 8b: OSINT service credential exposure scan
        if !ctx.cancel.is_cancelled() {
            let harvested = oathnet::harvest_credentials(key).await;
            for (service, username, password, url) in &harvested {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                let key_value = format!("{username}@{service}");
                if seen.insert(format!("@harvested:{}", key_value.to_lowercase())) {
                    let mut e = Entity::new(EntityKind::ApiKey, &key_value, 0.75, &ctx.scan_id);
                    e.tag("oathnet-pro");
                    e.tag(tags::STEALER_LOG);
                    e.tag(tags::API_KEY_EXPOSED);
                    e.tag(tags::SERVICE_CREDENTIAL);
                    e.tag(format!("service:{service}"));
                    e.add_evidence(
                        Evidence::new(
                            "oathnet_pro",
                            format!("Compromised {service} credential from stealer logs"),
                        )
                        .with_attr("service", service)
                        .with_attr("credential_username", username)
                        .with_attr("credential_password", password)
                        .with_attr("credential_url", url)
                        .with_attr("source", "stealer-harvest"),
                    );
                    result.push(e);

                    // Also create a Password entity for the credential password
                    if password.len() >= 4 && seen.insert(format!("@harvest-pw:{}", password.to_lowercase())) {
                        let mut pw_ent = Entity::new(EntityKind::Password, password, 0.65, &ctx.scan_id);
                        pw_ent.tag("oathnet-pro");
                        pw_ent.tag(tags::STEALER_LOG);
                        pw_ent.tag(tags::PASSWORD_AT_RISK);
                        pw_ent.tag(format!("service:{service}"));
                        pw_ent.add_evidence(
                            Evidence::new("oathnet_pro", format!("Stolen password for {service}"))
                                .with_attr("service", service)
                                .with_attr("source", "stealer-harvest"),
                        );
                        result.push(pw_ent);
                    }
                }
            }
        }

        // Synergy: tag victim domain with breach if employee credentials found
        if target.kind == TargetKind::Domain {
            let domain_lower = target.value.to_lowercase();
            let has_employee_creds = result.entities.iter().any(|e| {
                e.kind == EntityKind::Email
                    && e.has_tag("employee-credential")
                    && e.value.to_lowercase().ends_with(&format!("@{domain_lower}"))
            });
            if has_employee_creds {
                for e in &mut result.entities {
                    if e.kind == EntityKind::Domain
                        && e.value.to_lowercase() == domain_lower
                    {
                        e.tag(tags::BREACH);
                        break;
                    }
                }
            }
        }

        Ok(result)
    }
}

impl OathnetPro {
    async fn process_regex(
        &self,
        target: &Target,
        ctx: &ModuleContext,
        key: &str,
    ) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Search both breach and stealer databases with the regex
        let breach_items =
            oathnet::regex_search(key, paths::BREACH, &target.value, 50).await?;
        let stealer_items = if !ctx.cancel.is_cancelled() {
            oathnet::regex_search(key, paths::STEALER, &target.value, 50)
                .await
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let total = breach_items.len() + stealer_items.len();
        if total == 0 {
            return Ok(result);
        }

        // Parent entity represents the regex search itself
        let mut parent = Entity::new(EntityKind::Regex, &target.value, 0.90, &ctx.scan_id);
        parent.tag("oathnet-pro");
        parent.tag("regex-search");
        parent.add_evidence(
            Evidence::new(
                "oathnet_pro",
                format!(
                    "Regex '{}': {} breach + {} stealer matches",
                    target.value,
                    breach_items.len(),
                    stealer_items.len()
                ),
            )
            .with_attr("breach_hits", breach_items.len().to_string())
            .with_attr("stealer_hits", stealer_items.len().to_string())
            .with_attr("pattern", &target.value),
        );
        result.push(parent);

        // Extract entities from breach results
        for item in &breach_items {
            extract_breach_entities(item, &target.value, &ctx.scan_id, &mut seen, &mut result);
        }

        // Extract entities from stealer results
        for item in &stealer_items {
            extract_stealer_entities(item, &ctx.scan_id, &mut seen, &mut result);
        }

        // IP geolocation enrichment for discovered IPs
        if !ctx.cancel.is_cancelled() {
            let ips: Vec<String> = result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::IpAddress)
                .map(|e| e.value.clone())
                .collect();
            for ip in ips.iter().take(3) {
                if ctx.cancel.is_cancelled() {
                    break;
                }
                if let Ok(info) = oathnet::osint(key, paths::IP_INFO, "ip", ip).await {
                    extract_ip_info(info, ip, &ctx.scan_id, &mut result);
                }
            }
        }

        Ok(result)
    }
}

fn breach_evidence(item: &Value) -> Evidence {
    let db = val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string());
    let mut ev = Evidence::new("oathnet_pro", format!("Breach on {db}")).with_attr("dbname", &db);
    for (field, attr) in [
        ("country", "country"),
        ("gender", "gender"),
        ("date_birth", "date_of_birth"),
        ("created_at", "account_created"),
        ("language", "language"),
        ("account_id", "account_id"),
        ("ip", "ip"),
        ("city", "city"),
        ("state", "state"),
        ("postal_code", "postal_code"),
        ("bio", "bio"),
        ("location", "location"),
        ("discordid", "discord_id"),
        ("instagram", "instagram"),
        ("linkedin", "linkedin"),
        ("twitter", "twitter"),
        ("facebook", "facebook"),
        ("iban", "iban"),
        ("ssn", "ssn"),
        ("drivers_license", "drivers_license"),
        ("occupation", "occupation"),
        ("employer", "employer"),
        ("education", "education"),
        ("password", "password"),
        ("password_hash", "password_hash"),
        ("salt", "salt"),
    ] {
        ev = ev.with_opt_attr(attr, val_str(item, field));
    }
    if let Some(age) = item.get("age") {
        let s = if age.is_number() {
            age.to_string()
        } else {
            age.as_str().unwrap_or("").to_string()
        };
        if !s.is_empty() {
            ev = ev.with_attr("age", &s);
        }
    }
    ev = ev.with_opt_attr("followers", val_str(item, "followers"));
    ev = ev.with_attr("raw", item.to_string());
    ev
}

fn extract_breach_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let ev = breach_evidence(item);

    let target_lower = target_value.to_lowercase();
    let target_terms: Vec<&str> = target_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    let row_matches_target = |item: &Value| -> bool {
        for field in ["email", "username", "phone_number", "full_name"] {
            if let Some(v) = val_str(item, field) {
                let vl = v.to_lowercase();
                if vl == target_lower || target_terms.iter().any(|t| vl.contains(t)) {
                    return true;
                }
            }
        }
        false
    };
    let is_target_row = row_matches_target(item);
    let has_password = val_str(item, "password").is_some()
        || val_str(item, "password_hash").is_some();

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.70, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.tag_if(has_password, tags::PASSWORD_AT_RISK);
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            let mut e = Entity::new(EntityKind::Username, &uname, 0.65, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    let conf = |base: f64| -> f64 { if is_target_row { base } else { 0.25 } };

    if let Some(ph) = val_str_or(item, &["phone_number", "phone_national", "phone"])
        && ph.len() >= 7
        && seen.insert(ph.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Phone, &ph, conf(0.70), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag_if(!is_target_row, "candidate");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(n) = val_str_or(item, &["full_name", "display_name", "name"]) {
        let t = n.trim();
        if t.len() >= 4 && t.contains(' ') && seen.insert(t.to_lowercase()) {
            let mut e = Entity::new(EntityKind::Person, t, conf(0.70), scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.tag_if(!is_target_row, "candidate");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        let mut e = Entity::new(EntityKind::IpAddress, &ip, conf(0.60), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("geolocation-lead");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(pw) = val_str(item, "password")
        && pw.len() >= 4
        && seen.insert(format!("@pw:{}", pw.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Password, &pw, conf(0.65), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag(tags::PASSWORD_AT_RISK);
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(hash) = val_str(item, "password_hash")
        && hash.len() >= 16
        && seen.insert(format!("@hash:{}", hash.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Password, &hash, conf(0.60), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("hash");
        let algo = if hash.len() == 32 { "md5" }
            else if hash.len() == 40 { "sha1" }
            else if hash.len() == 64 { "sha256" }
            else if hash.starts_with("$2") { "bcrypt" }
            else if hash.starts_with("$argon2") { "argon2" }
            else { "unknown" };
        e.tag(format!("hash:{algo}"));
        e.add_evidence(ev.clone());
        result.push(e);
    }

    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        let mut e = Entity::new(EntityKind::Address, &country, conf(0.55), scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag_if(!is_target_row, "candidate");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    let street = val_str(item, "address_street");
    let city = val_str(item, "city");
    let state = val_str(item, "state");
    if city.is_some() || street.is_some() {
        let addr = [street.as_deref(), city.as_deref(), state.as_deref()]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<&str>>()
            .join(", ");
        if addr.len() >= 4 && seen.insert(format!("@addr:{}", addr.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Address, &addr, 0.65, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    // Social profile entities from breach data
    for (field, tag, prefix) in [
        ("discordid", "discord", "discord:"),
        ("instagram", "instagram", ""),
        ("linkedin", "linkedin", ""),
        ("twitter", "twitter", ""),
        ("facebook", "facebook", ""),
    ] {
        if let Some(handle) = val_str(item, field) {
            let value = if prefix.is_empty() {
                handle.clone()
            } else {
                format!("{prefix}{handle}")
            };
            let dedup_key = format!("@social:{field}:{}", handle.to_lowercase());
            if seen.insert(dedup_key) {
                let mut e = Entity::new(EntityKind::Username, &value, 0.55, scan_id);
                e.tag(tags::BREACH);
                e.tag("oathnet-pro");
                e.tag(tag);
                e.add_evidence(ev.clone());
                result.push(e);
            }
        }
    }

    // LinkedIn URL entity
    if let Some(li) = val_str(item, "linkedin") {
        let url = if li.starts_with("http") {
            li.clone()
        } else {
            format!("https://linkedin.com/in/{li}")
        };
        if seen.insert(format!("@url:{}", url.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Url, &url, 0.55, scan_id);
            e.tag(tags::BREACH);
            e.tag("oathnet-pro");
            e.tag("linkedin");
            e.tag("personal-site");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

fn extract_stealer_entities(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let ev = Evidence::new("oathnet_pro", "Stealer log entry")
        .with_attr("source", "stealer")
        .with_opt_attr("url", val_str(item, "url_str"))
        .with_opt_attr("log_id", val_str(item, "log_id"))
        .with_opt_attr("password", val_str(item, "password"))
        .with_opt_attr("username", val_str(item, "username"))
        .with_attr("raw", item.to_string());

    if let Some(emails) = item.get("email").and_then(|v| v.as_array()) {
        for email_val in emails {
            if let Some(email) = email_val.as_str() {
                let lower = email.to_lowercase();
                if lower.contains('@') && seen.insert(lower) {
                    let mut e = Entity::new(EntityKind::Email, email, 0.65, scan_id);
                    e.tag(tags::BREACH);
                    e.tag("oathnet-pro");
                    e.tag(tags::STEALER_LOG);
                    e.tag_if(val_str(item, "password").is_some(), tags::PASSWORD_AT_RISK);
                    e.add_evidence(ev.clone());
                    result.push(e);
                }
            }
        }
    }

    // Username entities from stealer logs
    if let Some(uname) = val_str(item, "username")
        && uname.len() >= 3
        && seen.insert(format!("@stealer-uname:{}", uname.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Username, &uname, 0.55, scan_id);
        e.tag("oathnet-pro");
        e.tag(tags::STEALER_LOG);
        e.tag("credential-exposed");
        e.add_evidence(ev.clone());
        result.push(e);
    }

    // Password/hash entities from stealer data — searchable pivoting artifacts
    if let Some(pw) = val_str(item, "password")
        && pw.len() >= 4
        && seen.insert(format!("@stealer-pw:{}", pw.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Password, &pw, 0.55, scan_id);
        e.tag("oathnet-pro");
        e.tag(tags::STEALER_LOG);
        e.tag(tags::PASSWORD_AT_RISK);
        e.add_evidence(ev.clone());
        result.push(e);
    }

    // IP entities from stealer victim machine
    if let Some(ip) = val_str_or(item, &["ip", "victim_ip"])
        && ip.len() >= 7
        && seen.insert(format!("@stealer-ip:{ip}"))
    {
        let mut e = Entity::new(EntityKind::IpAddress, &ip, 0.50, scan_id);
        e.tag("oathnet-pro");
        e.tag(tags::STEALER_LOG);
        e.tag("victim-machine");
        e.add_evidence(
            Evidence::new("oathnet_pro", format!("Victim machine IP from stealer log: {ip}"))
                .with_attr("source", "stealer"),
        );
        result.push(e);
    }

    if let Some(domains) = item.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(dom) = d.as_str()
                && dom.contains('.')
                && seen.insert(dom.to_lowercase())
            {
                let mut e = Entity::new(EntityKind::Domain, dom, 0.50, scan_id);
                e.tag("oathnet-pro");
                e.tag(tags::STEALER_LOG);
                e.add_evidence(
                    Evidence::new("oathnet_pro", format!("Stealer credential for {dom}"))
                        .with_attr("source", "stealer"),
                );
                result.push(e);
            }
        }
    }

    // Domain entities extracted from stealer URL
    if let Some(url_str) = val_str(item, "url_str")
        && url_str.starts_with("http")
    {
        if let Ok(parsed) = url::Url::parse(&url_str)
            && let Some(host) = parsed.host_str()
        {
            let domain = host.to_lowercase();
            if domain.contains('.') && seen.insert(format!("@stealer-domain:{domain}")) {
                let mut e = Entity::new(EntityKind::Domain, &domain, 0.50, scan_id);
                e.tag("oathnet-pro");
                e.tag(tags::STEALER_LOG);
                e.tag("compromised-service");
                e.add_evidence(
                    Evidence::new("oathnet_pro", format!("Credentials stolen from {domain}"))
                        .with_attr("source", "stealer")
                        .with_attr("stolen_url", &url_str),
                );
                result.push(e);
            }
        }
    }

    // URL entities from stealer logs
    if let Some(url_str) = val_str(item, "url_str")
        && url_str.starts_with("http")
        && seen.insert(format!("@stealer-url:{}", url_str.to_lowercase()))
    {
        let mut e = Entity::new(EntityKind::Url, &url_str, 0.55, scan_id);
        e.tag("oathnet-pro");
        e.tag(tags::STEALER_LOG);
        e.tag("compromised-service");
        e.add_evidence(
            Evidence::new("oathnet_pro", format!("Stolen credential URL: {url_str}"))
                .with_attr("source", "stealer"),
        );
        result.push(e);
    }

    if let Some(uname) = val_str(item, "username")
        && let Some(url_str) = val_str(item, "url_str")
    {
        let cred_val = format!("{uname}@{url_str}");
        if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id);
            e.tag("oathnet-pro");
            e.tag(tags::STEALER_LOG);
            e.add_evidence(ev);
            result.push(e);
        }
    }

    // Stealer family tagging
    if let Some(family) = val_str_or(item, &["stealer_family", "malware", "stealer"]) {
        if let Some(last_email) = result.entities.iter_mut().rev()
            .find(|e| e.kind == EntityKind::Email && e.has_tag(tags::STEALER_LOG))
        {
            last_email.tag(&format!("stealer:{}", family.to_lowercase()));
        }
    }
}

fn extract_victims(
    items: &[Value],
    domain: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    if items.is_empty() {
        return;
    }

    let mut groups: Vec<String> = Vec::new();
    let mut dates: Vec<String> = Vec::new();
    for item in items {
        if let Some(g) = val_str(item, "group_name") {
            if !groups.contains(&g) {
                groups.push(g);
            }
        }
        if let Some(d) = val_str_or(item, &["published_date", "discovered_date", "date"]) {
            if !dates.contains(&d) {
                dates.push(d);
            }
        }
    }

    let mut countries: Vec<String> = Vec::new();
    let mut sectors: Vec<String> = Vec::new();
    let mut descriptions: Vec<String> = Vec::new();
    for item in items {
        if let Some(c) = val_str(item, "country") {
            if !countries.contains(&c) { countries.push(c); }
        }
        if let Some(s) = val_str_or(item, &["sector", "industry", "category"]) {
            if !sectors.contains(&s) { sectors.push(s); }
        }
        if let Some(d) = val_str_or(item, &["description", "notes", "details"]) {
            if !descriptions.contains(&d) { descriptions.push(d); }
        }
    }

    let summary = format!(
        "Ransomware victim: {} hit(s) by {}",
        items.len(),
        if groups.is_empty() {
            "unknown group(s)".to_string()
        } else {
            groups.join(", ")
        }
    );

    let mut e = Entity::new(EntityKind::Domain, domain, 0.90, scan_id);
    e.tag("oathnet-pro");
    e.tag("ransomware-victim");
    e.tag("threat-intel");
    e.add_evidence(
        Evidence::new("oathnet_pro", &summary)
            .with_attr("victim_count", items.len().to_string())
            .with_opt_attr(
                "ransomware_groups",
                if groups.is_empty() {
                    None
                } else {
                    Some(groups.join(", "))
                },
            )
            .with_opt_attr(
                "dates",
                if dates.is_empty() {
                    None
                } else {
                    Some(dates.join(", "))
                },
            )
            .with_opt_attr("countries", if countries.is_empty() { None } else { Some(countries.join(", ")) })
            .with_opt_attr("sectors", if sectors.is_empty() { None } else { Some(sectors.join(", ")) })
            .with_opt_attr("descriptions", if descriptions.is_empty() { None } else { Some(descriptions.join(" | ")) })
            .with_attr("raw_records", serde_json::to_string(items).unwrap_or_default()),
    );
    result.push(e);

    // Emit Organisation entities for ransomware groups
    for group in &groups {
        let key = format!("@ransomware-group:{}", group.to_lowercase());
        if seen.insert(key) {
            let mut g_entity =
                Entity::new(EntityKind::Organisation, group, 0.80, scan_id);
            g_entity.tag("oathnet-pro");
            g_entity.tag("ransomware-group");
            g_entity.tag("threat-intel");
            g_entity.add_evidence(
                Evidence::new("oathnet_pro", format!("Ransomware group: {group}"))
                    .with_attr("victim_domain", domain),
            );
            result.push(g_entity);
        }
    }
}

fn extract_holehe(data: Value, email: &str, scan_id: &str, result: &mut ModuleResult) {
    let raw = data.to_string();
    let domains = match data.get("domains").and_then(|v| v.as_array()) {
        Some(d) if !d.is_empty() => d,
        _ => return,
    };
    let domains_str: Vec<&str> = domains.iter().filter_map(|v| v.as_str()).collect();
    let mut parent = Entity::new(EntityKind::Email, email, 0.80, scan_id);
    parent.tag("oathnet-pro");
    parent.tag("holehe");
    parent.tag_if(domains_str.len() >= 5, tags::HIGH_EXPOSURE);
    parent.add_evidence(
        Evidence::new(
            "oathnet_pro",
            format!("Holehe: email registered on {} service(s)", domains_str.len()),
        )
        .with_attr("holehe_count", domains_str.len().to_string())
        .with_attr("holehe_domains", domains_str.join(", "))
        .with_attr("raw", &raw),
    );
    result.push(parent);
}

fn extract_ghunt(data: Value, scan_id: &str, seen: &mut HashSet<String>, result: &mut ModuleResult) {
    let raw = data.to_string();
    let name = val_str_or(&data, &["name", "display_name", "fullName"]);
    let profile_pic = val_str(&data, "profile_pic");
    let last_edit = val_str_or(&data, &["last_edit", "lastUpdated"]);
    let gaia_id = val_str_or(&data, &["gaia_id", "gaiaId", "id"]);

    let mut ev = Evidence::new("oathnet_pro", "GHunt Google account reconnaissance")
        .with_attr("source", "ghunt")
        .with_opt_attr("name", name.clone())
        .with_opt_attr("profile_pic", profile_pic)
        .with_opt_attr("last_edit", last_edit)
        .with_opt_attr("gaia_id", gaia_id.clone())
        .with_attr("raw", &raw);

    // Extract Google Maps reviews
    let reviews = val_array_strings(&data, "reviews");
    if !reviews.is_empty() {
        ev = ev.with_attr("maps_reviews", reviews.len().to_string());
    }

    // Extract YouTube channel
    if let Some(yt) = val_str_or(&data, &["youtube_channel", "youtube"]) {
        ev = ev.with_attr("youtube", &yt);
        if yt.starts_with("http") && seen.insert(format!("@url:{}", yt.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Url, &yt, 0.70, scan_id);
            e.tag("oathnet-pro");
            e.tag("ghunt");
            e.tag("youtube");
            e.tag("personal-site");
            e.add_evidence(
                Evidence::new("oathnet_pro", "YouTube channel from GHunt")
                    .with_attr("source", "ghunt"),
            );
            result.push(e);
        }
    }

    // Person entity from GHunt name
    if let Some(ref n) = name {
        let t = n.trim();
        if t.len() >= 3 && t.contains(' ') && seen.insert(format!("@ghunt-name:{}", t.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Person, t, 0.80, scan_id);
            e.tag("oathnet-pro");
            e.tag("ghunt");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    // Attach GHunt evidence to existing email entities
    for e in &mut result.entities {
        if e.kind == EntityKind::Email && !e.has_tag("ghunt") {
            e.tag("ghunt");
            e.add_evidence(ev.clone());
            break;
        }
    }
}

fn extract_discord(data: Value, scan_id: &str, seen: &mut HashSet<String>, result: &mut ModuleResult) {
    let raw = data.to_string();
    let discord_id = val_str_or(&data, &["id", "user_id", "discord_id"]);
    let username = val_str_or(&data, &["username", "global_name"]);
    let avatar = val_str(&data, "avatar");
    let discriminator = val_str(&data, "discriminator");
    let created_at = val_str_or(&data, &["created_at", "creation_date"]);
    let badges = val_array_strings(&data, "badges");
    let banner_color = val_str(&data, "banner_color");

    if discord_id.is_none() && username.is_none() {
        return;
    }

    let display = username
        .as_deref()
        .or(discord_id.as_deref())
        .unwrap_or("unknown")
        .to_string();
    let dedup = format!("@discord-user:{}", display.to_lowercase());
    if !seen.insert(dedup) {
        return;
    }

    let mut ev = Evidence::new("oathnet_pro", format!("Discord user: {display}"))
        .with_attr("source", "discord")
        .with_opt_attr("discord_id", discord_id.clone())
        .with_opt_attr("username", username)
        .with_opt_attr("avatar", avatar)
        .with_opt_attr("discriminator", discriminator)
        .with_opt_attr("created_at", created_at)
        .with_opt_attr("banner_color", banner_color)
        .with_attr("raw", &raw);

    if !badges.is_empty() {
        ev = ev.with_attr("badges", badges.join(", "));
    }

    let value = if let Some(ref id) = discord_id {
        format!("discord:{id}")
    } else {
        display.to_string()
    };

    let mut e = Entity::new(EntityKind::Username, &value, 0.75, scan_id);
    e.tag("oathnet-pro");
    e.tag("discord");
    e.add_evidence(ev);
    result.push(e);
}

fn extract_steam(data: Value, scan_id: &str, seen: &mut HashSet<String>, result: &mut ModuleResult) {
    let raw = data.to_string();
    let steam_id = val_str_or(&data, &["steamid", "steam_id", "id"]);
    let persona = val_str_or(&data, &["personaname", "persona_name", "username"]);
    let real_name = val_str_or(&data, &["realname", "real_name"]);
    let profile_url = val_str_or(&data, &["profileurl", "profile_url"]);
    let loc_country = val_str_or(&data, &["loccountrycode", "country"]);
    let loc_state = val_str_or(&data, &["locstatecode", "state"]);
    let created = val_str_or(&data, &["timecreated", "created_at"]);

    if steam_id.is_none() && persona.is_none() {
        return;
    }

    let display = persona
        .as_deref()
        .or(steam_id.as_deref())
        .unwrap_or("unknown")
        .to_string();
    let dedup = format!("@steam:{}", display.to_lowercase());
    if !seen.insert(dedup) {
        return;
    }

    let ev = Evidence::new("oathnet_pro", format!("Steam profile: {display}"))
        .with_attr("source", "steam")
        .with_opt_attr("steam_id", steam_id)
        .with_opt_attr("persona_name", persona)
        .with_opt_attr("real_name", real_name.clone())
        .with_opt_attr("profile_url", profile_url.clone())
        .with_opt_attr("country", loc_country.clone())
        .with_opt_attr("state", loc_state)
        .with_opt_attr("created_at", created)
        .with_attr("raw", &raw);

    let mut e = Entity::new(EntityKind::Username, &display, 0.70, scan_id);
    e.tag("oathnet-pro");
    e.tag("steam");
    e.add_evidence(ev.clone());
    result.push(e);

    if let Some(ref n) = real_name {
        let t = n.trim();
        if t.len() >= 3 && t.contains(' ') && seen.insert(format!("@steam-name:{}", t.to_lowercase())) {
            let mut pe = Entity::new(EntityKind::Person, t, 0.60, scan_id);
            pe.tag("oathnet-pro");
            pe.tag("steam");
            pe.add_evidence(ev.clone());
            result.push(pe);
        }
    }

    if let Some(ref url) = profile_url {
        if url.starts_with("http") && seen.insert(format!("@url:{}", url.to_lowercase())) {
            let mut ue = Entity::new(EntityKind::Url, url, 0.70, scan_id);
            ue.tag("oathnet-pro");
            ue.tag("steam");
            ue.tag("personal-site");
            ue.add_evidence(ev.clone());
            result.push(ue);
        }
    }

    if let Some(ref country) = loc_country {
        if seen.insert(format!("@steam-country:{}", country.to_lowercase())) {
            let mut ae = Entity::new(EntityKind::Address, country, 0.50, scan_id);
            ae.tag("oathnet-pro");
            ae.tag("steam");
            ae.add_evidence(ev);
            result.push(ae);
        }
    }
}

fn extract_xbox(data: Value, username: &str, scan_id: &str, result: &mut ModuleResult) {
    let raw = data.to_string();
    let gamertag = val_str_or(&data, &["gamertag", "Gamertag", "username"]);
    let gamerscore = val_str_or(&data, &["gamerscore", "Gamerscore"]);
    let account_tier = val_str_or(&data, &["accountTier", "account_tier"]);
    let bio = val_str(&data, "bio");

    let display = gamertag.as_deref().unwrap_or(username).to_string();

    let ev = Evidence::new("oathnet_pro", format!("Xbox profile: {display}"))
        .with_attr("source", "xbox")
        .with_opt_attr("gamertag", gamertag)
        .with_opt_attr("gamerscore", gamerscore)
        .with_opt_attr("account_tier", account_tier)
        .with_opt_attr("bio", bio)
        .with_attr("raw", &raw);

    for e in &mut result.entities {
        if e.kind == EntityKind::Username
            && e.value.to_lowercase() == username.to_lowercase()
            && !e.has_tag("xbox")
        {
            e.tag("xbox");
            e.add_evidence(ev.clone());
            return;
        }
    }

    let mut e = Entity::new(EntityKind::Username, &display, 0.65, scan_id);
    e.tag("oathnet-pro");
    e.tag("xbox");
    e.add_evidence(ev);
    result.push(e);
}

fn extract_roblox(data: Value, scan_id: &str, seen: &mut HashSet<String>, result: &mut ModuleResult) {
    let raw = data.to_string();
    let roblox_id = val_str_or(&data, &["id", "user_id"]);
    let display_name = val_str_or(&data, &["displayName", "display_name", "name"]);
    let username = val_str_or(&data, &["name", "username"]);
    let created = val_str_or(&data, &["created", "created_at"]);
    let description = val_str(&data, "description");
    let is_banned = oathnet::val_bool(&data, "isBanned");

    let display = display_name
        .as_deref()
        .or(username.as_deref())
        .or(roblox_id.as_deref())
        .unwrap_or("unknown")
        .to_string();

    let dedup = format!("@roblox:{}", display.to_lowercase());
    if !seen.insert(dedup) {
        return;
    }

    let mut ev = Evidence::new("oathnet_pro", format!("Roblox profile: {display}"))
        .with_attr("source", "roblox")
        .with_opt_attr("roblox_id", roblox_id)
        .with_opt_attr("display_name", display_name)
        .with_opt_attr("username", username)
        .with_opt_attr("created", created)
        .with_opt_attr("description", description)
        .with_attr("raw", &raw);

    if is_banned == Some(true) {
        ev = ev.with_attr("banned", "true");
    }

    let mut e = Entity::new(EntityKind::Username, &display, 0.65, scan_id);
    e.tag("oathnet-pro");
    e.tag("roblox");
    e.tag_if(is_banned == Some(true), "banned");
    e.add_evidence(ev);
    result.push(e);
}

fn extract_ip_info(data: Value, ip: &str, scan_id: &str, result: &mut ModuleResult) {
    let raw = data.to_string();
    let mut ev =
        Evidence::new("oathnet_pro", format!("IP info for {ip}")).with_attr("source", "ip-info").with_attr("raw", &raw);
    for (field, attr) in [
        ("city", "city"),
        ("regionName", "region"),
        ("region", "region_code"),
        ("country", "country"),
        ("countryCode", "country_code"),
        ("zip", "postal_code"),
        ("isp", "isp"),
        ("org", "org"),
        ("as", "asn"),
        ("timezone", "timezone"),
        ("reverse", "reverse_dns"),
        ("district", "district"),
        ("continent", "continent"),
    ] {
        if let Some(v) = data.get(field).and_then(|v| v.as_str()) {
            ev = ev.with_attr(attr, v);
        }
    }

    let lat = data.get("lat").and_then(|v| v.as_f64());
    let lon = data.get("lon").and_then(|v| v.as_f64());
    if let (Some(lat), Some(lon)) = (lat, lon) {
        if lat.is_finite()
            && lon.is_finite()
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon)
        {
            let coords = format!("{lat},{lon}");
            let mut e = Entity::new(EntityKind::Coordinates, &coords, 0.65, scan_id);
            e.tag("oathnet-pro");
            e.tag("geoint");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }

    let city = data.get("city").and_then(|v| v.as_str());
    let region = data
        .get("regionName")
        .or_else(|| data.get("region"))
        .and_then(|v| v.as_str());
    let country = data.get("country").and_then(|v| v.as_str());
    if city.is_some() {
        let addr = [city, region, country]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<&str>>()
            .join(", ");
        let mut e = Entity::new(EntityKind::Address, &addr, 0.60, scan_id);
        e.tag("oathnet-pro");
        e.tag("geoint");
        e.add_evidence(ev);
        result.push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_identity_infra_and_fullname() {
        let m = OathnetPro;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::FullName,
            TargetKind::ApiKey,
            TargetKind::Regex,
        ] {
            assert!(m.accepts(&Target::new(k, "x")), "should accept {k:?}");
        }
        assert!(!m.accepts(&Target::new(TargetKind::Asn, "AS1234")));
    }

    #[test]
    fn cost_is_paid() {
        assert!(matches!(OathnetPro.cost(), ModuleCost::Paid));
    }

    #[test]
    fn timeout_exceeds_default() {
        assert!(OathnetPro.max_timeout_ms() > crate::MODULE_TIMEOUT_MS);
    }

    #[test]
    fn val_str_or_fallback() {
        let item = serde_json::json!({"full_name": "Jerome Despal"});
        assert_eq!(
            val_str_or(&item, &["display_name", "full_name"]).as_deref(),
            Some("Jerome Despal")
        );
    }

    #[test]
    fn breach_evidence_extracts_social_fields() {
        let item = serde_json::json!({
            "dbname": "test_db",
            "twitter": "alice_tw",
            "linkedin": "alice-smith",
            "facebook": "alice.smith.42",
            "password": "hunter2",
            "password_hash": "5f4dcc3b..."
        });
        let ev = breach_evidence(&item);
        assert!(ev.attributes.contains_key("twitter"));
        assert!(ev.attributes.contains_key("linkedin"));
        assert!(ev.attributes.contains_key("facebook"));
        assert!(ev.attributes.contains_key("password"));
        assert!(ev.attributes.contains_key("password_hash"));
    }

    #[test]
    fn extract_victims_creates_threat_intel_entities() {
        let items = vec![
            serde_json::json!({
                "group_name": "lockbit",
                "published_date": "2024-01-15"
            }),
            serde_json::json!({
                "group_name": "alphv",
                "published_date": "2024-03-20"
            }),
        ];
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_victims(&items, "example.com", "scan-1", &mut seen, &mut result);
        assert!(!result.is_empty());
        let domain_ent = result.entities.iter().find(|e| e.kind == EntityKind::Domain);
        assert!(domain_ent.is_some());
        let de = domain_ent.unwrap();
        assert!(de.has_tag("ransomware-victim"));
        assert!(de.has_tag("threat-intel"));
        let orgs: Vec<_> = result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .collect();
        assert_eq!(orgs.len(), 2);
    }

    #[test]
    fn password_at_risk_tagged_on_breach() {
        let item = serde_json::json!({
            "email": "test@example.com",
            "password": "hunter2",
            "dbname": "test"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(&item, "other@x.com", "scan-1", &mut seen, &mut result);
        let email_ent = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email);
        assert!(email_ent.is_some());
        assert!(email_ent.unwrap().has_tag("password-at-risk"));
    }

    #[test]
    fn stealer_log_tag_applied() {
        let item = serde_json::json!({
            "email": ["leaked@example.com"],
            "username": "user1",
            "url_str": "https://service.com/login",
            "password": "pass123"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan-1", &mut seen, &mut result);
        let email_ent = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email);
        assert!(email_ent.is_some());
        assert!(email_ent.unwrap().has_tag("stealer-log"));
        let url_ent = result.entities.iter().find(|e| e.kind == EntityKind::Url);
        assert!(url_ent.is_some());
    }
}
