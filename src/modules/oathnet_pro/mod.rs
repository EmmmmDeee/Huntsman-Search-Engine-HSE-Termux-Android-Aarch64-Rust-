//! OathNet Pro — full-spectrum breach, stealer, OSINT, and intelligence API.
//!
//! Uses the shared `util::oathnet` client for API calls. This module
//! orchestrates the search→extract→enrich pipeline and produces entities.

use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::oathnet::{self, paths, val_str, val_str_or};

pub mod key_harvest;
pub use key_harvest::store_api_credential_from_item;

/// Re-export the budget reset so `core/engine.rs` can call it without
/// importing `util::oathnet` directly (which violates the architecture rule).
pub fn reset_budget() {
    crate::util::oathnet::reset_budget();
}
use key_harvest::{extract_api_keys_from_item, store_api_credential};

const SRC: &str = "oathnet_pro";

/// Confidence ceiling for an entity sourced from a breach row that does NOT
/// match the scan target's identity. A broad search (especially a `full_name`)
/// returns rows for many different people; those rows are preserved as
/// quarantined `candidate` leads at this strength rather than discarded, but
/// must never reach the full-confidence, correlated, default-view tier.
const CANDIDATE_CONF: f64 = 0.25;

pub struct OathnetPro;

#[async_trait]
impl Module for OathnetPro {
    fn name(&self) -> &'static str {
        "oathnet_pro"
    }

    fn description(&self) -> &'static str {
        "Full-spectrum breach, stealer & OSINT intelligence via OathNet API"
    }

    fn priority(&self) -> u8 {
        127
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
                | TargetKind::FullName
                | TargetKind::IpAddress
                | TargetKind::Domain
        )
    }

    fn max_timeout_ms(&self) -> u64 {
        30_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Email,
            EntityKind::Username,
            EntityKind::Phone,
            EntityKind::Person,
            EntityKind::IpAddress,
            EntityKind::Address,
            EntityKind::Url,
            EntityKind::Domain,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = oathnet::resolve_key(ctx.key_opt(oathnet::KEY_ENV));
        // Origin fingerprint of the exact key in use — stamped on every entity so
        // each finding declares which API key (and provider) returned it.
        let key_fp = oathnet::key_fingerprint(key);

        let mut result = ModuleResult::new();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(target.value.to_lowercase());

        // Pre-flight skips for inputs that empirically waste OathNet
        // lookups. Catching these BEFORE the cache + budget check means
        // a junk input never burns a query nor pollutes the cache.
        let v = target.value.trim();
        let field = match target.kind {
            TargetKind::Email => {
                // Skip emails on test/example/invalid TLDs — never in
                // real breach corpora.
                if let Some((_, host)) = v.split_once('@')
                    && is_local_domain(host)
                {
                    return Ok(result);
                }
                "email"
            }
            TargetKind::Username => {
                // Usernames under 4 chars or all-digits or "anonymous"-
                // style placeholders are noise. The breach corpora
                // dedupe so well on these that hits are vanishingly rare.
                if v.len() < 4
                    || v.chars().all(|c| c.is_ascii_digit())
                    || is_placeholder_username(v)
                {
                    return Ok(result);
                }
                "username"
            }
            TargetKind::Phone => {
                // Phone < 6 digits or all-zeros = placeholder.
                let digits = v.chars().filter(|c| c.is_ascii_digit()).count();
                if digits < 6 || v.chars().filter(|c| c.is_ascii_digit()).all(|c| c == '0') {
                    return Ok(result);
                }
                "phone"
            }
            TargetKind::FullName => {
                // Single-word "names" are noise. Real full-name breach
                // matches require at least one space.
                if !v.contains(' ') || v.len() < 5 {
                    return Ok(result);
                }
                "q"
            }
            TargetKind::IpAddress => {
                if is_private_ip(v) {
                    return Ok(result);
                }
                "ip"
            }
            TargetKind::Domain => {
                if is_social_platform(v) || is_local_domain(v) {
                    return Ok(result);
                }
                "domain"
            }
            _ => return Ok(result),
        };

        // Initialise a search session so breach + stealer queries on the
        // same target consume only ONE OathNet lookup instead of two.
        // Non-fatal: if init fails, queries still work at higher quota cost.
        let _ = oathnet::init_session(key, &target.value).await;

        // ── Query 1: Breach search ──────────────────────────────────────
        // Highest value endpoint: single query returns emails, usernames,
        // phones, names, IPs, addresses, passwords, geo, DOB, social
        // handles. The API charges per QUERY not per record — larger
        // page_size is free ROI. Docs default is 100, max is 1000.
        // Use 100 for identity targets, 50 for noisy infra targets
        // (non-matching rows still produce candidate entities).
        let page_size: u32 = match target.kind {
            TargetKind::Email | TargetKind::Username => 100,
            TargetKind::Phone | TargetKind::FullName => 100,
            TargetKind::IpAddress | TargetKind::Domain => 50,
            _ => 50,
        };
        let items = oathnet::search(key, paths::BREACH, field, &target.value, page_size).await?;
        if items.is_empty() {
            return Ok(result);
        }

        let total = items.len();
        let top_dbs = oathnet::top_dbnames(&items, 5);

        let mut parent = target.to_entity(0.85, &ctx.scan_id);
        parent.tag(tags::BREACH);
        parent.tag("oathnet-pro");
        let mut ev = Evidence::new(
            SRC,
            format!("OathNet: {total} breach record(s) — {}", top_dbs.join(", ")),
        )
        .with_attr("hits", total.to_string())
        .with_attr("top_dbnames", top_dbs.join(", "));

        let mut countries: Vec<String> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        for item in &items {
            if let Some(c) = val_str(item, "country")
                && !countries.contains(&c)
            {
                countries.push(c);
            }
            if let Some(n) = val_str(item, "full_name")
                && !names.contains(&n)
            {
                names.push(n);
            }
            if let Some(g) = val_str(item, "gender") {
                ev = ev.with_attr("gender", &g);
            }
            if let Some(dob) = val_str(item, "date_birth") {
                ev = ev.with_attr("date_of_birth", &dob);
            }
        }
        if !countries.is_empty() {
            ev = ev.with_attr("countries", countries.join(", "));
        }
        if !names.is_empty() {
            ev = ev.with_attr("names", names.join("; "));
        }
        parent.add_evidence(ev);
        result.push(parent);

        for item in &items {
            extract_breach_entities(
                item,
                &target.value,
                &ctx.scan_id,
                &key_fp,
                &mut seen,
                &mut result,
            );
            store_api_credential(item);
            extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
        }

        // ── Query 2: Stealer search (Email/Username only) ───────────────
        // Stealer logs are indexed by login credentials (username/email +
        // password + URL). Only Email and Username targets have a direct
        // index match. Phone/FullName use free-text "q" which is noisy and
        // rarely productive. IP/Domain are already breach-only above.
        if matches!(target.kind, TargetKind::Email | TargetKind::Username)
            && !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) =
                oathnet::search(key, paths::STEALER, field, &target.value, 100).await
        {
            for item in &stealer_items {
                extract_stealer_entities(item, &ctx.scan_id, &key_fp, &mut seen, &mut result);
                store_api_credential(item);
                extract_api_keys_from_item(item, &ctx.scan_id, &mut seen, &mut result);
            }
        }

        // Holehe, Discord, GHunt, IP info, Steam, Xbox, Roblox, and
        // victims endpoints are intentionally not called. Breach is the
        // highest-yield endpoint per query; stealer adds URL-specific
        // credentials for indexed targets. Platform presence (holehe's
        // output) is discovered for free by search_engines and
        // username_search. Downstream free modules (ip_geo, dns_intel,
        // geocode, etc.) handle expansion from extracted entities.

        Ok(result)
    }
}

// Pre-flight validators (`is_private_ip`, `is_placeholder_username`,
// `is_local_domain`) live in `crate::util::preflight` — both
// oathnet_pro and see_know share the policy so a target rejected
// by one provider is rejected by the other.
use crate::util::preflight::{is_local_domain, is_placeholder_username, is_private_ip};

fn is_social_platform(domain: &str) -> bool {
    const PLATFORMS: &[&str] = &[
        "peekyou.com",
        "spokeo.com",
        "nuwber.com",
        "pipl.com",
        "facebook.com",
        "instagram.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "pinterest.com",
        "tiktok.com",
        "reddit.com",
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "youtube.com",
        "twitch.tv",
        "steamcommunity.com",
        "mastodon.social",
        "bsky.app",
        "threads.net",
        "tumblr.com",
        "snapchat.com",
        "telegram.org",
        "discord.com",
        "soundcloud.com",
        "spotify.com",
        "whatsapp.com",
        "signal.org",
        "vk.com",
        "whitepages.com",
        "whitepages.com.au",
        "locatefamily.com",
        "truecaller.com",
        "cloudflare.com",
        "google.com",
        "microsoft.com",
        "amazon.com",
        "apple.com",
    ];
    let lower = domain.to_lowercase();
    PLATFORMS
        .iter()
        .any(|p| crate::util::domains::is_or_subdomain_of(&lower, p))
}

// ─── Entity extraction ─────────────────────────────────────────────────────

fn breach_evidence(item: &Value) -> Evidence {
    let db = val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string());
    let mut ev = Evidence::new(SRC, format!("Breach on {db}")).with_attr("dbname", &db);
    for (field, attr) in [
        ("country", "country"),
        ("gender", "gender"),
        ("date_birth", "date_of_birth"),
        ("created_at", "account_created"),
        ("language", "language"),
        ("account_id", "account_id"),
        ("password", "password"),
        ("password_hash", "password_hash"),
        ("salt", "salt"),
        ("ip", "ip"),
        ("city", "city"),
        ("state", "state"),
        ("postal_code", "postal_code"),
        ("bio", "bio"),
        ("location", "location"),
        ("discordid", "discord_id"),
        ("instagram", "instagram"),
        ("linkedin", "linkedin"),
        ("iban", "iban"),
    ] {
        if let Some(v) = val_str(item, field) {
            ev = ev.with_attr(attr, &v);
        }
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
    if let Some(f) = val_str(item, "followers") {
        ev = ev.with_attr("followers", &f);
    }
    ev
}

/// Apply oathnet_pro's standard breach tags (`breach`, `oathnet-pro`, plus any
/// record-specific `extra_tags` in order) and a cloned evidence record to `e`,
/// then push it. Centralises the tag+evidence+push tail shared by every
/// breach-derived entity kind; `extra_tags` preserves the exact serialised tag
/// order (e.g. `candidate`, `geolocation-lead`, `discord`).
fn push_oathnet_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
    is_target_row: bool,
) {
    e.tag(tags::BREACH);
    e.tag("oathnet-pro");
    for t in extra_tags {
        e.tag(*t);
    }
    // Quarantine policy, enforced in ONE place: a row that doesn't match the
    // target identity yields CANDIDATE-strength, `candidate`-tagged entities.
    // Demotion happens here (not at each call site) so EVERY breach-derived
    // kind — email, username, domain, social handle — is gated uniformly. The
    // prior code gated only phone/person/ip, letting a name search emit
    // hundreds of strangers' emails/domains at full 0.70 confidence.
    if !is_target_row {
        e.confidence = e.confidence.min(CANDIDATE_CONF);
        e.tag(tags::CANDIDATE);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

fn extract_breach_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    // Provenance: which provider + which exact API key returned this record
    // (the source database/website is already on the evidence per row).
    let ev = breach_evidence(item)
        .with_attr("provider", "oathnet.org")
        .with_attr("api_key_origin", key_fp);

    // Decide whether this breach row actually belongs to the target. Breach
    // databases hold millions of records and a broad search (especially a
    // `full_name`) returns rows for many different people. A non-matching row
    // is NOT discarded — `push_oathnet_entity` demotes it to a quarantined
    // `candidate` (out of the default view and the correlator) so genuine
    // leads survive without flooding the result with strangers.
    let target_lower = target_value.to_lowercase();
    let target_terms: Vec<&str> = target_lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .collect();
    // Multi-term targets (a full name like "Jordan Avery", or an email)
    // must match EVERY significant term within a single field — not just one —
    // so a row for "Jordan Parker" no longer counts as the target on the
    // shared first name (the dominant junk source on name scans). Single-term
    // targets keep substring-contains matching.
    let require_all_terms = target_terms.len() >= 2;
    let row_matches_target = |item: &Value| -> bool {
        for field in ["email", "username", "phone_number", "full_name"] {
            if let Some(v) = val_str(item, field) {
                let vl = v.to_lowercase();
                if vl == target_lower {
                    return true;
                }
                if target_terms.is_empty() {
                    continue;
                }
                let hit = if require_all_terms {
                    target_terms.iter().all(|t| vl.contains(t))
                } else {
                    target_terms.iter().any(|t| vl.contains(t))
                };
                if hit {
                    return true;
                }
            }
        }
        false
    };
    let is_target_row = row_matches_target(item);

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') && seen.insert(lower) {
            push_oathnet_entity(
                result,
                Entity::new(EntityKind::Email, &email, 0.70, scan_id),
                &ev,
                &[],
                is_target_row,
            );
        }
    }

    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            push_oathnet_entity(
                result,
                Entity::new(EntityKind::Username, &uname, 0.65, scan_id),
                &ev,
                &[],
                is_target_row,
            );
        }
    }

    if let Some(ph) = val_str_or(item, &["phone_number", "phone_national", "phone"])
        && ph.len() >= 7
        && seen.insert(ph.to_lowercase())
    {
        push_oathnet_entity(
            result,
            Entity::new(EntityKind::Phone, &ph, 0.70, scan_id),
            &ev,
            &[],
            is_target_row,
        );
    }

    if let Some(n) = val_str_or(item, &["full_name", "display_name", "name"]) {
        let t = n.trim();
        if t.len() >= 4 && t.contains(' ') && seen.insert(t.to_lowercase()) {
            push_oathnet_entity(
                result,
                Entity::new(EntityKind::Person, t, 0.70, scan_id),
                &ev,
                &[],
                is_target_row,
            );
        }
    }

    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
        && seen.insert(ip.clone())
    {
        push_oathnet_entity(
            result,
            Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id),
            &ev,
            &["geolocation-lead"],
            is_target_row,
        );
    }

    if let Some(country) = val_str(item, "country")
        && seen.insert(format!("@country:{country}"))
    {
        push_oathnet_entity(
            result,
            Entity::new(EntityKind::Address, &country, 0.55, scan_id),
            &ev,
            &[],
            is_target_row,
        );
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
            push_oathnet_entity(
                result,
                Entity::new(EntityKind::Address, &addr, 0.65, scan_id),
                &ev,
                &[],
                is_target_row,
            );
        }
    }

    if let Some(did) = val_str(item, "discordid")
        && seen.insert(format!("@discord:{did}"))
    {
        push_oathnet_entity(
            result,
            Entity::new(
                EntityKind::Username,
                format!("discord:{did}"),
                0.55,
                scan_id,
            ),
            &ev,
            &["discord"],
            is_target_row,
        );
    }

    if let Some(ig) = val_str(item, "instagram")
        && seen.insert(format!("@ig:{}", ig.to_lowercase()))
    {
        push_oathnet_entity(
            result,
            Entity::new(EntityKind::Username, &ig, 0.55, scan_id),
            &ev,
            &["instagram"],
            is_target_row,
        );
    }

    // LinkedIn handle — unlocks proxycurl (paid LinkedIn enrichment).
    // The field may contain a URL or a bare handle. Emit as Url if it
    // looks like a URL, else as Username with a linkedin: prefix.
    if let Some(li) = val_str(item, "linkedin") {
        let lower = li.to_lowercase();
        if lower.contains("linkedin.com") {
            if seen.insert(format!("@li:{lower}")) {
                let url_val = if lower.starts_with("http") {
                    li
                } else {
                    format!("https://{li}")
                };
                push_oathnet_entity(
                    result,
                    Entity::new(EntityKind::Url, &url_val, 0.60, scan_id),
                    &ev,
                    &["linkedin"],
                    is_target_row,
                );
            }
        } else if seen.insert(format!("@li-handle:{lower}")) {
            push_oathnet_entity(
                result,
                Entity::new(
                    EntityKind::Username,
                    format!("linkedin:{li}"),
                    0.55,
                    scan_id,
                ),
                &ev,
                &["linkedin"],
                is_target_row,
            );
        }
    }

    // Email-domain → Domain entity. The breach record carries the
    // sender/account email's host as a dedicated field. Emitting it
    // unlocks dns_intel/cert_intel/securitytrails/wayback/cloud_storage
    // — all free modules — for that domain without further cost.
    if let Some(ed) = val_str(item, "email_domain") {
        let lower = ed.to_lowercase();
        if lower.contains('.') && !lower.contains('@') && seen.insert(format!("@edomain:{lower}")) {
            push_oathnet_entity(
                result,
                Entity::new(EntityKind::Domain, &lower, 0.55, scan_id),
                &ev,
                &["email-domain"],
                is_target_row,
            );
        }
    }

    // Password hash → seed for pwned_passwords (free k-anonymity lookup
    // confirms whether the hash is in known breach corpora). Emit as a
    // low-confidence ApiKey entity tagged for that module.
    if let Some(ph) = val_str(item, "password_hash")
        && ph.len() >= 32
        && seen.insert(format!(
            "@pwhash:{}",
            crate::util::str_util::truncate_safe(&ph, 16)
        ))
    {
        push_oathnet_entity(
            result,
            Entity::new(EntityKind::Password, &ph, 0.50, scan_id),
            &ev,
            &["password-hash"],
            is_target_row,
        );
    }
}

/// Apply the stealer-context tags (`oathnet-pro`, `stealer`, plus any
/// `extra_tags` in order) and a cloned evidence record to `e`, then push it.
/// Unlike [`push_oathnet_entity`] this does NOT add the `breach` tag — stealer
/// login/domain/credential context is not leaked PII per se.
fn push_stealer_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag("oathnet-pro");
    e.tag("stealer");
    for t in extra_tags {
        e.tag(*t);
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

fn extract_stealer_entities(
    item: &Value,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let mut ev = Evidence::new(SRC, "Stealer log entry".to_string())
        .with_attr("source", "stealer")
        .with_attr("provider", "oathnet.org")
        .with_attr("api_key_origin", key_fp);
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        ev = ev.with_attr("url", &url);
    }
    if let Some(lid) = val_str(item, "log_id").or_else(|| val_str(item, "log")) {
        ev = ev.with_attr("log_id", &lid);
    }
    if let Some(pw) = val_str(item, "password") {
        ev = ev.with_attr("password", &pw);
        if pw.contains("UPGRADE_TO_SEE") && pw.len() >= 3 {
            // `pw` is untrusted: take the first/last CHAR (not byte) so a
            // multi-byte boundary can't panic the slice.
            let first = pw.chars().next().map(String::from).unwrap_or_default();
            let last = pw.chars().next_back().map(String::from).unwrap_or_default();
            ev = ev
                .with_attr("password_hint_first", first)
                .with_attr("password_hint_last", last)
                .with_attr("password_redacted", "true");
        }
    }
    if let Some(uname) = val_str(item, "username") {
        ev = ev.with_attr("username", &uname);
    }

    if let Some(emails) = item.get("email").and_then(|v| v.as_array()) {
        for email_val in emails {
            if let Some(email) = email_val.as_str() {
                let lower = email.to_lowercase();
                if lower.contains('@') && seen.insert(lower) {
                    push_oathnet_entity(
                        result,
                        Entity::new(EntityKind::Email, email, 0.65, scan_id),
                        &ev,
                        &["stealer"],
                        // Stealer hits come from a search on the target's own
                        // identity — the row IS the target.
                        true,
                    );
                }
            }
        }
    }

    // Username field often contains an email address (stealer logs use the
    // login email as "username"). Emit it so it expands through the email
    // pipeline — HIBP, emailrep, epieos, etc. can then cross-reference.
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.contains('@')
            && lower.contains('.')
            && seen.insert(format!("@stealer-user:{lower}"))
        {
            push_stealer_entity(
                result,
                Entity::new(EntityKind::Email, &uname, 0.60, scan_id),
                &Evidence::new(SRC, "Stealer login email (username field)")
                    .with_attr("source", "stealer"),
                &["stealer-login"],
            );
        }
    }

    if let Some(domains) = item.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(dom) = d.as_str()
                && dom.contains('.')
                && seen.insert(dom.to_lowercase())
            {
                push_stealer_entity(
                    result,
                    Entity::new(EntityKind::Domain, dom, 0.50, scan_id),
                    &Evidence::new(SRC, format!("Stealer credential for {dom}"))
                        .with_attr("source", "stealer"),
                    &[],
                );
            }
        }
    }

    if let Some(uname) = val_str(item, "username")
        && let Some(url_str) = val_str(item, "url").or_else(|| val_str(item, "url_str"))
    {
        let cred_val = format!("{uname}@{url_str}");
        if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
            push_stealer_entity(
                result,
                Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id),
                &ev,
                &[],
            );
        }
    }
}

// ─── API key pattern recognition ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_breach_entities_characterization() {
        use serde_json::json;
        let item = json!({
            "email": "jordan.meyer@example.com",
            "username": "jmeyer",
            "phone_number": "15551234567",
            "ip": "8.8.8.8",
            "country": "US",
            "discordid": "123456789012345678",
            "email_domain": "example.com",
            "password_hash": "0123456789abcdef0123456789abcdef",
            "source": "TestDB"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        // Target matches the email -> is_target_row = true (no "candidate" tags).
        extract_breach_entities(
            &item,
            "jordan.meyer@example.com",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        // Exact, ordered tag vectors — locks byte-stable serialization across
        // the refactor (a reordered tag would fail here).
        let tags_of = |k: EntityKind, needle: &str| -> Vec<String> {
            result
                .entities
                .iter()
                .find(|e| e.kind == k && e.value.contains(needle))
                .map(|e| e.tags.clone())
                .unwrap_or_default()
        };
        assert_eq!(
            tags_of(EntityKind::Email, "jordan.meyer"),
            ["breach", "oathnet-pro"]
        );
        assert_eq!(
            tags_of(EntityKind::Username, "jmeyer"),
            ["breach", "oathnet-pro"]
        );
        assert_eq!(
            tags_of(EntityKind::Phone, "15551234567"),
            ["breach", "oathnet-pro"]
        );
        assert_eq!(
            tags_of(EntityKind::IpAddress, "8.8.8.8"),
            ["breach", "oathnet-pro", "geolocation-lead"]
        );
        assert_eq!(
            tags_of(EntityKind::Username, "discord:"),
            ["breach", "oathnet-pro", "discord"]
        );
        assert_eq!(
            tags_of(EntityKind::Domain, "example.com"),
            ["breach", "oathnet-pro", "email-domain"]
        );
        assert_eq!(
            tags_of(EntityKind::Password, "0123456789"),
            ["breach", "oathnet-pro", "password-hash"]
        );
    }

    #[test]
    fn extract_stealer_entities_characterization() {
        use serde_json::json;
        let item = json!({
            "email": ["victim@example.com"],
            "username": "loginuser@example.com",
            "domain": ["testsite.com"],
            "url": "https://login.site",
            "password": "secret"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_stealer_entities(&item, "scan", "oathnet.org:test", &mut seen, &mut result);

        let tags_of = |k: EntityKind, needle: &str| -> Vec<String> {
            result
                .entities
                .iter()
                .find(|e| e.kind == k && e.value.contains(needle))
                .map(|e| e.tags.clone())
                .unwrap_or_default()
        };
        // The email-array kind carries `breach`; the login-email/domain/credential
        // kinds do NOT (they are credential context, not leaked PII). Exact order.
        assert_eq!(
            tags_of(EntityKind::Email, "victim@example.com"),
            ["breach", "oathnet-pro", "stealer"]
        );
        assert_eq!(
            tags_of(EntityKind::Email, "loginuser@example.com"),
            ["oathnet-pro", "stealer", "stealer-login"]
        );
        assert_eq!(
            tags_of(EntityKind::Domain, "testsite.com"),
            ["oathnet-pro", "stealer"]
        );
        assert_eq!(
            tags_of(EntityKind::Credential, "loginuser@example.com@"),
            ["oathnet-pro", "stealer"]
        );
    }

    #[test]
    fn extract_breach_entities_non_target_row_tags_candidate() {
        use serde_json::json;
        // A row whose fields do NOT match the target: phone/person/country are
        // preserved at candidate confidence with a `candidate` tag (order:
        // breach, oathnet-pro, candidate).
        let item = json!({ "phone_number": "19998887777", "source": "TestDB" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "unrelated-target-xyz",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let phone = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Phone)
            .unwrap();
        assert_eq!(phone.tags, ["breach", "oathnet-pro", "candidate"]);
        assert!(
            (phone.confidence - 0.25).abs() < 1e-9,
            "non-target conf is 0.25"
        );
    }

    #[test]
    fn non_target_email_and_domain_are_quarantined_as_candidates() {
        use serde_json::json;
        // The exact junk pattern from the "Jordan Avery" name scan: a breach
        // row for a stranger (a bank employee) returned by the broad search. The
        // email AND its domain must be demoted to candidate — previously they
        // were emitted at full 0.70/0.55 confidence with no `candidate` tag,
        // which is what flooded the result with 88% junk.
        let item = json!({
            "email": "hlaura@blackhawkbank.com",
            "email_domain": "blackhawkbank.com",
            "source": "AbrigoBreach"
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &item,
            "Jordan Avery",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );

        let email = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("email entity");
        assert!(
            email.has_tag("candidate"),
            "stranger email must be a candidate"
        );
        assert!(email.confidence <= 0.25 + 1e-9, "demoted to candidate conf");

        let domain = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Domain)
            .expect("domain entity");
        assert!(
            domain.has_tag("candidate"),
            "stranger domain must be a candidate"
        );
    }

    #[test]
    fn full_name_matcher_requires_all_terms_not_just_one() {
        use serde_json::json;
        // "Jordan Parker" shares only the first name with the target — it must
        // NOT count as the target row (the old any-term match treated every
        // "Jordan …" as a hit, the dominant false-positive on name scans).
        let parker = json!({ "full_name": "Jordan Parker", "source": "X" });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(
            &parker,
            "Jordan Avery",
            "scan",
            "oathnet.org:test",
            &mut seen,
            &mut result,
        );
        let p = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person entity");
        assert!(
            p.has_tag("candidate"),
            "partial-name match must be a candidate, got tags {:?}",
            p.tags
        );

        // The real person — both terms present — is a confirmed target row.
        let avery = json!({ "full_name": "Jordan Avery", "source": "X" });
        let (mut seen2, mut r2) = (HashSet::new(), ModuleResult::new());
        extract_breach_entities(
            &avery,
            "Jordan Avery",
            "scan",
            "oathnet.org:test",
            &mut seen2,
            &mut r2,
        );
        let d = r2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Person)
            .expect("person entity");
        assert!(
            !d.has_tag("candidate"),
            "exact name is the target, not a candidate"
        );
        assert!(
            (d.confidence - 0.70).abs() < 1e-9,
            "target person at full conf"
        );
    }

    #[test]
    fn accepts_identity_and_infra_kinds() {
        let m = OathnetPro;
        for k in [
            TargetKind::Email,
            TargetKind::Username,
            TargetKind::Phone,
            TargetKind::IpAddress,
            TargetKind::Domain,
            TargetKind::FullName,
        ] {
            assert!(m.accepts(&Target::new(k, "x")));
        }
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
    fn private_ips_are_detected() {
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("169.254.1.1"));
        assert!(is_private_ip("100.64.0.1"));
        assert!(is_private_ip("::1"));
        assert!(is_private_ip("fe80::1"));
        assert!(is_private_ip("fd00::1"));
        assert!(is_private_ip("224.0.0.251"));
        assert!(is_private_ip("239.255.255.250"));
        assert!(is_private_ip("ff02::fb"));
    }

    #[test]
    fn public_ips_are_not_private() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("1.1.1.1"));
        assert!(!is_private_ip("203.0.113.5"));
        assert!(!is_private_ip("2606:4700::1111"));
    }

    #[test]
    fn local_domains_are_detected() {
        assert!(is_local_domain("localhost"));
        assert!(is_local_domain("router.local"));
        assert!(is_local_domain("mypc.lan"));
        assert!(is_local_domain("host.internal"));
        assert!(is_local_domain("gateway.home"));
        assert!(is_local_domain("1.168.192.in-addr.arpa"));
        assert!(is_local_domain("router.local."));
    }

    #[test]
    fn real_domains_are_not_local() {
        assert!(!is_local_domain("example.com"));
        assert!(!is_local_domain("oathnet.org"));
        assert!(!is_local_domain("google.com.au"));
    }

    #[test]
    fn placeholder_usernames_detected() {
        for u in [
            "anonymous",
            "anon",
            "user",
            "admin",
            "test",
            "demo",
            "guest",
            "root",
            "username",
            "default",
            "example",
            "null",
            "undefined",
            "Anonymous",
            "ADMIN",
            "Test", // case insensitive
        ] {
            assert!(is_placeholder_username(u), "should skip: {u}");
        }
    }

    #[test]
    fn real_usernames_not_placeholders() {
        for u in ["alice", "bob_smith", "matrix_neo", "trinity99", "jdoe2024"] {
            assert!(!is_placeholder_username(u), "should NOT skip: {u}");
        }
    }
}
