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
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
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

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = oathnet::resolve_key(ctx.key_opt(oathnet::KEY_ENV));

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
            extract_breach_entities(item, &target.value, &ctx.scan_id, &mut seen, &mut result);
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
                extract_stealer_entities(item, &ctx.scan_id, &mut seen, &mut result);
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
        .any(|p| lower == *p || lower.ends_with(&format!(".{p}")))
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

fn extract_breach_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let ev = breach_evidence(item);

    // Only emit entities from records that match the target lookup.
    // Breach databases contain millions of records — a phone/IP search
    // returns rows for many different people. We only want entities
    // from rows where the email/username/phone matches our target.
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

    // Every emitted kind flows through `push_breach`, which applies the
    // seed-relevance gate uniformly: rows that actually match the target keep
    // full confidence; the rest (common-name breach-corpus co-occurrences that
    // belong to other people) land at CANDIDATE tier + "candidate" tag,
    // preserved for investigation but never masquerading as the subject's
    // verified identifiers. Centralising this here makes the gate correct by
    // construction for all kinds — previously email/username/IP/social handles
    // each leaked at full confidence through their own bespoke block.

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if lower.contains('@') {
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Email,
                email,
                lower,
                0.70,
                is_target_row,
                &[],
            );
        }
    }

    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 {
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Username,
                uname.clone(),
                lower,
                0.65,
                is_target_row,
                &[],
            );
        }
    }

    if let Some(ph) = val_str_or(item, &["phone_number", "phone_national", "phone"])
        && ph.len() >= 7
    {
        let key = ph.to_lowercase();
        push_breach(
            result,
            seen,
            scan_id,
            &ev,
            EntityKind::Phone,
            ph,
            key,
            0.70,
            is_target_row,
            &[],
        );
    }

    if let Some(n) = val_str_or(item, &["full_name", "display_name", "name"]) {
        let t = n.trim();
        if t.len() >= 4 && t.contains(' ') {
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Person,
                t,
                t.to_lowercase(),
                0.70,
                is_target_row,
                &[],
            );
        }
    }

    if let Some(ip) = val_str(item, "ip")
        && ip.len() >= 7
    {
        let key = ip.clone();
        push_breach(
            result,
            seen,
            scan_id,
            &ev,
            EntityKind::IpAddress,
            ip,
            key,
            0.60,
            is_target_row,
            &["geolocation-lead"],
        );
    }

    if let Some(country) = val_str(item, "country") {
        push_breach(
            result,
            seen,
            scan_id,
            &ev,
            EntityKind::Address,
            country.clone(),
            format!("@country:{country}"),
            0.55,
            is_target_row,
            &[],
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
        if addr.len() >= 4 {
            let key = format!("@addr:{}", addr.to_lowercase());
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Address,
                addr,
                key,
                0.65,
                is_target_row,
                &[],
            );
        }
    }

    if let Some(did) = val_str(item, "discordid") {
        push_breach(
            result,
            seen,
            scan_id,
            &ev,
            EntityKind::Username,
            format!("discord:{did}"),
            format!("@discord:{did}"),
            0.55,
            is_target_row,
            &["discord"],
        );
    }

    if let Some(ig) = val_str(item, "instagram") {
        let key = format!("@ig:{}", ig.to_lowercase());
        push_breach(
            result,
            seen,
            scan_id,
            &ev,
            EntityKind::Username,
            ig,
            key,
            0.55,
            is_target_row,
            &["instagram"],
        );
    }

    // LinkedIn handle — unlocks proxycurl (paid LinkedIn enrichment).
    // The field may contain a URL or a bare handle. Emit as Url if it
    // looks like a URL, else as Username with a linkedin: prefix.
    if let Some(li) = val_str(item, "linkedin") {
        let lower = li.to_lowercase();
        if lower.contains("linkedin.com") {
            let url_val = if lower.starts_with("http") {
                li.clone()
            } else {
                format!("https://{li}")
            };
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Url,
                url_val,
                format!("@li:{lower}"),
                0.60,
                is_target_row,
                &["linkedin"],
            );
        } else {
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Username,
                format!("linkedin:{li}"),
                format!("@li-handle:{lower}"),
                0.55,
                is_target_row,
                &["linkedin"],
            );
        }
    }

    // Email-domain → Domain entity. Unlocks free DNS/cert/wayback modules for
    // the subject's domain; off-target rows (unrelated employers like
    // abrigo.com) are gated to CANDIDATE so they don't rank as signal or seed
    // expansion into dozens of irrelevant corporate domains.
    if let Some(ed) = val_str(item, "email_domain") {
        let lower = ed.to_lowercase();
        if lower.contains('.') && !lower.contains('@') {
            push_breach(
                result,
                seen,
                scan_id,
                &ev,
                EntityKind::Domain,
                lower.clone(),
                format!("@edomain:{lower}"),
                0.55,
                is_target_row,
                &["email-domain"],
            );
        }
    }

    // Password hash → seed for pwned_passwords (free k-anonymity lookup
    // confirms whether the hash is in known breach corpora). Emit as a
    // low-confidence ApiKey entity tagged for that module.
    if let Some(ph) = val_str(item, "password_hash")
        && ph.len() >= 32
        && seen.insert(format!("@pwhash:{}", &ph[..16.min(ph.len())]))
    {
        let mut e = Entity::new(EntityKind::Password, &ph, 0.50, scan_id);
        e.tag(tags::BREACH);
        e.tag("oathnet-pro");
        e.tag("password-hash");
        e.add_evidence(ev);
        result.push(e);
    }
}

/// Emit one breach-derived entity with uniform tagging, dedup, and the
/// seed-relevance gate. No-op if `dedup_key` was already seen this scan.
///
/// Centralises the rule that off-target rows (common-name breach-corpus
/// co-occurrences) land at CANDIDATE tier + `candidate` tag, so every kind is
/// gated correctly by construction rather than in bespoke per-field blocks.
#[allow(clippy::too_many_arguments)]
fn push_breach(
    result: &mut ModuleResult,
    seen: &mut HashSet<String>,
    scan_id: &str,
    ev: &Evidence,
    kind: EntityKind,
    value: impl Into<String>,
    dedup_key: String,
    base_conf: f64,
    is_target_row: bool,
    extra_tags: &[&str],
) {
    if !seen.insert(dedup_key) {
        return;
    }
    let conf = if is_target_row { base_conf } else { 0.25 };
    let mut e = Entity::new(kind, value, conf, scan_id);
    e.tag(tags::BREACH);
    e.tag("oathnet-pro");
    for t in extra_tags {
        e.tag(*t);
    }
    if !is_target_row {
        e.tag("candidate");
    }
    e.add_evidence(ev.clone());
    result.push(e);
}

fn extract_stealer_entities(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let mut ev = Evidence::new(SRC, "Stealer log entry".to_string()).with_attr("source", "stealer");
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        ev = ev.with_attr("url", &url);
    }
    if let Some(lid) = val_str(item, "log_id").or_else(|| val_str(item, "log")) {
        ev = ev.with_attr("log_id", &lid);
    }
    if let Some(pw) = val_str(item, "password") {
        ev = ev.with_attr("password", &pw);
        if pw.contains("UPGRADE_TO_SEE") && pw.len() >= 3 {
            let first = &pw[..1];
            let last = &pw[pw.len() - 1..];
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
                    let mut e = Entity::new(EntityKind::Email, email, 0.65, scan_id);
                    e.tag(tags::BREACH);
                    e.tag("oathnet-pro");
                    e.tag("stealer");
                    e.add_evidence(ev.clone());
                    result.push(e);
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
            let mut e = Entity::new(EntityKind::Email, &uname, 0.60, scan_id);
            e.tag("oathnet-pro");
            e.tag("stealer");
            e.tag("stealer-login");
            e.add_evidence(
                Evidence::new(SRC, "Stealer login email (username field)")
                    .with_attr("source", "stealer"),
            );
            result.push(e);
        }
    }

    if let Some(domains) = item.get("domain").and_then(|v| v.as_array()) {
        for d in domains {
            if let Some(dom) = d.as_str()
                && dom.contains('.')
                && seen.insert(dom.to_lowercase())
            {
                let mut e = Entity::new(EntityKind::Domain, dom, 0.50, scan_id);
                e.tag("oathnet-pro");
                e.tag("stealer");
                e.add_evidence(
                    Evidence::new(SRC, format!("Stealer credential for {dom}"))
                        .with_attr("source", "stealer"),
                );
                result.push(e);
            }
        }
    }

    if let Some(uname) = val_str(item, "username")
        && let Some(url_str) = val_str(item, "url").or_else(|| val_str(item, "url_str"))
    {
        let cred_val = format!("{uname}@{url_str}");
        if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id);
            e.tag("oathnet-pro");
            e.tag("stealer");
            e.add_evidence(ev);
            result.push(e);
        }
    }
}

// ─── API key pattern recognition ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn breach_email_off_target_is_candidate_not_verified() {
        // A breach row whose email shares nothing with the seed (common-name
        // dump noise) must be emitted at CANDIDATE confidence + tag, not at
        // the 0.70 verified tier — the 92-email flood fix.
        let item = serde_json::json!({
            "email": "max.morelli@abrigo.com",
            "full_name": "Max Morelli",
            "dbname": "abrigo.com"
        });
        let mut seen = std::collections::HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(&item, "Jordan Leigh Meyer", "s", &mut seen, &mut result);
        let email = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("email emitted");
        assert!(
            email.confidence < 0.40,
            "off-target email should be candidate, got {}",
            email.confidence
        );
        assert!(email.has_tag("candidate"));
    }

    #[test]
    fn breach_email_on_target_keeps_full_confidence() {
        // A row whose email contains a seed term stays at the verified tier.
        let item = serde_json::json!({ "email": "jordanleigh.meyer@example.com" });
        let mut seen = std::collections::HashSet::new();
        let mut result = ModuleResult::new();
        extract_breach_entities(&item, "Jordan Leigh Meyer", "s", &mut seen, &mut result);
        let email = result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Email)
            .expect("email emitted");
        assert!((email.confidence - 0.70).abs() < 1e-9);
        assert!(!email.has_tag("candidate"));
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
