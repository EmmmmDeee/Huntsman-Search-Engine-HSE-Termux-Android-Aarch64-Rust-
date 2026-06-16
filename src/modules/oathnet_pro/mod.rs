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

    fn attack_techniques(&self) -> &'static [&'static str] {
        // oathnet_pro sits in the People category for dispatch, but functionally
        // it is a breach / stealer pool: its extractors mint leaked credentials,
        // emails, employee names, network IPs, and physical addresses. The People
        // default (T1589.003 + T1591.004 "Identify Roles") both over-claims a
        // role mapping the module never performs and under-claims the
        // credential/email/IP/location collection it actually does — so declare
        // the precise set instead (mirroring au_people, which likewise drops
        // T1591.004 where no role is identified).
        &[
            "T1589.001", // Credentials — leaked passwords / hashes
            "T1589.002", // Email Addresses
            "T1589.003", // Employee Names — Person from name fields
            "T1590.005", // IP Addresses
            "T1591.001", // Determine Physical Locations — street / city / state address
        ]
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

        let v = target.value.trim();
        // The selector field is the single-sourced kind→field mapping shared
        // with the `oathnet_batch` generator; `None` means OathNet doesn't
        // index this kind, so there is nothing to query.
        let Some(field) = oathnet::selector_field(target.kind) else {
            return Ok(result);
        };
        // Pre-flight skips for inputs that empirically waste OathNet lookups.
        // Catching these BEFORE the cache + budget check means a junk input
        // never burns a query nor pollutes the cache.
        if should_skip_preflight(target.kind, v) {
            return Ok(result);
        }

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
        // Aggregate identity attributes ADDITIVELY across every breach record:
        // each record contributes its distinct country / name / gender / DOB so
        // multiple hits (and aliases) are all retained and cross-correlatable,
        // never overwritten to the last record. Order-preserving, deduplicated.
        let countries = oathnet::distinct_field(&items, "country");
        let names = oathnet::distinct_field(&items, "full_name");
        let genders = oathnet::distinct_field(&items, "gender");
        let dobs = oathnet::distinct_field(&items, "date_birth");

        let mut ev = Evidence::new(
            SRC,
            format!("OathNet: {total} breach record(s) — {}", top_dbs.join(", ")),
        )
        .with_attr("hits", total.to_string())
        .with_attr("top_dbnames", top_dbs.join(", "));
        if !countries.is_empty() {
            ev = ev.with_attr("countries", countries.join(", "));
        }
        if !names.is_empty() {
            ev = ev.with_attr("names", names.join("; "));
        }
        if !genders.is_empty() {
            ev = ev.with_attr("genders", genders.join(", "));
        }
        if !dobs.is_empty() {
            ev = ev.with_attr("dates_of_birth", dobs.join(", "));
        }
        parent.add_evidence(ev);
        result.push(parent);

        // Hoist the per-target match context out of the per-record loop:
        // `target_lower` and the significant-term split depend only on the
        // target value, not the row, so computing them once (instead of once
        // per breach record) eliminates a `to_lowercase()` allocation and a
        // term-`Vec` build for every item on large breach pages.
        let match_ctx = TargetMatch::new(&target.value);
        result.entities.reserve(items.len());
        for item in &items {
            extract_breach_entities_with(
                item,
                &match_ctx,
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
        if oathnet::stealer_indexable(field)
            && !ctx.cancel.is_cancelled()
            && let Ok(stealer_items) =
                oathnet::search(key, paths::STEALER, field, &target.value, 100).await
        {
            result.entities.reserve(stealer_items.len());
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

/// True for inputs that empirically waste an OathNet lookup for `kind` — junk
/// the breach/stealer corpora never match: test/example-TLD emails, placeholder
/// or too-short/all-digit usernames, placeholder phones, single-word names,
/// private IPs, and social-platform / local domains. **Pure** — extracted from
/// the `process` dispatcher so the per-kind gates are testable on their own and
/// kept separate from the (now single-sourced) field naming. Kinds OathNet
/// doesn't index are skipped, though `oathnet::selector_field` already filters
/// those upstream.
fn should_skip_preflight(kind: TargetKind, v: &str) -> bool {
    match kind {
        // Emails on test/example/invalid TLDs are never in real breach corpora.
        TargetKind::Email => v
            .split_once('@')
            .is_some_and(|(_, host)| is_local_domain(host)),
        // Usernames under 4 chars, all-digits, or "anonymous"-style placeholders
        // are noise — the corpora dedupe so well that hits are vanishingly rare.
        TargetKind::Username => {
            v.len() < 4 || v.chars().all(|c| c.is_ascii_digit()) || is_placeholder_username(v)
        }
        // Phone < 6 digits or all-zeros = placeholder.
        TargetKind::Phone => {
            let digits = v.chars().filter(char::is_ascii_digit).count();
            digits < 6 || v.chars().filter(char::is_ascii_digit).all(|c| c == '0')
        }
        // Single-word "names" are noise; real full-name matches have a space.
        TargetKind::FullName => !v.contains(' ') || v.len() < 5,
        TargetKind::IpAddress => is_private_ip(v),
        TargetKind::Domain => is_social_platform(v) || is_local_domain(v),
        _ => true,
    }
}

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

/// Pre-computed, row-independent matching context for a single scan target.
///
/// Built once per `process` call (not per breach record) and reused across
/// every row, so the `to_lowercase()` allocation and the significant-term
/// split happen exactly once instead of once per item on large breach pages.
struct TargetMatch {
    /// Lowercased target value, used both for the exact-equality short-circuit
    /// and as the backing store the borrowed `terms` slice into.
    lower: String,
    /// Significant (`len >= 3`) alphanumeric terms of `lower`.
    terms: Vec<(usize, usize)>,
    /// Multi-term targets must match EVERY term within a single field.
    require_all_terms: bool,
}

impl TargetMatch {
    fn new(target_value: &str) -> Self {
        let lower = target_value.to_lowercase();
        // Store term spans (byte ranges) rather than `&str` to sidestep the
        // self-referential borrow of `lower`; resolved on demand in `matches`.
        let terms: Vec<(usize, usize)> = lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 3)
            .map(|w| {
                let start = w.as_ptr() as usize - lower.as_ptr() as usize;
                (start, start + w.len())
            })
            .collect();
        let require_all_terms = terms.len() >= 2;
        Self {
            lower,
            terms,
            require_all_terms,
        }
    }

    /// True if any matchable field of `item` identifies the target.
    fn matches(&self, item: &Value) -> bool {
        for field in ["email", "username", "phone_number", "full_name"] {
            if let Some(v) = val_str(item, field) {
                let vl = v.to_lowercase();
                if vl == self.lower {
                    return true;
                }
                if self.terms.is_empty() {
                    continue;
                }
                let mut terms = self.terms.iter().map(|&(s, e)| &self.lower[s..e]);
                // Multi-term targets (a full name like "Jordan Avery", or an
                // email) must match EVERY significant term within a single
                // field — not just one — so a row for "Jordan Parker" no longer
                // counts as the target on the shared first name (the dominant
                // junk source on name scans). Single-term targets keep
                // substring-contains matching.
                let hit = if self.require_all_terms {
                    terms.all(|t| vl.contains(t))
                } else {
                    terms.any(|t| vl.contains(t))
                };
                if hit {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
fn extract_breach_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    extract_breach_entities_with(
        item,
        &TargetMatch::new(target_value),
        scan_id,
        key_fp,
        seen,
        result,
    );
}

fn extract_breach_entities_with(
    item: &Value,
    match_ctx: &TargetMatch,
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
    let is_target_row = match_ctx.matches(item);

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
    include!("tests.rs");
}
