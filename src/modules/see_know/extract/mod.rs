//! SeekNow record → entity extraction.
//!
//! The pure(ish) extraction layer that turns SeekNow's breach/stealer/OSINT
//! JSON records into graph entities. Split out of `mod.rs` so the `Module`
//! trait impl and per-target dispatch orchestration stay readable, and so the
//! field-mapping / confidence / tagging logic can be unit-tested directly (the
//! `tests` module re-imports these via `super::*`).
//!
//! SeekNow records share most field names with OathNet's V2 schema. We extract
//! the same surface set: email, username, phone, full_name, ip, country,
//! city, state, address, dbname, discord_id, plus URL+credential pairs from
//! stealer items.

mod rich_detail;
use rich_detail::extract_rich_detail;
mod associates;
mod geo;
use associates::*;
pub(super) use geo::extract_geo_entities;
#[cfg(test)]
use geo::parse_coord;
use std::collections::HashSet;

use serde_json::Value;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    tags,
};
use crate::util::extract::EMAIL_RE;
use crate::util::geo::is_valid_coords;
use crate::util::see_know::val_str;
use crate::util::target_match::TargetMatch;

use super::SRC;
use super::pivots::looks_like_steam_id;

/// Matches `<@id>` and `<@!id>` Discord user-mention shapes.
static MESSAGE_MENTION_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"<@!?(\d{17,20})>").expect("constant discord-mention regex")
});

/// Mine a `discord_messages` item's free-text `content` for embedded emails
/// and emit each as a low-confidence `Email` entity (0.30 — below pivot floor).
pub(super) fn extract_message_emails(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for m in EMAIL_RE.find_iter(&content) {
        let email = m.as_str().to_lowercase();
        if seen.insert(email.clone()) {
            let mut e = Entity::new(EntityKind::Email, &email, 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Mine a `discord_messages` item's free-text `content` for `<@id>` / `<@!id>`
/// Discord user-mention snowflakes and emit each as a low-confidence `Username`
/// entity (`discord:<id>`, 0.30 — below pivot floor).
pub(super) fn extract_message_mentions(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let Some(content) = val_str(item, "content") else {
        return;
    };
    let ev = Evidence::new(SRC, "SeekNow discord_messages content")
        .with_attr("source", "discord_messages");
    for caps in MESSAGE_MENTION_RE.captures_iter(&content) {
        let id = &caps[1];
        if seen.insert(format!("@discord:{id}")) {
            let mut e = Entity::new(EntityKind::Username, format!("discord:{id}"), 0.30, scan_id);
            e.tag("see-know");
            e.tag("discord-message");
            e.tag("weak-lead");
            e.tag("mention");
            e.add_evidence(ev.clone());
            result.push(e);
        }
    }
}

/// Build an [`Evidence`] record that preserves EVERY field of the raw source
/// record `item` as an attribute — full fidelity, nothing redacted or omitted
/// (operator data-fidelity policy). Scalars are stored as-is; nested
/// objects/arrays as compact JSON. This is what makes a result traceable to its
/// actual raw source record rather than just a module name + entity hash.
fn record_evidence(item: &Value, dbname: &str, endpoint: &str, key_fp: &str) -> Evidence {
    let ev = Evidence::new(SRC, format!("SeekNow record from {dbname}"))
        .with_attr("source", dbname)
        // Provenance: which provider, which exact API key, and which endpoint
        // returned this record. Stamped on EVERY record so a finding always
        // declares its origin (operator directive: specify the API key origin).
        .with_attr("provider", "see-know.eu")
        .with_attr("api_key_origin", key_fp)
        .with_attr("via_endpoint", endpoint);
    let Some(obj) = item.as_object() else {
        return ev;
    };
    obj.iter().fold(ev, |ev, (k, v)| {
        let val = match v {
            Value::Null => return ev,
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if val.is_empty() {
            return ev;
        }
        // Don't clobber the canonical "source" attribute set above.
        let key = if k == "source" {
            "source_db"
        } else {
            k.as_str()
        };
        ev.with_attr(key, val)
    })
}

/// Normalized identity-demographic tags (`dob:` / `gender:` / `age:`) for the
/// subject node, read across the key spellings the providers use for the same
/// datum. Returned in a stable order; empty when the record carries no
/// demographics. The caller stamps these on the Person so the subject's
/// headline surfaces its demographics as first-class, queryable tags.
fn identity_tags(item: &Value) -> Vec<String> {
    let mut tags = Vec::new();
    // Date of birth — one canonical `dob:` tag from whichever key holds it.
    if let Some(dob) = val_str(item, "date_birth")
        .or_else(|| val_str(item, "birthdate"))
        .or_else(|| val_str(item, "date_of_birth"))
        .or_else(|| val_str(item, "dob"))
    {
        let d = dob.trim();
        if !d.is_empty() {
            tags.push(format!("dob:{d}"));
        }
    }
    // Gender — collapse the obvious spellings to a single uppercase initial so
    // `gender:M` from one record merges with `gender:male` from another.
    if let Some(g) = val_str(item, "gender") {
        let gt = g.trim();
        if !gt.is_empty() {
            let norm = match gt.to_ascii_lowercase().as_str() {
                "m" | "male" => "M",
                "f" | "female" => "F",
                _ => gt,
            };
            tags.push(format!("gender:{norm}"));
        }
    }
    // Age — a number or a numeric string; skip a placeholder/zero.
    let age = item.get("age").map(|a| {
        if a.is_number() {
            a.to_string()
        } else {
            a.as_str().unwrap_or("").trim().to_string()
        }
    });
    if let Some(a) = age
        && !a.is_empty()
        && a != "0"
    {
        tags.push(format!("age:{a}"));
    }
    tags
}

pub(super) fn extract_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    endpoint: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let dbname = val_str(item, "dbname")
        .or_else(|| val_str(item, "source"))
        .unwrap_or_else(|| "see-know".to_string());
    // Full raw record on the evidence chain — every entity derived from this
    // record carries the complete source data plus its provenance (provider,
    // API-key origin, endpoint) for traceability.
    let ev = record_evidence(item, &dbname, endpoint, key_fp);

    // Does this record actually identify the subject? A broad see_know search —
    // above all a name auto-detect — can return same-name strangers; the
    // identity + credential entities they yield are demoted to quarantined
    // `candidate` leads below (mirroring oathnet_pro), so they never reach the
    // subject's full-confidence tier. `quarantine_start` marks where this
    // record's entities begin so the demotion targets exactly them.
    let is_target = TargetMatch::new(target_value).matches(item);
    let quarantine_start = result.entities.len();

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if crate::util::extract::looks_like_email(&lower) && seen.insert(lower) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Email, &email, 0.70, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(uname) = val_str(item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && seen.insert(lower) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Username, &uname, 0.65, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(phone) = val_str(item, "phone").or_else(|| val_str(item, "phone_number"))
        && phone.len() >= 7
    {
        // Lowercase `phone` once and reuse that single copy for both the dedup
        // key and the target comparison, instead of lowercasing it twice (and
        // the target unconditionally). Preserves the exact prior comparison.
        let phone_lower = phone.to_lowercase();
        if seen.insert(phone_lower.clone()) {
            let conf = if phone_lower == target_value.to_lowercase() {
                0.70
            } else {
                0.55
            };
            push_breach_entity(
                result,
                Entity::new(EntityKind::Phone, &phone, conf, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(name) = val_str(item, "full_name").or_else(|| val_str(item, "name"))
        && name.trim().contains(' ')
        && seen.insert(name.to_lowercase())
    {
        let mut person = Entity::new(EntityKind::Person, name.trim(), 0.65, scan_id);
        // Surface the record's identity demographics (DOB / gender / age) as
        // normalized first-class tags on the subject node, not only buried in
        // the raw-record evidence the full-field fold already carries. The
        // dossier headline then reads "Ali Kareem [dob:…] [gender:M]" directly,
        // and the tags merge by UID across every record that re-states them.
        for tag in identity_tags(item) {
            person.tag(tag);
        }
        push_breach_entity(result, person, &ev, &[]);
    }
    // Login IPs — the session `ip` plus the last-login `lastip`/`last_ip`, all
    // geolocation leads. snusbase records carry ONLY `lastip`, so the subject's
    // login location (e.g. 142.204.244.67 on ali.kareem95@gmail.com) was dropped
    // entirely. Gate on a publicly-routable literal so a LAN address never
    // becomes geo-noise — the prior `len >= 7` check admitted private IPs.
    for ip_field in ["ip", "lastip", "last_ip"] {
        if let Some(ip) = val_str(item, ip_field)
            && crate::util::preflight::is_public_ip(&ip)
            && seen.insert(ip.clone())
        {
            push_breach_entity(
                result,
                Entity::new(EntityKind::IpAddress, &ip, 0.60, scan_id),
                &ev,
                &["geolocation-lead"],
            );
        }
    }
    if let Some(country) = val_str(item, "country")
        && !crate::util::json::is_null_sentinel(&country)
        && seen.insert(format!("@country:{country}"))
    {
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(&country) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(EntityKind::Coordinates, &coord_val, 0.45, scan_id);
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("breach");
            c.tag("see-know");
            c.add_evidence(ev.clone());
            result.push(c);
        }
        push_breach_entity(
            result,
            Entity::new(EntityKind::Address, &country, 0.55, scan_id),
            &ev,
            &[],
        );
    }
    if let Some(did) = val_str(item, "discord_id").or_else(|| val_str(item, "discordid"))
        && seen.insert(format!("@discord:{did}"))
    {
        push_breach_entity(
            result,
            Entity::new(
                EntityKind::Username,
                format!("discord:{did}"),
                0.60,
                scan_id,
            ),
            &ev,
            &["discord"],
        );
    }
    // Steam ID — 17-digit 64-bit SteamIDs (steamID64). Surface as a
    // Username with `steam:<id>` prefix so the gaming endpoint pivot
    // can find it without colliding with normal usernames. Matches
    // the discord-pivot pattern.
    if let Some(sid) = val_str(item, "steam_id")
        .or_else(|| val_str(item, "steamid"))
        .or_else(|| val_str(item, "steam_id64"))
        && looks_like_steam_id(&sid)
        && seen.insert(format!("@steam:{sid}"))
    {
        push_breach_entity(
            result,
            Entity::new(EntityKind::Username, format!("steam:{sid}"), 0.60, scan_id),
            &ev,
            &["steam"],
        );
    }
    // Leaked credentials were previously dropped entirely — capture them as
    // first-class Password entities (operator policy: never redacted). The full
    // record (including any hash) is already on `ev`, so nothing is lost even
    // when several credential fields coexist; one pivotable entity is enough.
    for field in [
        "password",
        "passwordHash",
        "password_hash",
        "hashed_password",
        "hash",
    ] {
        let Some(pw) = val_str(item, field) else {
            continue;
        };
        let p = pw.trim();
        match crate::util::extract::classify_credential_field(p) {
            // Capture sentinel ([fail], …) — not a secret; try the next field.
            crate::util::extract::CredentialField::Sentinel => continue,
            // Email mis-stored in a credential slot — recover it as a lead rather
            // than mint a junk Password (the same fix as oathnet_pro's breach path).
            crate::util::extract::CredentialField::Email => {
                if seen.insert(format!("@pw-email:{}", p.to_lowercase())) {
                    let mut e = Entity::new(EntityKind::Email, p, 0.45, scan_id);
                    e.tag("see-know");
                    e.tag("recovered-from-password");
                    e.add_evidence(ev.clone());
                    result.push(e);
                }
                break;
            }
            crate::util::extract::CredentialField::Secret => {
                if seen.insert(format!("@pw:{p}")) {
                    push_breach_entity(
                        result,
                        Entity::new(EntityKind::Password, p, 0.75, scan_id),
                        &ev,
                        &["credential"],
                    );
                    break;
                }
            }
        }
    }

    // ── Stealer-log saved-credential URL ──────────────────────────────────
    //
    // The single most OSINT-valuable artifact in a stealer record is the URL
    // the victim had a saved credential for. SeekNow's /stealer endpoint (and
    // the /search auto-route into it) carries it as `url`/`url_str`. Spider it
    // into two pivotable entities — exactly OathNet's stealer model — so the rest
    // of the graph (credential correlation, login-surface mapping) can converge:
    //
    //   • the Url itself (the captured login surface);
    //   • a `<username>@<url>` Credential when a login accompanies the URL.
    //
    // The URL's host is deliberately NOT minted as a Domain: a stealer host is a
    // third-party service the subject merely has an account on
    // (`akzonobel.taleo.net`, `bitcoinptc.top`), not a domain they own. Minting it
    // spawned subdomain-proliferation noise and misdirected crt.sh/DNS/whois
    // expansion of the *platform's* infrastructure, and forged false correlation
    // brokers across everyone who used that platform. The Url already records the
    // pathway; the subject's own domains arrive via the breach email-domain path.
    //
    // None are tagged `breach`: a saved-login URL is credential CONTEXT /
    // infrastructure, not leaked PII — the same policy `extract_stealer_entities`
    // applies in oathnet_pro.
    if let Some(url) = val_str(item, "url").or_else(|| val_str(item, "url_str")) {
        if url.len() >= 4 && seen.insert(format!("@url:{}", url.to_lowercase())) {
            let mut e = Entity::new(EntityKind::Url, &url, 0.60, scan_id);
            e.tag("see-know");
            e.tag("stealer");
            e.add_evidence(ev.clone());
            result.push(e);
        }
        // `<username>@<url>` Credential — the login↔surface binding, surfaced as
        // a first-class pivotable entity (operator policy: never redacted).
        if let Some(uname) = val_str(item, "username") {
            let cred_val = format!("{uname}@{url}");
            if seen.insert(format!("@cred:{}", cred_val.to_lowercase())) {
                let mut e = Entity::new(EntityKind::Credential, &cred_val, 0.60, scan_id);
                e.tag("see-know");
                e.tag("stealer");
                e.add_evidence(ev.clone());
                result.push(e);
            }
        }
    }

    // Maximum-raw-data pass: surface the long tail of the record (names, full
    // address, organisation, device fingerprints, extra social handles, DOB,
    // and EVERY remaining scalar field) as first-class entities so nothing
    // valuable stays locked inside the evidence blob. Operator directive: "I
    // want everything. Maximum raw data."
    extract_rich_detail(item, scan_id, &ev, seen, result);

    // Quarantine a non-matching record's identity/credential/raw-detail entities
    // to CANDIDATE strength with a `candidate` tag — the same demotion
    // oathnet_pro applies per row — so a same-name stranger from a broad search
    // survives as a low-confidence lead instead of masquerading as the subject
    // at full confidence. Applied to everything THIS record contributed above;
    // declared relatives (next) carry their own `family-candidate` model and the
    // subject's own rows (`is_target`) are untouched.
    if !is_target {
        for e in &mut result.entities[quarantine_start..] {
            e.demote_to_candidate();
        }
    }

    // Relatives / associates / household members → connected Person leads. The
    // searched subject (`target_value`) anchors each via `related_to`, so a
    // name search on one family member surfaces and binds to the others.
    extract_associates(item, target_value, scan_id, key_fp, seen, result);

    // Domain is infrastructure, not a leaked credential, so it is the one kind
    // NOT tagged `breach` — keep its inline tail (and consume the last `ev`). A
    // reverse-DNS app package (`com.facebook.katana`) carried in this field is an
    // app id, not a web domain — skip it (same gate as oathnet_pro's stealer path).
    if let Some(domain) = val_str(item, "domain")
        && crate::util::domains::looks_like_domain(&domain)
        && seen.insert(domain.to_lowercase())
    {
        let mut e = Entity::new(EntityKind::Domain, &domain, 0.55, scan_id);
        e.tag("see-know");
        // Same quarantine as the identity block above (this push lands after it,
        // so it is demoted here rather than by the range pass).
        if !is_target {
            e.demote_to_candidate();
        }
        e.add_evidence(ev);
        result.push(e);
    }
}

/// Apply see_know's standard breach tags (`breach`, `see-know`, plus any
/// endpoint-specific `extra_tags`) and a cloned evidence record to `e`, then
/// push it onto `result`. Centralises the tag+evidence+push tail that every
/// breach-derived entity kind shares.
fn push_breach_entity(
    result: &mut ModuleResult,
    mut e: Entity,
    ev: &Evidence,
    extra_tags: &[&str],
) {
    e.tag(tags::BREACH);
    e.tag("see-know");
    for t in extra_tags {
        e.tag(*t);
    }
    // (Source-sector tagging is applied universally at engine admission —
    // `core::engine::enrich::tag_breach_sector` — so it is not done per-module.)
    e.add_evidence(ev.clone());
    result.push(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_coord_reads_json_number() {
        let item = json!({"lat": 12.5});
        assert_eq!(parse_coord(&item, &["lat"]), Some(12.5));
    }

    #[test]
    fn parse_coord_parses_numeric_string() {
        let item = json!({"lat": "12.5"});
        assert_eq!(parse_coord(&item, &["lat"]), Some(12.5));
    }

    #[test]
    fn parse_coord_tries_keys_in_order_first_present_wins() {
        // First key absent, second present → second is used.
        let item = json!({"lon": -77.25});
        assert_eq!(parse_coord(&item, &["longitude", "lon"]), Some(-77.25));
    }

    #[test]
    fn parse_coord_none_when_no_key_present() {
        let item = json!({"other": 1.0});
        assert_eq!(parse_coord(&item, &["lat", "latitude"]), None);
    }

    #[test]
    fn parse_coord_none_for_non_numeric_string() {
        // Present key, but the string isn't a number → None (the first-present
        // key is consumed even when it fails to parse).
        let item = json!({"lat": "north"});
        assert_eq!(parse_coord(&item, &["lat"]), None);
    }

    #[test]
    fn associates_extracted_as_related_persons() {
        // A SeekNow name record for the subject lists relatives (mixed string +
        // object shapes) and associates. Each becomes a Person bound to the
        // subject by `related_to`, title-cased so it merges with the anchor.
        let item = json!({
            "full_name": "Kyle Diegmann",
            "relatives": ["ERIK DIEGMANN", {"name": "curt diegmann"}, {"first_name":"Hayley","last_name":"Diegmann"}],
            "associates": ["Jane Smith"],
            "neighbours": ["Kyle Diegmann"], // the subject re-listed → skipped
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_associates(&item, "Kyle Diegmann", "s", "fp", &mut seen, &mut result);

        let persons: Vec<&Entity> = result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Person)
            .collect();
        let names: std::collections::BTreeSet<&str> =
            persons.iter().map(|e| e.value.as_str()).collect();
        assert!(
            names.contains("Erik Diegmann"),
            "string relative, title-cased"
        );
        assert!(names.contains("Curt Diegmann"), "object .name relative");
        assert!(
            names.contains("Hayley Diegmann"),
            "first+last composed relative"
        );
        assert!(names.contains("Jane Smith"), "associate");
        assert!(
            !names.contains("Kyle Diegmann"),
            "the subject must not be re-emitted as their own relative"
        );

        // Every relative carries the declared edge data + corroboration tag.
        let erik = persons.iter().find(|e| e.value == "Erik Diegmann").unwrap();
        assert!(erik.has_tag("family-candidate"));
        let related_to = erik
            .evidence
            .iter()
            .find_map(|ev| ev.attributes.get("related_to"))
            .map(String::as_str);
        assert_eq!(related_to, Some("Kyle Diegmann"));
        // Associates are not in the surname cluster → tagged differently.
        let jane = persons.iter().find(|e| e.value == "Jane Smith").unwrap();
        assert!(jane.has_tag("associate-candidate"));
    }

    #[test]
    fn associates_noop_without_relationship_arrays() {
        // A plain breach record (no relationship arrays) yields no associates.
        let item = json!({"email": "a@b.com", "username": "ab"});
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_associates(&item, "Someone", "s", "fp", &mut seen, &mut result);
        assert!(result.entities.is_empty());
    }
}
