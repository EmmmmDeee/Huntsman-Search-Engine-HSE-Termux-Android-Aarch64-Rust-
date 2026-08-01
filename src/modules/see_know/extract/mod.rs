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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
    tags,
    validation::is_username_derived_name,
};
use crate::util::geo::is_valid_coords;
use crate::util::see_know::val_str;
use crate::util::target_match::TargetMatch;

use super::SRC;
use super::pivots::looks_like_steam_id;

/// Build an [`Evidence`] record that preserves EVERY field of the raw source
/// record `item` as an attribute — full fidelity, nothing redacted or omitted
/// (operator data-fidelity policy). Scalars are stored as-is; nested
/// objects/arrays as compact JSON. This is what makes a result traceable to its
/// actual raw source record rather than just a module name + entity hash.
fn record_evidence(item: &Value, dbname: &str, endpoint: &str, key_fp: &str) -> Evidence {
    let ev = Evidence::new(SRC, format!("SeekNow record from {dbname}"))
        // `dbname` is the canonical breach-name attribute the credential-reuse
        // correlator (AU-105) groups on; without it AU-105 falls back to the
        // Evidence `source` FIELD (the module name) and collapses every SeekNow
        // record into one pseudo-breach, so cross-breach reuse among a subject's
        // SeekNow hits could never fire. `source` is retained (existing consumers
        // read it) but is an attribute, not the field AU-105's fallback inspects.
        .with_attr("dbname", dbname)
        .with_attr("source", dbname)
        // Provenance: which provider, which exact API key, and which endpoint
        // returned this record. Stamped on EVERY record so a finding always
        // declares its origin (operator directive: specify the API key origin).
        // Domain-agnostic — SeekNow rotates across three domains (see
        // `see_know::client::all_base_urls`), so a literal TLD here would
        // misdescribe records served by a fallback and go stale on rotation.
        .with_attr("provider", "see-know")
        .with_attr("api_key_origin", key_fp)
        .with_attr("via_endpoint", endpoint);
    let Some(obj) = item.as_object() else {
        return ev;
    };
    let ev = obj.iter().fold(ev, |ev, (k, v)| {
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
    });
    // SeekNow labels the subject's self-reported postcode `postal`, but the
    // AU-locality correlator (AU-091/AU-093, `rules/breach_pii.rs`) reads the
    // canonical `postcode` key. Stamp it additively (the raw `postal` is left
    // untouched for existing consumers) so a breach record's OWN postcode reaches
    // the rule — a producer-side alias exactly like the `dbname` fix above.
    // Deliberately NOT done by widening the rule's shared `POSTCODE_KEYS`:
    // `postal` is also stamped by the IP-geo modules (`ip_geo`/`ipinfo`/
    // `ip_whois_geo`) on network-derived `Coordinates`, a different evidentiary
    // class that must not masquerade as self-reported breach PII. Skipped when
    // the record already carries `postcode`, so a real value is never overridden.
    if !obj.contains_key("postcode") {
        let postal = match obj.get("postal") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        };
        if !postal.is_empty() {
            return ev.with_attr("postcode", postal);
        }
    }
    ev
}

// Coordinates 8 distinct inputs (raw target + prebuilt matcher + provenance +
// two accumulators); bundling them into a struct would only move the arity, so
// this follows the module's existing convention (`see_know/mod.rs`).
#[allow(clippy::too_many_arguments)]
pub(super) fn extract_entities(
    item: &Value,
    target_value: &str,
    match_ctx: &TargetMatch,
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
    let is_target = match_ctx.matches(item);
    let quarantine_start = result.entities.len();

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if crate::util::extract::looks_like_email(&lower) && seen.insert(lower) {
            push_breach_entity(
                result,
                Entity::new(EntityKind::Email, &email, confidence::HIGH_PLUS, scan_id),
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
                Entity::new(EntityKind::Username, &uname, confidence::HIGH, scan_id),
                &ev,
                &[],
            );
        }
    }
    if let Some(phone) = val_str(item, "phone").or_else(|| val_str(item, "phone_number"))
        && phone.len() >= 7
    {
        // Lowercase `phone` once and reuse that single copy for both the dedup
        // key and the target comparison. The target's lowercased form is reused
        // from the shared `match_ctx` (computed once per scan), not re-derived
        // per record. Preserves the exact prior comparison.
        let phone_lower = phone.to_lowercase();
        if seen.insert(phone_lower.clone()) {
            let conf = if phone_lower == match_ctx.lower() {
                confidence::HIGH_PLUS
            } else {
                confidence::MEDIUM_HIGH
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
        // Some breach databases store `full_name = "{username} {username}"`
        // when no real name is available — reject before it reaches the graph
        // (the sibling `oathnet_pro` extractor shares this exact schema and
        // the same guard, `oathnet_pro/breach.rs`).
        && !is_username_derived_name(name.trim())
        && seen.insert(name.to_lowercase())
    {
        let mut person = Entity::new(EntityKind::Person, name.trim(), confidence::HIGH, scan_id);
        // Surface the record's identity demographics (DOB / gender / age) as
        // normalized first-class tags on the subject node, not only buried in
        // the raw-record evidence the full-field fold already carries. The
        // dossier headline then reads "Ali Kareem [dob:…] [gender:M]" directly,
        // and the tags merge by UID across every record that re-states them.
        for tag in crate::util::identity::identity_tags(item) {
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
                Entity::new(EntityKind::IpAddress, &ip, confidence::MEDIUM_PLUS, scan_id),
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
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::LOW_MEDIUM,
                scan_id,
            );
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("breach");
            c.tag("see-know");
            c.add_evidence(ev.clone());
            result.push(c);
        }
        push_breach_entity(
            result,
            Entity::new(
                EntityKind::Address,
                &country,
                confidence::MEDIUM_HIGH,
                scan_id,
            ),
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
                confidence::MEDIUM_PLUS,
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
            Entity::new(
                EntityKind::Username,
                format!("steam:{sid}"),
                confidence::MEDIUM_PLUS,
                scan_id,
            ),
            &ev,
            &["steam"],
        );
    }
    // ── Discord connected_accounts → cross-platform identity pivots. ──
    // Discord's `connected_accounts` (a.k.a. `connections`) array is its
    // canonical cross-platform identity edge and the highest-yield artifact the
    // discord/user endpoint returns. Each entry is `{type, id, name}`. A `steam`
    // link mints the SAME `steam:<id>` Username the direct field does, so it
    // plugs straight into the existing, already-tested steam pivot; every other
    // platform mints a `{type}:{handle}` Username matching the breach_rich handle
    // convention. Shape-gated (entry is an object with a short alnum `type` and
    // an id/name) so an unrelated array named `connections` can't inject noise.
    for arr_key in ["connected_accounts", "connections"] {
        let Some(arr) = item.get(arr_key).and_then(Value::as_array) else {
            continue;
        };
        for conn in arr {
            let Some(obj) = conn.as_object() else {
                continue;
            };
            let ty = obj
                .get("type")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if ty.is_empty() || !ty.chars().all(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            let id = obj.get("id").and_then(Value::as_str).map(str::trim);
            let name = obj.get("name").and_then(Value::as_str).map(str::trim);
            // Steam link → the pivot-feeding `steam:<id>` shape when the id validates.
            if ty == "steam"
                && let Some(sid) = id.filter(|s| looks_like_steam_id(s))
                && seen.insert(format!("@steam:{sid}"))
            {
                push_breach_entity(
                    result,
                    Entity::new(
                        EntityKind::Username,
                        format!("steam:{sid}"),
                        confidence::MEDIUM_HIGH,
                        scan_id,
                    ),
                    &ev,
                    &["steam", "discord-linked"],
                );
                continue;
            }
            // Any other platform → a `{type}:{handle}` Username pivot. Prefer the
            // human handle (`name`); fall back to the numeric id.
            let handle = name.filter(|s| !s.is_empty()).or(id);
            if let Some(h) = handle.filter(|s| s.len() >= 2)
                && seen.insert(format!("@{ty}:{}", h.to_lowercase()))
            {
                // Borrow `ty` for the tag slice (no per-entry allocation/leak).
                let tags = [ty.as_str(), "discord-linked"];
                push_breach_entity(
                    result,
                    Entity::new(
                        EntityKind::Username,
                        format!("{ty}:{h}"),
                        confidence::MEDIUM_HIGH,
                        scan_id,
                    ),
                    &ev,
                    &tags,
                );
            }
        }
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
                    let mut e = Entity::new(EntityKind::Email, p, confidence::LOW_MEDIUM, scan_id);
                    e.tag("see-know");
                    e.tag("recovered-from-password");
                    e.add_evidence(ev.clone());
                    result.push(e);
                }
                break;
            }
            crate::util::extract::CredentialField::Secret => {
                if seen.insert(format!("@pw:{p}")) {
                    // Offline hash intelligence ("hashcat-lite"), the same enrichment
                    // dehashed/oathnet apply: classify the algorithm + crackability,
                    // flag an appended salt, and reverse-look-up a common-password
                    // digest — all pure, no network, no GPU (Termux-safe). A see_know
                    // stealer/breach HASH is now as pivotable as a dehashed one; a
                    // plaintext password is unaffected (`identify_hash` → None).
                    let mut tags: Vec<String> = vec!["credential".to_string()];
                    if let Some((algo, fast)) = crate::util::hashcat::identify_hash(p) {
                        tags.push("password-hash".to_string());
                        tags.push(format!("hash:{algo}"));
                        tags.push(
                            if fast {
                                "crackable:fast"
                            } else {
                                "crackable:slow"
                            }
                            .to_string(),
                        );
                    }
                    // Salted if the digest itself carries an appended salt OR the
                    // record has a dedicated `salt` column (Snusbase-style schema).
                    // Without the column check a fast MD5/SHA-1 shipped alongside a
                    // separate salt was mis-tagged `crackable:fast` — overstating
                    // exposure and inviting a bogus rainbow-table pivot. OathNet's
                    // breach path already reads this field; SeekNow was the outlier
                    // on its own schema.
                    if crate::util::hashcat::is_salted(p)
                        || val_str(item, "salt").is_some_and(|s| !s.trim().is_empty())
                    {
                        tags.push("salted".to_string());
                    }
                    let cracked = crate::util::hashcat::crack_common(p);
                    if cracked.is_some() {
                        tags.push("cracked".to_string());
                    }
                    let tag_refs: Vec<&str> = tags.iter().map(String::as_str).collect();
                    push_breach_entity(
                        result,
                        Entity::new(EntityKind::Password, p, confidence::VERY_HIGH, scan_id),
                        &ev,
                        &tag_refs,
                    );
                    // A recovered plaintext (the subject's weak password laid bare)
                    // becomes a first-class node, exactly as the dehashed path does.
                    if let Some(pt) = cracked
                        && seen.insert(format!("@pw:{}", pt.to_lowercase()))
                    {
                        push_breach_entity(
                            result,
                            Entity::new(EntityKind::Password, pt, confidence::STRONG, scan_id),
                            &ev,
                            &["cracked", "weak-password", "from-hash"],
                        );
                    }
                    break;
                }
            }
        }
    }

    // ── IBAN — a leaked bank-account number ───────────────────────────────
    // Emit ONLY when the ISO 7064 mod-97 check digit validates (via the shared
    // `util::extract::iban_is_valid`), so a redacted sentinel or a transcription
    // error in the `iban` field never mints a bogus financial artifact — the same
    // discipline OathNet's breach path already applies. Before this, SeekNow's
    // `iban` field fell through to breach_rich's UNVALIDATED catch-all, minting an
    // `Other("iban")` node for ANY string (bad check digit included); `iban` is
    // now in `RICH_DETAIL_SKIP` so the catch-all no longer emits it unvalidated.
    // No dedicated financial `EntityKind` exists, so it lands as `Other("iban")`
    // tagged `financial` for the dossier/export.
    if let Some(iban) = val_str(item, "iban") {
        // Normalise (strip whitespace, upper-case) BEFORE validating: the shared
        // `iban_is_valid` requires an all-alphanumeric body, and breach exports
        // routinely store the grouped "GB82 WEST …" form — the same normalisation
        // OathNet's validator wrapper applies. The DISPLAYED value keeps the
        // trimmed original spacing, exactly as OathNet emits it.
        let normalized: String = iban
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        if crate::util::extract::iban_is_valid(&normalized)
            && seen.insert(format!("@iban:{normalized}"))
        {
            push_breach_entity(
                result,
                Entity::new(
                    EntityKind::Other("iban".to_string()),
                    iban.trim(),
                    0.70,
                    scan_id,
                ),
                &ev,
                &["iban", "financial"],
            );
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
        let u = url.trim();
        // Mirror oathnet_pro's stealer Url gate: only a real web URL (an `http(s)`
        // scheme AND a dotted host) is a captured login surface. The old bare
        // `len >= 4` admitted native-app URIs (`app://…`), scheme-less junk, and
        // capture sentinels the sibling parser rejects — minting bogus `Url` nodes
        // that then misdirect crawl/DNS expansion. Single-sourced with
        // `oathnet_pro::stealer` so the two stealer consumers can't drift.
        if u.starts_with("http")
            && u.contains('.')
            && seen.insert(format!("@url:{}", u.to_lowercase()))
        {
            let mut e = Entity::new(EntityKind::Url, u, confidence::MEDIUM_PLUS, scan_id);
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
                let mut e = Entity::new(
                    EntityKind::Credential,
                    &cred_val,
                    confidence::MEDIUM_PLUS,
                    scan_id,
                );
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

    // ── /domain/intel subdomains → the target's OWN attack surface. ──
    // Only the domain/intel response carries a `subdomains` array. Each is a
    // first-class seed the dns_intel/cert_intel/crtsh/web_crawler modules fan out
    // from — a paid domain-intel corpus may hold subdomains the free CT/DNS stack
    // misses. Gated on `is_or_subdomain_of(sub, queried_domain)` so ONLY the
    // target's own tree is minted, never a third-party host the record merely
    // mentions (unlike the deliberately un-minted stealer URL host below). Not
    // tagged `breach` — a subdomain is infrastructure, exactly like the `domain`
    // field below. Pushed inside the quarantine range so a non-matching record's
    // subdomains demote with the rest.
    if endpoint == "domain_intel"
        && let Some(subs) = item.get("subdomains").and_then(Value::as_array)
    {
        for sub in subs {
            let Some(raw) = sub.as_str() else { continue };
            let s = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if crate::util::domains::looks_like_domain(&s)
                && crate::util::domains::is_or_subdomain_of(&s, target_value)
                && seen.insert(format!("@subdomain:{s}"))
            {
                let mut e = Entity::new(EntityKind::Domain, &s, confidence::MEDIUM_PLUS, scan_id);
                e.tag("see-know");
                e.tag("subdomain");
                e.tag("dns");
                e.add_evidence(ev.clone());
                result.push(e);
            }
        }
    }

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
        let mut e = Entity::new(
            EntityKind::Domain,
            &domain,
            confidence::MEDIUM_HIGH,
            scan_id,
        );
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
        let erik = persons
            .iter()
            .find(|e| e.value == "Erik Diegmann")
            .expect("should succeed");
        assert!(erik.has_tag("family-candidate"));
        let related_to = erik
            .evidence
            .iter()
            .find_map(|ev| ev.attributes.get("related_to"))
            .map(String::as_str);
        assert_eq!(related_to, Some("Kyle Diegmann"));
        // Associates are not in the surname cluster → tagged differently.
        let jane = persons
            .iter()
            .find(|e| e.value == "Jane Smith")
            .expect("should succeed");
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

    #[test]
    fn associates_reject_username_derived_and_null_pair_names() {
        // A relationship-array element that is a doubled/slug username (breach
        // `full_name = "{username} {username}"`) or the "\N \N" SQL-null pair must
        // NOT be minted as a fabricated associate Person — the same guard the
        // subject-name path applies. A real associate in the same array survives.
        let item = json!({
            "known_associates": ["rhino-ryno23 rhino-ryno23", "\\N \\N", "Jane Smith"],
        });
        let mut seen = HashSet::new();
        let mut result = ModuleResult::new();
        extract_associates(&item, "Kyle Diegmann", "s", "fp", &mut seen, &mut result);

        let names: std::collections::BTreeSet<&str> = result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Person)
            .map(|e| e.value.as_str())
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n.eq_ignore_ascii_case("rhino-ryno23 rhino-ryno23")),
            "doubled-username associate must be rejected, not minted as a Person"
        );
        assert!(
            names.contains("Jane Smith"),
            "a real associate in the same array is unaffected"
        );
        assert_eq!(names.len(), 1, "only the legitimate associate survives");
    }
}
