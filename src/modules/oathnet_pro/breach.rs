//! Breach-record PII extraction for OathNet results.
//!
//! Turns a breach row into Email / Username / Phone / Person / IP / Address
//! entities, gated by target-identity match (`TargetMatch`) so a name search
//! doesn't emit strangers at full confidence. The shared entity pusher
//! (`push_oathnet_entity`) lives here too. Reaches parent items via `use super::*`.

use super::*;
use crate::util::extract::CredentialField;
// ─── Entity extraction ─────────────────────────────────────────────────────

pub(super) fn breach_evidence(item: &Value) -> Evidence {
    let db = val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string());
    let mut ev = Evidence::new(SRC, format!("Breach on {db}")).with_attr("dbname", &db);
    for (field, attr) in [
        // Account join-keys — the email/username this record belongs to. The
        // reused-secret correlator (AU-047) reads these off a leaked secret's
        // evidence to tie the accounts that share it to one controller, and the
        // dossier uses them as provenance ("which account leaked this"); the
        // breach evidence previously omitted them, starving the correlator of the
        // primary source's join-keys.
        ("email", "email"),
        ("username", "username"),
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
pub(super) fn push_oathnet_entity(
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

/// Build the subject's breach **dossier** entity from the rows that matched the
/// subject identity, or `None` when the subject does not appear in the page.
///
/// A broad search — above all a `full_name` — returns a page of strangers. The
/// engine pre-inserts a seed anchor for the subject, so minting a 0.85
/// `breach`-tagged parent off a ZERO-match page merged a false "breach hit" —
/// and an aggregate dump of every stranger's name/country/DOB — straight onto
/// that anchor. Gating on a real match keeps the subject's headline node honest,
/// and aggregating identity attributes over the MATCHING rows ONLY (never the
/// whole stranger-laden page) means the dossier reflects the subject's own
/// records. Attributes are aggregated additively (order-preserving, deduplicated)
/// so multiple hits and aliases are all retained, never overwritten.
pub(super) fn breach_parent_entity(
    target: &Target,
    scan_id: &str,
    matching: &[Value],
    total_returned: usize,
) -> Option<Entity> {
    if matching.is_empty() {
        return None;
    }
    let match_count = matching.len();
    let top_dbs = oathnet::top_dbnames(matching, 5);
    let countries = oathnet::distinct_field(matching, "country");
    let names = oathnet::distinct_field(matching, "full_name");
    let genders = oathnet::distinct_field(matching, "gender");
    let dobs = oathnet::distinct_field(matching, "date_birth");
    // Dossier-level credential-exposure signal: how many of the subject's own
    // records leaked a fast, GPU-trivial hash (≈ plaintext once cracked).
    let fast_hashes = matching
        .iter()
        .filter_map(|i| val_str(i, "password_hash"))
        .filter(|h| identify_password_hash(h).is_some_and(|(_, fast)| fast))
        .count();

    let mut parent = target.to_entity(0.85, scan_id);
    parent.tag(tags::BREACH);
    parent.tag("oathnet-pro");
    let mut ev = Evidence::new(
        SRC,
        format!(
            "OathNet: {match_count} matching breach record(s) of {total_returned} — {}",
            top_dbs.join(", ")
        ),
    )
    .with_attr("hits", match_count.to_string())
    .with_attr("records_returned", total_returned.to_string())
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
    if fast_hashes > 0 {
        ev = ev.with_attr("fast_crackable_hashes", fast_hashes.to_string());
    }
    parent.add_evidence(ev);
    Some(parent)
}

/// Extract a full page of breach records into entities, enforcing the
/// candidate-flood cap.
///
/// Each row's target-match decision is precomputed by the caller (one pass that
/// also feeds [`breach_parent_entity`]), passed in as `row_matches` aligned to
/// `items`. Target-matching rows are always extracted in full; non-matching
/// strangers are only sampled — at most `MAX_CANDIDATE_ROWS` of them — so a
/// broad `full_name` search that returns a whole page of unrelated people can't
/// drown a memory-constrained device in low-value `candidate` entities. API-key
/// harvesting (`store_api_credential` + `extract_api_keys_from_item`) runs
/// unconditionally for every row: a leaked tool credential is valuable
/// independent of whether the row identifies the target, and such keys are rare
/// enough never to flood.
pub(super) fn extract_breach_page(
    items: &[Value],
    row_matches: &[bool],
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    debug_assert_eq!(
        items.len(),
        row_matches.len(),
        "row_matches must be aligned 1:1 with items"
    );
    result.entities.reserve(items.len());
    let mut candidate_rows = 0usize;
    for (item, &is_target_row) in items.iter().zip(row_matches) {
        // Target rows always extract; strangers only up to the cap.
        if is_target_row {
            extract_breach_entities_with(item, true, scan_id, key_fp, seen, result);
        } else if candidate_rows < MAX_CANDIDATE_ROWS {
            candidate_rows += 1;
            extract_breach_entities_with(item, false, scan_id, key_fp, seen, result);
        }
        // Unconditional — independent of the candidate cap and the target
        // match (see the doc comment), kept after PII extraction to preserve
        // the original per-row ordering.
        store_api_credential(item);
        extract_api_keys_from_item(item, scan_id, seen, result);
    }
}

#[cfg(test)]
pub(super) fn extract_breach_entities(
    item: &Value,
    target_value: &str,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let is_target_row = TargetMatch::new(target_value).matches(item);
    extract_breach_entities_with(item, is_target_row, scan_id, key_fp, seen, result);
}

pub(super) fn extract_breach_entities_with(
    item: &Value,
    is_target_row: bool,
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

    // `is_target_row` (computed once per row by the caller via `TargetMatch`)
    // decides whether this record belongs to the target. Breach databases hold
    // millions of records and a broad search — above all a `full_name` —
    // returns rows for many different people. A non-matching row is NOT
    // discarded here: `push_oathnet_entity` demotes it to a quarantined
    // `candidate` (out of the default view and the correlator) so genuine leads
    // survive without flooding the result with strangers.

    if let Some(email) = val_str(item, "email") {
        let lower = email.to_lowercase();
        if looks_like_email(&lower) && seen.insert(lower) {
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
        && has_min_digits(&ph, 7)
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

    // Login IPs — the session `ip` AND the last-login `lastip`/`last_ip` are
    // both geolocation leads tied to the account. snusbase-style records carry
    // only `lastip`, so reading `ip` alone dropped the subject's login location;
    // each distinct public address becomes its own lead.
    for ip_field in ["ip", "lastip", "last_ip"] {
        if let Some(ip) = val_str(item, ip_field)
            && is_public_ip(&ip)
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
        if crate::util::domains::looks_like_domain(&lower)
            && seen.insert(format!("@edomain:{lower}"))
        {
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
        // Hash intelligence: classify the algorithm + crackability so the dossier
        // ranks credential exposure. A present, non-empty `salt` field defeats
        // rainbow tables even for an otherwise-fast hash.
        let hash_id = identify_password_hash(&ph);
        let algo_tag = hash_id.map(|(a, _)| format!("hash:{a}"));
        let mut extra: Vec<&str> = vec!["password-hash"];
        if let Some(a) = &algo_tag {
            extra.push(a);
        }
        if let Some((_, fast)) = hash_id {
            extra.push(if fast {
                "crackable:fast"
            } else {
                "crackable:slow"
            });
        }
        // A salt defeats rainbow tables even for a fast hash. It arrives either as
        // a dedicated `salt` field (Snusbase) or appended to the digest (OathNet:
        // `"2f43… _:=j…"`, `"b3dd…,:xpay"`). Detect the appended form as a bare-hex
        // digest with a non-empty remainder past the first separator — a prefixed
        // KDF ($argon2/$2a$/…) carries its own salt, is already classified slow,
        // and its option commas must not be misread as a salt separator.
        let appended_salt = ph.trim().starts_with(|c: char| c.is_ascii_hexdigit())
            && ph
                .trim()
                .split_once([' ', '\t', ':', ',', ';', '|'])
                .is_some_and(|(digest, rest)| {
                    digest.bytes().all(|b| b.is_ascii_hexdigit()) && !rest.trim().is_empty()
                });
        if appended_salt || val_str(item, "salt").is_some_and(|s| !s.trim().is_empty()) {
            extra.push("salted");
        }
        push_oathnet_entity(
            result,
            Entity::new(EntityKind::Password, &ph, 0.50, scan_id),
            &ev,
            &extra,
            is_target_row,
        );
    }

    // Plaintext password → first-class Password entity: the canonical secret the
    // reused-secret correlator (AU-047) and credential-exposure rule (AU-037)
    // operate on, which the breach extractor never emitted (only the hash). The
    // per-account dedup key lets the same password under two accounts survive as
    // two same-value entities that merge by UID into one carrying both accounts'
    // evidence — exactly the ≥2-account signal AU-047 fires on. Redacted
    // sentinels and trivial (single-character / too-short) values are skipped.
    if let Some(pw) = val_str(item, "password") {
        let p = pw.trim();
        match crate::util::extract::classify_credential_field(p) {
            // A capture sentinel ([fail], UPGRADE_TO_SEE…) is not a secret — drop it.
            CredentialField::Sentinel => {}
            // An email mis-stored in the password slot is a lead, not a secret:
            // minting it as a Password would forge a reused-secret link across every
            // row with the same quirk. Recover it into the email pipeline instead,
            // at modest confidence (the field placement is itself suspect).
            CredentialField::Email => {
                let lower = p.to_lowercase();
                if seen.insert(format!("@pw-email:{lower}")) {
                    push_oathnet_entity(
                        result,
                        Entity::new(EntityKind::Email, p, 0.45, scan_id),
                        &ev,
                        &["recovered-from-password"],
                        is_target_row,
                    );
                }
            }
            CredentialField::Secret => {
                let len = p.chars().count();
                let first = p.chars().next();
                let varied = p.chars().any(|c| Some(c) != first);
                let acct = val_str(item, "email")
                    .or_else(|| val_str(item, "username"))
                    .unwrap_or_default()
                    .to_lowercase();
                if (6..=128).contains(&len)
                    && varied
                    && seen.insert(format!("@pw:{}:{acct}", p.to_lowercase()))
                {
                    push_oathnet_entity(
                        result,
                        Entity::new(EntityKind::Password, p, 0.55, scan_id),
                        &ev,
                        &["plaintext-password"],
                        is_target_row,
                    );
                }
            }
        }
    }

    // IBAN — a leaked bank-account number. Emit ONLY when the ISO 7064 mod-97
    // check digit validates, so a redacted sentinel or a transcription error in
    // the `iban` field never mints a bogus financial artifact. There is no
    // dedicated financial EntityKind, so it lands as `Other("iban")`, tagged
    // `financial` for the dossier/export.
    if let Some(iban) = val_str(item, "iban")
        && iban_is_valid(&iban)
        && seen.insert(format!(
            "@iban:{}",
            iban.replace(|c: char| c.is_whitespace(), "").to_uppercase()
        ))
    {
        push_oathnet_entity(
            result,
            Entity::new(
                EntityKind::Other("iban".to_string()),
                iban.trim(),
                0.70,
                scan_id,
            ),
            &ev,
            &["iban", "financial"],
            is_target_row,
        );
    }

    // Additional social handles → Username pivots (mirroring the instagram
    // handler above). Each unlocks username_search / search_engines for free, so
    // extracting them squeezes more reach from a breach query already paid for.
    // Redacted sentinels and out-of-range junk are filtered.
    for (field, platform) in [
        ("telegram", "telegram"),
        ("twitter", "twitter"),
        ("snapchat", "snapchat"),
        ("facebook", "facebook"),
        ("github", "github"),
        ("tiktok", "tiktok"),
        ("reddit", "reddit"),
    ] {
        if let Some(handle) = val_str(item, field) {
            let h = handle.trim().trim_start_matches('@');
            if (2..=64).contains(&h.len())
                && !is_redacted_sentinel(h)
                && seen.insert(format!("@{platform}:{}", h.to_lowercase()))
            {
                push_oathnet_entity(
                    result,
                    Entity::new(EntityKind::Username, h, 0.55, scan_id),
                    &ev,
                    &[platform],
                    is_target_row,
                );
            }
        }
    }

    // Free-text `bio` mining — a profile bio routinely carries an alternate
    // contact email or phone the structured columns miss. Reuse the canonical
    // scanner-grade extractors (one definition of "what an email/phone looks like
    // in free text") so this never drifts from the rest of the engine. Lower
    // confidence than a structured field: these are inferred from prose.
    if let Some(bio) = val_str(item, "bio") {
        for email in crate::util::extract::emails(&bio) {
            if seen.insert(email.clone()) {
                push_oathnet_entity(
                    result,
                    Entity::new(EntityKind::Email, &email, 0.55, scan_id),
                    &ev,
                    &["bio-mined"],
                    is_target_row,
                );
            }
        }
        for phone in crate::util::extract::phones(&bio) {
            if seen.insert(format!("@bio-phone:{phone}")) {
                push_oathnet_entity(
                    result,
                    Entity::new(EntityKind::Phone, &phone, 0.50, scan_id),
                    &ev,
                    &["bio-mined"],
                    is_target_row,
                );
            }
        }
    }
}
