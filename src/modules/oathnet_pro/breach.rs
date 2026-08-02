//! Breach-record PII extraction for OathNet results.
//!
//! Turns a breach row into Email / Username / Phone / Person / IP / Address
//! entities, gated by target-identity match (`TargetMatch`) so a name search
//! doesn't emit strangers at full confidence. The shared entity pusher
//! (`push_oathnet_entity`) lives here too. Reaches parent items via `use super::*`.

use super::*;
use crate::core::confidence;
use crate::util::extract::CredentialField;

/// True for a value that is really an absence sentinel (`\N`, `NULL`, an empty/
/// whitespace string, a redaction placeholder), not a datum — the SAME guard
/// SeekNow/breach_rich already apply (`breach_rich::is_absent_marker`). Gating
/// an emission on it stops a breach page where many rows carry `\N` employer or
/// `NULL` country/location from minting one shared node that fuses all those
/// unrelated strangers together — a false positive, the worst kind for an
/// evidentiary tool.
fn is_absent(s: &str) -> bool {
    crate::util::json::is_null_sentinel(s) || crate::util::extract::is_placeholder_secret(s)
}
// ─── Entity extraction ─────────────────────────────────────────────────────

pub(super) fn breach_evidence(item: &Value) -> Evidence {
    let db = val_str(item, "dbname").unwrap_or_else(|| "unknown".to_string());
    let mut ev = Evidence::new(SRC, format!("Breach on {db}")).with_attr("dbname", &db);
    for (field, attr) in [
        // The breach's own occurrence date — `util::oathnet::search` additively
        // stamps this onto the row from the response's sibling `dbname_info`
        // block (keyed by this row's own `dbname`) when the row doesn't already
        // carry one. Every entity built from this evidence is `breach`-tagged, so
        // this is the canonical `breach_date` key AU-019's temporal breach-
        // cluster rule (`rules/breach.rs`) reads — without it, oathnet-sourced
        // hits (a paid, high-quality breach source) could never date-cluster
        // with HIBP/IntelX/xposed_or_not/psbdmp/niamonx/hudsonrock.
        ("breach_date", "breach_date"),
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
        ("employer", "employer"),
        ("company", "employer"),
        ("organization", "employer"),
        ("organisation", "employer"),
        ("workplace", "employer"),
        ("discordid", "discord_id"),
        ("instagram", "instagram"),
        ("linkedin", "linkedin"),
        ("iban", "iban"),
        // Australian government identifiers + stated relationships, so the
        // breach-PII correlators (AU-073/074/075) see them when a dump carries
        // them. Source-name variants normalise to the canonical key each rule
        // scans for; absent fields are simply skipped, so these are inert on a
        // record that doesn't include them.
        ("tfn", "tfn"),
        ("tax_file_number", "tfn"),
        ("medicare", "medicare"),
        ("medicare_number", "medicare"),
        ("crn", "crn"),
        ("centrelink_crn", "crn"),
        ("drivers_license", "drivers_licence"),
        ("driver_license", "drivers_licence"),
        ("license_number", "drivers_licence"),
        ("passport", "passport"),
        ("passport_number", "passport"),
        ("spouse", "spouse"),
        ("partner", "partner"),
        ("next_of_kin", "next_of_kin"),
        ("emergency_contact", "emergency_contact"),
    ] {
        // Coerce numbers: breach dumps encode `postal_code`/`account_id`/`discordid`
        // (and occasionally `date_birth`) as JSON ints, which the string-only read
        // silently dropped from the evidence the correlators key on.
        if let Some(v) = val_str_coerce(item, field) {
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

    // Stamp the grouping attributes the household/associate correlators read off a
    // Person's evidence — AU-049 (household), AU-050 (shared phone line), AU-051
    // (same-surname kin) — so those cluster pivots fire on LIVE breach scans, not
    // only on hand-imported text dossiers. The separate Phone / Address *entities*
    // minted below are geo/pivot nodes; the clustering rules key off these evidence
    // attrs (see `core::correlator::rules::assoc::{entity_phones,entity_residences}`).
    if let Some(phone) = val_str_or_coerce(item, &["phone_number", "phone_national", "phone"]) {
        ev = ev.with_attr("phone", &phone);
    }
    // The `address` attr is stamped only for a STREET-anchored residence: a bare
    // city/postcode names a region thousands of people share and clustering on it
    // would fuse strangers into a false household (the `is_specific_residence`
    // residence gate AU-049/051 apply mirrors this intent). When a street is
    // present the composed value is identical to the standalone Address entity's,
    // so a Person's residence key aligns with that anchor node.
    if let Some(street) = val_str(item, "address_street") {
        let parts = [
            Some(street),
            val_str_coerce(item, "city"),
            val_str_coerce(item, "state"),
            val_str_coerce(item, "postal_code"),
        ];
        let addr = parts
            .iter()
            .flatten()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>()
            .join(", ");
        if !addr.is_empty() {
            ev = ev.with_attr("address", &addr);
        }
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
    // (Source-sector tagging is applied universally at engine admission —
    // `core::engine::enrich::tag_breach_sector` — for EVERY breach pool, so it
    // is not done per-module here.)
    // Quarantine policy, enforced in ONE place: a row that doesn't match the
    // target identity yields CANDIDATE-strength, `candidate`-tagged entities, so
    // EVERY breach-derived kind — email, username, domain, social handle — is
    // gated uniformly (the prior code gated only phone/person/ip, letting a name
    // search emit hundreds of strangers' emails/domains at full 0.70). The
    // demotion semantics are the shared `Entity::demote_to_candidate`.
    if !is_target_row {
        e.demote_to_candidate();
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
#[must_use]
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

    let mut parent = target.to_entity(confidence::HIGH_PLUSPLUS_PLUS, scan_id);
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
        store_api_credential(item, SRC);
        extract_api_keys_from_item(item, scan_id, SRC, seen, result);
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

/// Shared inputs every per-row breach-field extraction helper below needs:
/// the raw record, its evidence trail, the emission dedup set, the output
/// sink, the target-match gate, and the scan id. Bundled into one struct so
/// each helper takes a single `&mut RowCtx` instead of repeating the same
/// six parameters (and so none of them individually trips clippy's
/// too-many-arguments lint).
struct RowCtx<'a> {
    item: &'a Value,
    ev: &'a Evidence,
    seen: &'a mut HashSet<String>,
    result: &'a mut ModuleResult,
    is_target_row: bool,
    scan_id: &'a str,
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
    let mut ev = breach_evidence(item)
        .with_attr("provider", "oathnet.org")
        .with_attr("api_key_origin", key_fp);
    // Carry the row's OWN name on every entity extracted from it, so the
    // geo-corroboration re-promotion (`promote_breach_candidate_geo_corroborated`)
    // can enforce the "same name AND same place" its evidence text asserts. A
    // breach candidate is a NON-target-matched (namesake) row, so promoting one
    // on locality alone fuses a same-metro stranger's leaked identifiers onto the
    // subject; the surname gate needs the row's name to reject that. Deliberately
    // a dedicated key (NOT a `PERSON_NAME_ATTRS` key) so it feeds only the
    // promotion gate and never the person-place relation builders.
    if let Some(name) = val_str_or(
        item,
        &[
            "full_name",
            "display_name",
            "name",
            "nickname",
            "real_name",
            "realname",
        ],
    ) {
        let name = name.trim();
        if name.len() >= 2 {
            ev = ev.with_attr("breach_row_name", name);
        }
    }
    let ev = ev;

    // `is_target_row` (computed once per row by the caller via `TargetMatch`)
    // decides whether this record belongs to the target. Breach databases hold
    // millions of records and a broad search — above all a `full_name` —
    // returns rows for many different people. A non-matching row is NOT
    // discarded here: `push_oathnet_entity` demotes it to a quarantined
    // `candidate` (out of the default view and the correlator) so genuine leads
    // survive without flooding the result with strangers.

    let mut ctx = RowCtx {
        item,
        ev: &ev,
        seen,
        result,
        is_target_row,
        scan_id,
    };
    extract_contact_fields(&mut ctx);
    extract_login_ip_fields(&mut ctx);
    extract_location_fields(&mut ctx);
    extract_social_handles(&mut ctx);
    extract_org_and_domain_fields(&mut ctx);
    extract_credential_fields(&mut ctx);
    extract_iban_field(&mut ctx);
    extract_additional_social_handles(&mut ctx);
    extract_bio_mined_fields(&mut ctx);
}

/// Email / username / phone / person-name — the record's core identity
/// fields.
fn extract_contact_fields(ctx: &mut RowCtx) {
    if let Some(email) = val_str(ctx.item, "email") {
        let lower = email.to_lowercase();
        if looks_like_email(&lower) && ctx.seen.insert(lower) {
            push_oathnet_entity(
                ctx.result,
                Entity::new(
                    EntityKind::Email,
                    &email,
                    confidence::HIGH_PLUS,
                    ctx.scan_id,
                ),
                ctx.ev,
                &[],
                ctx.is_target_row,
            );
        }
    }

    if let Some(uname) = val_str(ctx.item, "username") {
        let lower = uname.to_lowercase();
        if lower.len() >= 3 && ctx.seen.insert(lower) {
            push_oathnet_entity(
                ctx.result,
                Entity::new(EntityKind::Username, &uname, confidence::HIGH, ctx.scan_id),
                ctx.ev,
                &[],
                ctx.is_target_row,
            );
        }
    }

    if let Some(ph) = val_str_or_coerce(ctx.item, &["phone_number", "phone_national", "phone"])
        && has_min_digits(&ph, 7)
        && ctx.seen.insert(ph.to_lowercase())
    {
        push_oathnet_entity(
            ctx.result,
            Entity::new(EntityKind::Phone, &ph, confidence::HIGH_PLUS, ctx.scan_id),
            ctx.ev,
            &[],
            ctx.is_target_row,
        );
    }

    if let Some(n) = val_str_or(
        ctx.item,
        &[
            "full_name",
            "display_name",
            "name",
            "nickname",
            "real_name",
            "realname",
        ],
    ) {
        let t = n.trim();
        // Some breach databases store `full_name = "{username} {username}"`
        // when no real name is available (previously observed live: a
        // scan seeded on this field emitted `Person("rhino-ryno23
        // rhino-ryno23")`, which the engine expanded into a 123-entity,
        // 94%-noise child scan) — reject that shape before it ever reaches
        // the graph.
        if t.len() >= 4
            && t.contains(' ')
            && !is_username_derived_name(t)
            && ctx.seen.insert(t.to_lowercase())
        {
            // Parity with SeekNow: stamp the record's demographics (DOB / gender
            // / age) as normalized first-class tags on the Person, so OathNet's
            // subject nodes filter/merge on the same signals SeekNow's do.
            let id_tags = crate::util::identity::identity_tags(ctx.item);
            let id_refs: Vec<&str> = id_tags.iter().map(String::as_str).collect();
            push_oathnet_entity(
                ctx.result,
                Entity::new(EntityKind::Person, t, confidence::HIGH_PLUS, ctx.scan_id),
                ctx.ev,
                &id_refs,
                ctx.is_target_row,
            );
        }
    }
}

/// Login IPs — the session `ip` AND the last-login `lastip`/`last_ip` are
/// both geolocation leads tied to the account. snusbase-style records carry
/// only `lastip`, so reading `ip` alone dropped the subject's login location;
/// each distinct public address becomes its own lead.
fn extract_login_ip_fields(ctx: &mut RowCtx) {
    for ip_field in ["ip", "lastip", "last_ip"] {
        if let Some(ip) = val_str(ctx.item, ip_field)
            && is_public_ip(&ip)
            && ctx.seen.insert(ip.clone())
        {
            push_oathnet_entity(
                ctx.result,
                Entity::new(
                    EntityKind::IpAddress,
                    &ip,
                    confidence::MEDIUM_PLUS,
                    ctx.scan_id,
                ),
                ctx.ev,
                &["geolocation-lead"],
                ctx.is_target_row,
            );
        }
    }
}

/// Country, structured street/city/state/postal, and free-text `location` —
/// each becomes an Address (plus an inline geocoded Coordinates when
/// resolvable).
fn extract_location_fields(ctx: &mut RowCtx) {
    if let Some(country) = val_str(ctx.item, "country")
        && !is_absent(&country)
        && ctx.seen.insert(format!("@country:{country}"))
    {
        if let Some((lat, lon)) = crate::util::city_coords::city_coords(&country) {
            let coord_val = format!("{lat:.4},{lon:.4}");
            let mut c = Entity::new(
                EntityKind::Coordinates,
                &coord_val,
                confidence::LOW_MEDIUM,
                ctx.scan_id,
            );
            c.tag("addr-derived");
            c.tag("geoint");
            c.tag("breach");
            c.tag("oathnet-pro");
            if !ctx.is_target_row {
                c.demote_to_candidate();
            }
            c.add_evidence(ctx.ev.clone());
            ctx.result.push(c);
        }
        push_oathnet_entity(
            ctx.result,
            Entity::new(
                EntityKind::Address,
                &country,
                confidence::MEDIUM_HIGH,
                ctx.scan_id,
            ),
            ctx.ev,
            &[],
            ctx.is_target_row,
        );
    }

    let street = val_str(ctx.item, "address_street");
    let city = val_str_coerce(ctx.item, "city");
    let state = val_str_coerce(ctx.item, "state");
    // Include the postal code in the composed value (the breach record carries it
    // — e.g. `23666` for HAMPTON, VA). A postcode-qualified address geocodes to
    // the ZIP centroid instead of the whole city, the precision the downstream
    // geocode + geo-correlation chain depends on; it was previously kept only on
    // the evidence. Postcode alone never forms an address — the city/street gate
    // still guards that — so a bare ZIP can't mint a useless node.
    let postal = val_str_coerce(ctx.item, "postal_code");
    if city.is_some() || street.is_some() {
        let addr = [
            street.as_deref(),
            city.as_deref(),
            state.as_deref(),
            postal.as_deref(),
        ]
        .iter()
        .flatten()
        .map(|s| s.trim())
        // `val_str` rejects empty strings but not whitespace-only ones, so trim
        // each part and drop any that collapse to nothing — otherwise a blank
        // `state`/`postal` would leave a `", ,"` gap or a trailing `", "` in the
        // composed value and degrade geocoding. Also drop an absence sentinel
        // (`\N`/`NULL`/redaction) part so it can't fuse strangers into one address.
        .filter(|s| !s.is_empty() && !is_absent(s))
        .collect::<Vec<&str>>()
        .join(", ");
        if addr.len() >= 4 && ctx.seen.insert(format!("@addr:{}", addr.to_lowercase())) {
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(&addr) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    confidence::MEDIUM_HIGH,
                    ctx.scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("breach");
                c.tag("oathnet-pro");
                if !ctx.is_target_row {
                    c.demote_to_candidate();
                }
                c.add_evidence(ctx.ev.clone());
                ctx.result.push(c);
            }
            push_oathnet_entity(
                ctx.result,
                Entity::new(EntityKind::Address, &addr, confidence::HIGH, ctx.scan_id),
                ctx.ev,
                &[],
                ctx.is_target_row,
            );
        }
    }

    // Free-text `location` field — emitted as an Address hint when no structured
    // street/city/state address was found (or in addition to it if they differ).
    // Requires ≥4 chars to filter out empty-string variants and single tokens like
    // "US" that are already captured as the `country` evidence attribute.
    if let Some(loc) = val_str(ctx.item, "location") {
        let loc = loc.trim();
        if loc.len() >= 4
            && !is_absent(loc)
            && ctx.seen.insert(format!("@loc:{}", loc.to_lowercase()))
        {
            if let Some((lat, lon)) = crate::util::city_coords::city_coords(loc) {
                let coord_val = format!("{lat:.4},{lon:.4}");
                let mut c = Entity::new(
                    EntityKind::Coordinates,
                    &coord_val,
                    confidence::SPECULATIVE,
                    ctx.scan_id,
                );
                c.tag("addr-derived");
                c.tag("geoint");
                c.tag("breach");
                c.tag("oathnet-pro");
                if !ctx.is_target_row {
                    c.demote_to_candidate();
                }
                c.add_evidence(ctx.ev.clone());
                ctx.result.push(c);
            }
            push_oathnet_entity(
                ctx.result,
                Entity::new(EntityKind::Address, loc, confidence::LOW, ctx.scan_id),
                ctx.ev,
                &["geo-hint", "free-text-location"],
                ctx.is_target_row,
            );
        }
    }
}

/// Discord ID, SteamID64, Instagram, and LinkedIn — each unlocks a distinct
/// pivot module (discord expansion, gaming endpoints, username_search,
/// proxycurl).
fn extract_social_handles(ctx: &mut RowCtx) {
    if let Some(did) = val_str_coerce(ctx.item, "discordid")
        && ctx.seen.insert(format!("@discord:{did}"))
    {
        push_oathnet_entity(
            ctx.result,
            Entity::new(
                EntityKind::Username,
                format!("discord:{did}"),
                0.55,
                ctx.scan_id,
            ),
            ctx.ev,
            &["discord"],
            ctx.is_target_row,
        );
    }

    // SteamID64 — parity with SeekNow's identity handling. OathNet shares the
    // same V2 breach schema, so leaked SteamID64s appear here too; gate them by
    // the shared strict heuristic and mint the same `steam:<id>` Username pivot
    // (which feeds the gaming-endpoint expansion) instead of discarding them.
    if let Some(sid) = val_str_or_coerce(ctx.item, &["steam_id", "steamid", "steam_id64"])
        && crate::util::identity::looks_like_steam_id(&sid)
        && ctx.seen.insert(format!("@steam:{sid}"))
    {
        push_oathnet_entity(
            ctx.result,
            Entity::new(
                EntityKind::Username,
                format!("steam:{sid}"),
                confidence::MEDIUM_PLUS,
                ctx.scan_id,
            ),
            ctx.ev,
            &["steam"],
            ctx.is_target_row,
        );
    }

    if let Some(ig) = val_str(ctx.item, "instagram")
        && ctx.seen.insert(format!("@ig:{}", ig.to_lowercase()))
    {
        push_oathnet_entity(
            ctx.result,
            Entity::new(
                EntityKind::Username,
                &ig,
                confidence::MEDIUM_HIGH,
                ctx.scan_id,
            ),
            ctx.ev,
            &["instagram"],
            ctx.is_target_row,
        );
    }

    // LinkedIn handle — unlocks proxycurl (paid LinkedIn enrichment).
    // The field may contain a URL or a bare handle. Emit as Url if it
    // looks like a URL, else as Username with a linkedin: prefix.
    if let Some(li) = val_str(ctx.item, "linkedin") {
        let lower = li.to_lowercase();
        if lower.contains("linkedin.com") {
            if ctx.seen.insert(format!("@li:{lower}")) {
                let url_val = if lower.starts_with("http") {
                    li
                } else {
                    format!("https://{li}")
                };
                push_oathnet_entity(
                    ctx.result,
                    Entity::new(
                        EntityKind::Url,
                        &url_val,
                        confidence::MEDIUM_PLUS,
                        ctx.scan_id,
                    ),
                    ctx.ev,
                    &["linkedin"],
                    ctx.is_target_row,
                );
            }
        } else if ctx.seen.insert(format!("@li-handle:{lower}")) {
            push_oathnet_entity(
                ctx.result,
                Entity::new(
                    EntityKind::Username,
                    format!("linkedin:{li}"),
                    0.55,
                    ctx.scan_id,
                ),
                ctx.ev,
                &["linkedin"],
                ctx.is_target_row,
            );
        }
    }
}

/// Employer/company/organisation → Organisation entity, plus the account
/// email's domain → Domain entity (unlocks dns_intel/cert_intel/
/// securitytrails/wayback/cloud_storage for free).
fn extract_org_and_domain_fields(ctx: &mut RowCtx) {
    // Employer / company → Organisation entity. Breach dumps from LinkedIn,
    // dating apps, and e-commerce platforms frequently carry an employer or
    // company field. Emitting it as Organisation feeds the employer_pivot and
    // opencorporates chains — mirroring the see_know extractor.
    for k in [
        "employer",
        "company",
        "organization",
        "organisation",
        "workplace",
    ] {
        if let Some(org) = val_str(ctx.item, k) {
            let org = org.trim();
            if org.len() >= 2
                && !is_absent(org)
                && ctx
                    .seen
                    .insert(format!("@org:{}", org.to_ascii_lowercase()))
            {
                let mut oe = Entity::new(
                    EntityKind::Organisation,
                    org,
                    confidence::MEDIUM,
                    ctx.scan_id,
                );
                oe.tag("oathnet");
                oe.tag("employer-field");
                push_oathnet_entity(ctx.result, oe, ctx.ev, &[], ctx.is_target_row);
            }
        }
    }

    // Email-domain → Domain entity. The breach record carries the
    // sender/account email's host as a dedicated field. Emitting it
    // unlocks dns_intel/cert_intel/securitytrails/wayback/cloud_storage
    // — all free modules — for that domain without further cost.
    if let Some(ed) = val_str(ctx.item, "email_domain") {
        let lower = ed.to_lowercase();
        if crate::util::domains::looks_like_domain(&lower)
            && ctx.seen.insert(format!("@edomain:{lower}"))
        {
            push_oathnet_entity(
                ctx.result,
                Entity::new(
                    EntityKind::Domain,
                    &lower,
                    confidence::MEDIUM_HIGH,
                    ctx.scan_id,
                ),
                ctx.ev,
                &["email-domain"],
                ctx.is_target_row,
            );
        }
    }
}

/// Password hash (classified + offline-cracked when possible) and plaintext
/// password — the secrets the reused-secret correlator (AU-047) and
/// credential-exposure rule (AU-037) operate on.
fn extract_credential_fields(ctx: &mut RowCtx) {
    // Password hash → seed for pwned_passwords (free k-anonymity lookup
    // confirms whether the hash is in known breach corpora). Emit as a
    // low-confidence ApiKey entity tagged for that module.
    if let Some(ph) = val_str(ctx.item, "password_hash")
        && ph.len() >= 32
        && ctx.seen.insert(format!(
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
        if appended_salt || val_str(ctx.item, "salt").is_some_and(|s| !s.trim().is_empty()) {
            extra.push("salted");
        }
        // Offline reverse-lookup: if this unsalted digest is a known common
        // password, recover the plaintext (pure, no network/GPU).
        let cracked = crate::util::hashcat::crack_common(&ph);
        if cracked.is_some() {
            extra.push("cracked");
        }
        push_oathnet_entity(
            ctx.result,
            Entity::new(EntityKind::Password, &ph, confidence::MEDIUM, ctx.scan_id),
            ctx.ev,
            &extra,
            ctx.is_target_row,
        );
        // Synergy: surface the recovered weak plaintext as a first-class node.
        if let Some(pt) = cracked
            && ctx.seen.insert(format!("@pw:{}", pt.to_lowercase()))
        {
            push_oathnet_entity(
                ctx.result,
                Entity::new(
                    EntityKind::Password,
                    pt,
                    confidence::MEDIUM_HIGH,
                    ctx.scan_id,
                ),
                ctx.ev,
                &["cracked", "weak-password", "from-hash"],
                ctx.is_target_row,
            );
        }
    }

    // Plaintext password → first-class Password entity: the canonical secret the
    // reused-secret correlator (AU-047) and credential-exposure rule (AU-037)
    // operate on, which the breach extractor never emitted (only the hash). The
    // per-account dedup key lets the same password under two accounts survive as
    // two same-value entities that merge by UID into one carrying both accounts'
    // evidence — exactly the ≥2-account signal AU-047 fires on. Redacted
    // sentinels and trivial (single-character / too-short) values are skipped.
    if let Some(pw) = val_str(ctx.item, "password") {
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
                if ctx.seen.insert(format!("@pw-email:{lower}")) {
                    push_oathnet_entity(
                        ctx.result,
                        Entity::new(EntityKind::Email, p, confidence::LOW_MEDIUM, ctx.scan_id),
                        ctx.ev,
                        &["recovered-from-password"],
                        ctx.is_target_row,
                    );
                }
            }
            CredentialField::Secret => {
                let len = p.chars().count();
                let first = p.chars().next();
                let varied = p.chars().any(|c| Some(c) != first);
                let acct = val_str(ctx.item, "email")
                    .or_else(|| val_str(ctx.item, "username"))
                    .unwrap_or_default()
                    .to_lowercase();
                if (6..=128).contains(&len)
                    && varied
                    && ctx.seen.insert(format!("@pw:{}:{acct}", p.to_lowercase()))
                {
                    push_oathnet_entity(
                        ctx.result,
                        Entity::new(
                            EntityKind::Password,
                            p,
                            confidence::MEDIUM_HIGH,
                            ctx.scan_id,
                        ),
                        ctx.ev,
                        &["plaintext-password"],
                        ctx.is_target_row,
                    );
                }
            }
        }
    }
}

/// IBAN — a leaked bank-account number. Emitted ONLY when the ISO 7064 mod-97
/// check digit validates, so a redacted sentinel or a transcription error in
/// the `iban` field never mints a bogus financial artifact. There is no
/// dedicated financial EntityKind, so it lands as `Other("iban")`, tagged
/// `financial` for the dossier/export.
fn extract_iban_field(ctx: &mut RowCtx) {
    if let Some(iban) = val_str(ctx.item, "iban")
        && iban_is_valid(&iban)
        && ctx.seen.insert(format!(
            "@iban:{}",
            iban.replace(|c: char| c.is_whitespace(), "").to_uppercase()
        ))
    {
        push_oathnet_entity(
            ctx.result,
            Entity::new(
                EntityKind::Other("iban".to_string()),
                iban.trim(),
                0.70,
                ctx.scan_id,
            ),
            ctx.ev,
            &["iban", "financial"],
            ctx.is_target_row,
        );
    }
}

/// Additional social handles → Username pivots (mirroring
/// `extract_social_handles`'s instagram handler). Each unlocks
/// username_search / search_engines for free, so extracting them squeezes
/// more reach from a breach query already paid for. Redacted sentinels and
/// out-of-range junk are filtered. Kept as its own helper (not merged into
/// `extract_social_handles`) so its entities keep landing after the org/
/// domain/credential/iban passes, exactly as the original function ordered
/// them.
fn extract_additional_social_handles(ctx: &mut RowCtx) {
    for (field, platform) in [
        ("telegram", "telegram"),
        ("twitter", "twitter"),
        ("snapchat", "snapchat"),
        ("facebook", "facebook"),
        ("github", "github"),
        ("tiktok", "tiktok"),
        ("reddit", "reddit"),
    ] {
        if let Some(handle) = val_str(ctx.item, field) {
            let h = handle.trim().trim_start_matches('@');
            if (2..=64).contains(&h.len())
                && !is_redacted_sentinel(h)
                && ctx.seen.insert(format!("@{platform}:{}", h.to_lowercase()))
            {
                push_oathnet_entity(
                    ctx.result,
                    Entity::new(
                        EntityKind::Username,
                        h,
                        confidence::MEDIUM_HIGH,
                        ctx.scan_id,
                    ),
                    ctx.ev,
                    &[platform],
                    ctx.is_target_row,
                );
            }
        }
    }
}

/// Free-text `bio` mining — a profile bio routinely carries an alternate
/// contact email or phone the structured columns miss. Reuse the canonical
/// scanner-grade extractors (one definition of "what an email/phone looks like
/// in free text") so this never drifts from the rest of the engine. Lower
/// confidence than a structured field: these are inferred from prose.
fn extract_bio_mined_fields(ctx: &mut RowCtx) {
    if let Some(bio) = val_str(ctx.item, "bio") {
        for email in crate::util::extract::emails(&bio) {
            if ctx.seen.insert(email.clone()) {
                push_oathnet_entity(
                    ctx.result,
                    Entity::new(
                        EntityKind::Email,
                        &email,
                        confidence::MEDIUM_HIGH,
                        ctx.scan_id,
                    ),
                    ctx.ev,
                    &["bio-mined"],
                    ctx.is_target_row,
                );
            }
        }
        for phone in crate::util::extract::phones(&bio) {
            if ctx.seen.insert(format!("@bio-phone:{phone}")) {
                push_oathnet_entity(
                    ctx.result,
                    Entity::new(EntityKind::Phone, &phone, confidence::MEDIUM, ctx.scan_id),
                    ctx.ev,
                    &["bio-mined"],
                    ctx.is_target_row,
                );
            }
        }
    }
}
