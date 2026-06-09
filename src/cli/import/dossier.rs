//! Parser for the breach/dossier compilation import format. Shared helpers (ImportStats,
//! persistence, geo/key construction) live in `super` and are reached via
//! `use super::*`.

use super::*;

/// Which `-> value` list a run of lines belongs to.
#[derive(PartialEq, Clone, Copy)]
enum DossierSection {
    None,
    Usernames,
    Emails,
    Passwords,
}

/// Parse a breach/dossier compilation into individualised, correlated entities.
///
/// Two structures are recognised and both preserved in full:
///   * `Entry #N:` blocks of `• key: value` fields (username/email/name/_domain/
///     id/created/updated/language/hash/birthdate/country/gender). Every field
///     in an entry is attached as evidence to *each* entity the entry yields, so
///     the email, username and person stay correlated and carry the complete,
///     verifiable record (birthdate/country/gender included) — never a fragment.
///   * `USERNAMES:` / `EMAILS:` / `PASSWORDS:` sections of `-> value` lines, the
///     aggregate identifier lists. Dedup by UID folds these into the per-entry
///     entities where they overlap.
///
/// Pure (no I/O) so it is unit-testable; `cmd_import_dossier` does the output.
pub(super) fn parse_dossier(
    body: &str,
    sid: &str,
) -> (Vec<crate::core::entity::Entity>, ImportStats) {
    use std::collections::HashSet;

    let mut entities = Vec::new();
    let mut stats = ImportStats::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut section = DossierSection::None;
    let mut entry: Vec<(String, String)> = Vec::new();

    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        // Section header — an all-caps label ending in ':' with no value.
        if let Some(label) = line.strip_suffix(':') {
            let sect = match label.trim() {
                "USERNAMES" => Some(DossierSection::Usernames),
                "EMAILS" => Some(DossierSection::Emails),
                "PASSWORDS" | "HASHES" => Some(DossierSection::Passwords),
                _ => None,
            };
            if let Some(s) = sect {
                emit_dossier_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);
                section = s;
                continue;
            }
        }

        // `Entry #N:` header begins a fresh record.
        if line.starts_with("Entry #") {
            emit_dossier_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);
            section = DossierSection::None;
            continue;
        }

        // `-> value` list item under the current section.
        if let Some(val) = line.strip_prefix("->").map(str::trim) {
            if !val.is_empty() {
                emit_dossier_list_item(section, val, sid, &mut entities, &mut stats, &mut seen);
            }
            continue;
        }

        // `• key: value` (or bare `key: value`) field — accumulate into the entry.
        let field = line.trim_start_matches('\u{2022}').trim();
        if let Some((k, v)) = field.split_once(':') {
            let key = k.trim().trim_start_matches('_').to_ascii_lowercase();
            let val = v.trim();
            // Only accept the known field keys so a stray "http://…: x" or prose
            // colon doesn't pollute the record.
            const FIELDS: &[&str] = &[
                "username",
                "email",
                "name",
                "domain",
                "ip",
                "id",
                "created",
                "updated",
                "language",
                "hash",
                "birthdate",
                "country",
                "gender",
                "phone",
            ];
            if !val.is_empty() && FIELDS.contains(&key.as_str()) {
                entry.push((key, val.to_string()));
                continue;
            }
        }

        // A bare top-level URL (e.g. the LinkedIn profile heading the file).
        if (line.starts_with("http://") || line.starts_with("https://"))
            && seen.insert(format!("u:{line}"))
        {
            let mut e = crate::core::entity::Entity::new(
                crate::core::entity::EntityKind::Url,
                line,
                0.55,
                sid,
            );
            e.tag("import");
            e.tag("dossier");
            entities.push(e);
            stats.urls += 1;
        }
    }
    // Flush the final entry.
    emit_dossier_entry(&mut entry, sid, &mut entities, &mut stats, &mut seen);

    (entities, stats)
}

/// Emit the entities for one accumulated `Entry #N` record, attaching the FULL
/// record as evidence to each so the data stays correlated and verifiable.
fn emit_dossier_entry(
    entry: &mut Vec<(String, String)>,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
    seen: &mut std::collections::HashSet<String>,
) {
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::validation::is_fragment_value;
    if entry.is_empty() {
        return;
    }
    let get = |k: &str| {
        entry
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.as_str())
    };
    let email = get("email");
    let username = get("username");
    let name = get("name");
    let hash = get("hash");

    // One evidence record carrying every field of the entry — cloned onto each
    // entity so the complete record (birthdate/country/gender/created/id/hash/…)
    // travels with the email, the username and the person alike.
    let label = email.or(name).or(username).unwrap_or("breach entry");
    let mut ev = Evidence::new("import:dossier", format!("Breach dossier entry — {label}"));
    for (k, v) in entry.iter() {
        // Don't echo a raw password hash into a human-readable attribute under a
        // benign name; it's surfaced as its own Credential entity below.
        if k != "hash" {
            ev = ev.with_attr(k, v);
        }
    }

    let mut push = |mut e: Entity, tag: &str| {
        e.tag("import");
        e.tag("dossier");
        e.tag(tag);
        e.add_evidence(ev.clone());
        entities.push(e);
    };

    if let Some(em) = email {
        let em = em.to_ascii_lowercase();
        if em.contains('@')
            && !is_fragment_value(&EntityKind::Email, &em)
            && seen.insert(format!("em:{em}"))
        {
            push(Entity::new(EntityKind::Email, &em, 0.72, sid), "breach");
            stats.emails += 1;
        }
    }
    if let Some(un) = username
        && un.len() >= 2
        && !un.contains('@')
        && seen.insert(format!("un:{}", un.to_lowercase()))
    {
        push(Entity::new(EntityKind::Username, un, 0.60, sid), "breach");
        stats.usernames += 1;
    }
    if let Some(nm) = name {
        // A real person name: at least two words, not a placeholder.
        if nm.split_whitespace().count() >= 2
            && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, nm)
            && seen.insert(format!("pn:{}", nm.to_lowercase()))
        {
            push(Entity::new(EntityKind::Person, nm, 0.62, sid), "breach");
            stats.persons += 1;
        }
    }
    if let Some(h) = hash {
        // A password hash is an inherently-unique credential artifact (bcrypt
        // `$2a$…`, hex digests). Keep it as a Credential, never a plaintext
        // Password, and tie it to THIS record. Crucially, do NOT value-dedup the
        // credential across entries here: when the same hash recurs under a
        // different email, that recurrence IS the signal — a reused secret across
        // separate accounts (AU-047). Emit it per entry carrying this entry's
        // evidence; `deduplicate_by_uid` then MERGES the duplicates into one
        // credential that retains every record (each entry's email), so the
        // cross-account reuse is preserved instead of silently collapsed.
        if h.len() >= 8 {
            // Count distinct hashes for the stats line (entity dedup is by uid
            // downstream), but always emit so reuse evidence accumulates.
            if seen.insert(format!("cr:{h}")) {
                stats.credentials += 1;
            }
            push(
                Entity::new(EntityKind::Credential, h, 0.60, sid),
                "password-hash",
            );
        }
    }
    // A dossier entry's `ip` / `phone` / `domain` are first-class pivotable seeds,
    // not just evidence attributes — the whole point of expansion is to re-scan
    // them. The JSON importer already emits IpAddress from `ip`; the text path
    // must match, or the same breach record yields fewer leads depending only on
    // its file format. Each is validated so malformed/placeholder values
    // ("256.256.256.256", "+0…") don't become high-confidence false seeds.
    if let Some(ip) = get("ip")
        && ip.parse::<std::net::IpAddr>().is_ok()
        && !crate::core::validation::is_bogus_ip(ip)
        && seen.insert(format!("ip:{ip}"))
    {
        push(Entity::new(EntityKind::IpAddress, ip, 0.65, sid), "breach");
        stats.ips += 1;
    }
    if let Some(ph) = get("phone")
        && crate::core::validation::validate_phone_e164(ph).valid
        && seen.insert(format!("ph:{ph}"))
    {
        push(Entity::new(EntityKind::Phone, ph, 0.62, sid), "breach");
        stats.phones += 1;
    }
    // A dossier's `address` is the strongest associate-pivot seed there is: the
    // residence that ties a person to the people they live with. Promote it from
    // a buried evidence attribute to a first-class Address entity so it surfaces
    // in Browse, feeds the validated-address / co-location rules, and lets the
    // shared-address association rule (AU-049) cluster co-residents into a
    // household. Gated on specificity — a bare country/state ("USA") names a
    // region thousands of strangers share and would fabricate a household, so we
    // require a street-number signal (a digit) and ≥3 tokens before emitting.
    if let Some(addr) = get("address")
        && crate::core::validation::is_specific_residence(addr)
        && seen.insert(format!("ad:{}", addr.to_ascii_lowercase()))
    {
        push(Entity::new(EntityKind::Address, addr, 0.58, sid), "breach");
        stats.addresses += 1;
    }
    // A dossier's `_domain` is usually the email's OWN host (gmail.com) —
    // freemail/mega-domains are useless pivots (deep-expanding them maps a
    // platform, not the subject), so gate them out exactly as the engine's
    // expansion does. A genuine corporate domain still becomes a seed.
    if let Some(dom) = get("domain").map(str::to_ascii_lowercase)
        && dom.contains('.')
        && !crate::util::domains::is_freemail(&dom)
        && !crate::core::scan::is_mega_domain(&dom)
        && !crate::core::validation::is_placeholder_domain(&dom)
        && !is_fragment_value(&EntityKind::Domain, &dom)
        && seen.insert(format!("dom:{dom}"))
    {
        push(Entity::new(EntityKind::Domain, &dom, 0.60, sid), "breach");
        stats.domains += 1;
    }
    entry.clear();
}

/// Emit an entity for a single `-> value` line under a `USERNAMES:`/`EMAILS:`/
/// `PASSWORDS:` section.
fn emit_dossier_list_item(
    section: DossierSection,
    val: &str,
    sid: &str,
    entities: &mut Vec<crate::core::entity::Entity>,
    stats: &mut ImportStats,
    seen: &mut std::collections::HashSet<String>,
) {
    use crate::core::entity::{Entity, EntityKind};
    use crate::core::validation::is_fragment_value;
    let mut push = |e: Entity, key: String| {
        if seen.insert(key) {
            let mut e = e;
            e.tag("import");
            e.tag("dossier");
            e.tag("dossier-list");
            entities.push(e);
            return true;
        }
        false
    };
    match section {
        DossierSection::Emails => {
            let em = val.to_ascii_lowercase();
            if em.contains('@') && !is_fragment_value(&EntityKind::Email, &em) {
                let e = Entity::new(EntityKind::Email, &em, 0.55, sid);
                if push(e, format!("em:{em}")) {
                    stats.emails += 1;
                }
            }
        }
        DossierSection::Usernames => {
            // A username list can contain bare emails too — classify by shape.
            if val.contains('@') {
                let em = val.to_ascii_lowercase();
                if !is_fragment_value(&EntityKind::Email, &em) {
                    let e = Entity::new(EntityKind::Email, &em, 0.50, sid);
                    if push(e, format!("em:{em}")) {
                        stats.emails += 1;
                    }
                }
            } else if val.len() >= 2 {
                let e = Entity::new(EntityKind::Username, val, 0.50, sid);
                if push(e, format!("un:{}", val.to_lowercase())) {
                    stats.usernames += 1;
                }
            }
        }
        DossierSection::Passwords => {
            if val.len() >= 8 {
                let e = Entity::new(EntityKind::Credential, val, 0.50, sid);
                if push(e, format!("cr:{val}")) {
                    stats.credentials += 1;
                }
            }
        }
        DossierSection::None => {}
    }
}

pub(super) async fn cmd_import_dossier(body: &str, output: &str) -> Result<()> {
    note(output, "Importing breach/dossier compilation...");
    let sid = format!("import-dossier-{}", crate::core::entity::unix_now());
    let (mut entities, stats) = parse_dossier(body, &sid);
    deduplicate_by_uid(&mut entities);
    print_import_stats(&stats, entities.len(), output);

    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
