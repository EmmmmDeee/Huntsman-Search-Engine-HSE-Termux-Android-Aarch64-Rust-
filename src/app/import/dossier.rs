//! Parser for the breach/dossier compilation import format. Shared helpers (ImportStats,
//! persistence, geo/key construction) live in `super` and are reached via
//! `use super::*`.

use super::*;
use crate::core::confidence;

/// Which `-> value` list a run of lines belongs to.
#[derive(PartialEq, Clone, Copy)]
enum DossierSection {
    None,
    Usernames,
    Emails,
    Passwords,
    // SeekNow `CONTACT SUMMARY (KEY DATA)` aggregate sections — the deduplicated
    // identity/network/geo lists the per-entry `• key: value` blocks don't always
    // repeat. Without these the whole summary block was silently dropped.
    Names,
    Phones,
    Addresses,
    IpAddresses,
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

    // A UTF-8 BOM (the "UTF-8 with BOM" default of Excel / Notepad / many
    // exporters) is U+FEFF, which is NOT whitespace — `str::trim` leaves it on the
    // first line, turning `EMAILS:` into `\u{feff}EMAILS:`. That matches no section
    // header, so the ENTIRE first section (and its `-> value` items) was silently
    // dropped. Strip a single leading BOM once at ingest.
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);

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
                "NAMES" => Some(DossierSection::Names),
                "PHONE NUMBERS" | "PHONES" => Some(DossierSection::Phones),
                "ADDRESSES" => Some(DossierSection::Addresses),
                "IP ADDRESSES" | "IPS" => Some(DossierSection::IpAddresses),
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
                // `address` MUST be whitelisted here: `emit_dossier_entry` reads
                // `get("address")` and emits a first-class Address entity (the
                // associate/household pivot, AU-049). Without this key the field
                // was never accumulated into the entry, so that whole block was
                // dead code and every dossier address was silently dropped.
                "address",
                // Stealer-log / breach credential artifacts — first-class
                // cross-correlation join-keys for AU-047 (reused-secret identity
                // link). A plaintext `password` reused, or a `cookie`/`session`
                // token shared, across separate accounts ties them to one
                // controller. Surfaced as Credential entities below.
                "password",
                "cookie",
                "session",
                // Breach-PII correlator join-keys (AU-073/074/075): date of
                // birth (the namesake disambiguator), Australian government
                // identifiers (the critical identity-theft exposure), and stated
                // relationships. Normalised to the canonical key each rule scans.
                "date_of_birth",
                "dob",
                "tfn",
                "tax_file_number",
                "medicare",
                "medicare_number",
                "crn",
                "centrelink_crn",
                "licence",
                "license",
                "drivers_licence",
                "drivers_license",
                "passport",
                "passport_number",
                "spouse",
                "partner",
                "next_of_kin",
                "emergency_contact",
                "father",
                "mother",
                "owner_name",
                // Common spelling/aliasing variants of the above that the
                // AU-073/074/075 rules ALSO scan — without them a dump that uses
                // e.g. `birthday`, `centrelink`, or `wife` would be silently
                // dropped and the rule could never fire. Keep the parser's
                // preserve-set aligned with the rules' scan-set.
                "birth_date",
                "birthday",
                "dateofbirth",
                "born",
                "taxfilenumber",
                "tax_file_no",
                "medicare_no",
                "medicarecard",
                "centrelink",
                "customer_reference_number",
                "driver_licence",
                "driver_license",
                "licence_number",
                "license_number",
                "dl_number",
                "passport_no",
                "husband",
                "wife",
                "nextofkin",
                "emergency_contact_name",
                "parent",
                "guardian",
                "dependent",
                "relationship",
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
                confidence::MEDIUM_HIGH,
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

    // BSSID → geo seed; wallet → chain seed; leaked API key → first-class finding.
    push_macs(body, sid, "dossier", &mut entities);
    push_crypto(body, sid, "dossier", &mut entities);
    push_api_keys(body, sid, "dossier", &mut entities);
    push_ibans(body, sid, "dossier", &mut entities);
    push_ssids(body, sid, "dossier", &mut entities);
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

    let mut push = breach_entity_pusher(entities, &ev, &["dossier"]);

    if let Some(em) = email {
        let em = em.to_ascii_lowercase();
        if em.contains('@')
            && !is_fragment_value(&EntityKind::Email, &em)
            && seen.insert(format!("em:{em}"))
        {
            push(
                Entity::new(EntityKind::Email, &em, confidence::ATTRIBUTED, sid),
                "breach",
            );
            stats.emails += 1;
        }
    }
    if let Some(un) = username
        && un.len() >= 2
        && !un.contains('@')
        && seen.insert(format!("un:{}", un.to_lowercase()))
    {
        push(
            Entity::new(EntityKind::Username, un, confidence::MEDIUM_PLUS, sid),
            "breach",
        );
        stats.usernames += 1;
    }
    if let Some(nm) = name {
        // A real person name: at least two words, not a placeholder.
        if nm.split_whitespace().count() >= 2
            && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, nm)
            && seen.insert(format!("pn:{}", nm.to_lowercase()))
        {
            push(
                Entity::new(EntityKind::Person, nm, confidence::NOTABLE, sid),
                "breach",
            );
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
                Entity::new(EntityKind::Credential, h, confidence::MEDIUM_PLUS, sid),
                "password-hash",
            );
        }
    }
    // Plaintext credential reuse and session/cookie tokens are first-class
    // cross-correlation join-keys (AU-047): the same high-entropy password, or
    // the same session token, across separate accounts ties them to one
    // controller — and stealer-log compilations carry exactly these. Emit each
    // as a Credential carrying THIS entry's full evidence (so the implicated
    // email travels with it) and — exactly like the hash above — never
    // value-dedup here, so reuse across entries survives to the uid-merge that
    // gathers every account's email onto the one secret. AU-047's entropy gate
    // decides linkability; a weak/common password is recorded but links nobody.
    for (field, tag, min_len) in [
        ("password", "plaintext-credential", 6usize),
        ("cookie", "session-token", 12usize),
        ("session", "session-token", 12usize),
    ] {
        if let Some(v) = get(field)
            && v.chars().count() >= min_len
        {
            if seen.insert(format!("cr:{v}")) {
                stats.credentials += 1;
            }
            push(
                Entity::new(EntityKind::Credential, v, confidence::MEDIUM_HIGH, sid),
                tag,
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
        push(
            Entity::new(EntityKind::IpAddress, ip, confidence::HIGH, sid),
            "breach",
        );
        stats.ips += 1;
    }
    if let Some(ph) = get("phone").and_then(crate::core::validation::to_e164_au)
        && seen.insert(format!("ph:{ph}"))
    {
        push(
            Entity::new(EntityKind::Phone, &ph, confidence::NOTABLE, sid),
            "breach",
        );
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
        push(
            Entity::new(EntityKind::Address, addr, confidence::MEDIUM_SOLID, sid),
            "breach",
        );
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
        push(
            Entity::new(EntityKind::Domain, &dom, confidence::MEDIUM_PLUS, sid),
            "breach",
        );
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
    use crate::core::confidence;
    use crate::core::entity::{Entity, EntityKind, Evidence};
    use crate::core::validation::is_fragment_value;
    let mut push = |e: Entity, key: String| {
        if seen.insert(key) {
            let mut e = e;
            e.tag("import");
            e.tag("dossier");
            e.tag("dossier-list");
            // Provenance: every list item carries its origin as a corroborating
            // source. Without it `corroborating_sources()` is empty, which (a)
            // leaves the entity with no source trail in the dossier, and (b) bars
            // an Address from the offline geocode pass (`address_to_coords_pass`
            // skips source-less addresses), so a `CONTACT SUMMARY` residence never
            // became a Coordinates. `import:dossier` is a real corroborating
            // source (not enrichment), so this both records the origin and lets
            // the address feed the geo-correlation stack.
            e.add_evidence(Evidence::new(
                "import:dossier",
                format!("Aggregate {} from a breach key-data summary list", e.kind),
            ));
            entities.push(e);
            return true;
        }
        false
    };
    match section {
        DossierSection::Emails => {
            let em = val.to_ascii_lowercase();
            if em.contains('@') && !is_fragment_value(&EntityKind::Email, &em) {
                let e = Entity::new(EntityKind::Email, &em, confidence::MEDIUM_HIGH, sid);
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
                    let e = Entity::new(EntityKind::Email, &em, confidence::MEDIUM, sid);
                    if push(e, format!("em:{em}")) {
                        stats.emails += 1;
                    }
                }
            } else if val.len() >= 2 {
                let e = Entity::new(EntityKind::Username, val, confidence::MEDIUM, sid);
                if push(e, format!("un:{}", val.to_lowercase())) {
                    stats.usernames += 1;
                }
            }
        }
        DossierSection::Passwords => {
            if val.len() >= 8 {
                let e = Entity::new(EntityKind::Credential, val, confidence::MEDIUM, sid);
                if push(e, format!("cr:{val}")) {
                    stats.credentials += 1;
                }
            }
        }
        DossierSection::Names => {
            // Items are `Full Name: <person>` / `Company Name: <org>` (or a bare
            // name). A company is the subject's employer — an org pivot
            // (employer_pivot / ASIC); a full name is a Person.
            let (key, name) = match val.split_once(':') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
                None => (String::new(), val),
            };
            if name.len() < 2 {
                return;
            }
            if key.contains("company")
                || key.contains("organisation")
                || key.contains("organization")
            {
                let e = Entity::new(EntityKind::Organisation, name, confidence::MEDIUM, sid);
                if push(e, format!("org:{}", name.to_lowercase())) {
                    stats.organisations += 1;
                }
            } else if name.split_whitespace().count() >= 2
                && !crate::core::validation::is_placeholder_entity(&EntityKind::Person, name)
            {
                let e = Entity::new(EntityKind::Person, name, confidence::MEDIUM_HIGH, sid);
                if push(e, format!("pn:{}", name.to_lowercase())) {
                    stats.persons += 1;
                }
            }
        }
        DossierSection::Phones => {
            // AU-focused: keep only numbers `to_e164_au` can canonicalise — this
            // drops the bare foreign-national numbers (no recoverable country
            // code) while keeping every `+61`/`61…`/`0…` Australian number.
            if let Some(ph) = crate::core::validation::to_e164_au(val) {
                let e = Entity::new(EntityKind::Phone, &ph, confidence::MEDIUM_HIGH, sid);
                if push(e, format!("ph:{ph}")) {
                    stats.phones += 1;
                }
            }
        }
        DossierSection::Addresses => {
            // Items are `address: <full>` / `city:` / `state:` / `country:`.
            // Only a full `address:` line (or a bare specific value) names a
            // dwelling; a lone city/state/country is too coarse to pin one and
            // would fabricate a household (AU-049), so it is skipped.
            let candidate = match val.split_once(':') {
                Some((k, v)) if k.trim().eq_ignore_ascii_case("address") => v.trim(),
                Some(_) => "",
                None => val,
            };
            if !candidate.is_empty() && crate::core::validation::is_specific_residence(candidate) {
                let e = Entity::new(
                    EntityKind::Address,
                    candidate,
                    confidence::MEDIUM_LIGHT,
                    sid,
                );
                if push(e, format!("ad:{}", candidate.to_ascii_lowercase())) {
                    stats.addresses += 1;
                }
            }
        }
        DossierSection::IpAddresses => {
            if val.parse::<std::net::IpAddr>().is_ok() && !crate::core::validation::is_bogus_ip(val)
            {
                let e = Entity::new(EntityKind::IpAddress, val, confidence::MEDIUM_HIGH, sid);
                if push(e, format!("ip:{val}")) {
                    stats.ips += 1;
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
