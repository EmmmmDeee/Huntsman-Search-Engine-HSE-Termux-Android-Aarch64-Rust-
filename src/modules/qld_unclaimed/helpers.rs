//! Pure helper functions: query derivation, record parsing, entity building.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    scan::{Target, TargetKind},
};
use crate::util::ckan::field_str;
use crate::util::postcode_au::Locality;

use super::{ACTION_BASE, MAX_RECORDS, POSTCODE_CAP, RESOURCE_ID, SRC, SUBURB_CAP};

/// A 4-digit Australian postcode, else `None`.
pub(super) fn postcode(rec: &Map<String, Value>) -> Option<String> {
    let p = field_str(rec, "PCode")?;
    (p.len() == 4 && p.bytes().all(|b| b.is_ascii_digit())).then_some(p)
}

/// The register's full-text search ANDs multi-word queries, so seeding a full
/// name (`"Jordan Avery"`) only matches a row whose owner contains *both*
/// tokens — which silently misses the deceased-estate funds the register mostly
/// holds, where the money is owed to a *relative* (a different given name, same
/// surname). For a multi-token `FullName` we therefore search the **surname**
/// (last token) to surface the whole family, then classify each row back against
/// the full seed (see [`owner_matches_full_name`]). Single-token names and
/// organisations are searched verbatim.
pub(super) fn derive_query(target: &Target) -> &str {
    let v = target.value.trim();
    if matches!(target.kind, TargetKind::FullName)
        && let Some(surname) = v.split_whitespace().next_back()
        && surname.len() >= 3
        && surname.len() < v.len()
    {
        return surname;
    }
    v
}

/// True if `owner` contains every token of the seed name as a *whole word*
/// (case-insensitive) — i.e. this row is the seeded person, not merely a
/// surname-match relative. Whole-word (not substring) matching so a seed token
/// like `"M"` doesn't match inside `"AVERY"`, or `"ANN"` inside `"JOANNE"`,
/// which would wrongly upgrade a relative to `exact-name-match`. Tokenises on
/// non-alphanumeric boundaries and compares with `eq_ignore_ascii_case` (no
/// per-token `String` allocation).
pub(super) fn owner_matches_full_name(owner: &str, seed: &str) -> bool {
    let owner_words: Vec<&str> = owner
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let tokens: Vec<&str> = seed
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|tok| owner_words.iter().any(|w| w.eq_ignore_ascii_case(tok)))
}

/// Honorific tokens stripped from the FRONT of a parsed owner name, so the real
/// register's `"MR HERVE MOREAU"` yields the person "Herve Moreau", not the
/// title-polluted "Mr Herve Moreau" (which fragments his identity and breaks the
/// surname link). Matched case- and dot-insensitively.
const NAME_TITLES: &[&str] = &[
    "MR", "MRS", "MS", "MISS", "MX", "DR", "PROF", "REV", "SIR", "DAME", "MASTER", "MSTR", "MDM",
    "MADAME", "HON", "LADY", "LORD", "FR",
];

/// `<ALEXANDRE MOREAU>` — the register's notation for an ASSOCIATED person on a
/// record (a beneficiary, a child), captured as an extra owner. Non-nested.
static ANGLE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^<>]*)>").expect("valid"));

/// `(unknown owner)` / `(deceased)` / `(c/- …)` — a parenthesised NOTE, not a
/// person; dropped as noise so it can't masquerade as a name. Non-nested.
static PAREN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\([^()]*\)").expect("valid"));

/// The individual person name(s) in an unclaimed-money `owner` field — the richest
/// free family source, parsed against the register's REAL notations: joint owners
/// split on `&` / `and` / `+` / `;` / `,`; honorifics (`MR`/`MRS`/`DR`/…) stripped;
/// an associated `<NAME>` captured; a `(note)` dropped; and a `"SURNAME, GIVENS"`
/// reversal reordered. Companies are excluded (the Organisation pass owns them),
/// and every result is title-cased into a merge-stable `Person` value.
///
/// `"MR HERVE MOREAU + MRS MARIANNE MOREAU <ALEXANDRE MOREAU>"` →
/// `["Herve Moreau", "Marianne Moreau", "Alexandre Moreau"]` (a whole household);
/// `"MOREAU, VALERIE D"` → `["Valerie D Moreau"]`; `"HAYLEY DIEGMANN & CURT DIEGMANN"`
/// → `["Hayley Diegmann", "Curt Diegmann"]`; `"ACME PTY LTD"` / `"(unknown owner)"`
/// → `[]`. Surfacing each human owner as its own node is what lets the relation
/// layer connect the family — by surname from any seed, by the declared co-owner
/// link, and by co-residence at a shared address.
pub(super) fn owner_person_names(owner: &str) -> Vec<String> {
    // Pull out `<associated>` persons first, then strip `(notes)`; what remains is
    // the joint-owner body.
    let bracket_names: Vec<String> = ANGLE_RE
        .captures_iter(owner)
        .map(|c| c[1].trim().to_string())
        .collect();
    let no_angle = ANGLE_RE.replace_all(owner, " ");
    let body = PAREN_RE.replace_all(&no_angle, " ");

    // Normalise every joint separator to `&`, then split.
    let normalised = body
        .replace(" AND ", " & ")
        .replace(" and ", " & ")
        .replace(['+', ';'], " & ");
    let mut segments: Vec<String> = Vec::new();
    for part in normalised.split('&') {
        push_comma_segments(part.trim(), &mut segments);
    }
    segments.extend(bracket_names);

    let mut out: Vec<String> = Vec::new();
    for seg in &segments {
        if let Some(name) = clean_person_name(seg)
            && !out.contains(&name)
        {
            out.push(name);
        }
    }
    out
}

/// Split one `&`-delimited part on commas, disambiguating the two meanings of a
/// comma the register uses: a `"SURNAME, GIVENS"` REVERSAL (one token before a lone
/// comma → reordered to "GIVENS SURNAME") vs a co-owner SEPARATOR (`"A SMITH, B JONES"`).
fn push_comma_segments(part: &str, out: &mut Vec<String>) {
    if part.is_empty() {
        return;
    }
    if part.matches(',').count() == 1
        && let Some((head, tail)) = part.split_once(',')
        && head.split_whitespace().count() == 1
        && !head.trim().is_empty()
        && !tail.trim().is_empty()
    {
        out.push(format!("{} {}", tail.trim(), head.trim()));
        return;
    }
    for sub in part.split(',') {
        let s = sub.trim();
        if !s.is_empty() {
            out.push(s.to_string());
        }
    }
}

/// Validate and canonicalise one owner segment into a `Person` value, or `None` if
/// it isn't a usable individual: strip leading honorifics, require 2–4 name-shaped
/// tokens with at least one real (non-initial) word, exclude companies, title-case.
fn clean_person_name(raw: &str) -> Option<String> {
    let mut tokens: Vec<&str> = raw.split_whitespace().collect();
    while let Some(first) = tokens.first() {
        let bare = first.trim_end_matches('.').to_ascii_uppercase();
        if NAME_TITLES.contains(&bare.as_str()) {
            tokens.remove(0);
        } else {
            break;
        }
    }
    if !(2..=4).contains(&tokens.len()) {
        return None;
    }
    let joined = tokens.join(" ");
    if joined.len() < 5 {
        return None;
    }
    let name_shaped = joined
        .chars()
        .all(|c| c.is_alphabetic() || c.is_whitespace() || matches!(c, '-' | '\'' | '.'));
    if !name_shaped || crate::util::abn::looks_like_company(&joined) {
        return None;
    }
    // Reject an all-initials fragment ("L B"): a real name has a ≥2-letter word.
    if !tokens
        .iter()
        .any(|t| t.chars().filter(char::is_ascii_alphabetic).count() >= 2)
    {
        return None;
    }
    Some(crate::util::str_util::title_case(&joined))
}

/// The datastore_search URL for one full-text query.
pub(super) fn query_url(q: &str) -> String {
    crate::util::ckan::datastore_search_url(ACTION_BASE, RESOURCE_ID, q, MAX_RECORDS)
}

/// Merge an exact-name (`primary`) record set *ahead of* a broad surname
/// (`secondary`) set, de-duplicating on the CKAN row `_id`. Exact rows lead so
/// the seeded person's own record survives the `MAX_RECORDS` cap even when a
/// common surname returns a flood of unrelated namesakes ranked above them.
pub(super) fn merge_records(
    primary: Vec<Map<String, Value>>,
    secondary: Vec<Map<String, Value>>,
) -> Vec<Map<String, Value>> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    primary
        .into_iter()
        .chain(secondary)
        .filter(|rec| {
            let id = field_str(rec, "_id").unwrap_or_default();
            // Keep id-less rows (CKAN always sets `_id`; defensive) + first-seen ids.
            id.is_empty() || seen.insert(id)
        })
        .collect()
}

/// Pure transform: CKAN records → entities. One entity per record — a geocodable
/// `Address` built from the lodged postcode when present (so geocode/coords can
/// pivot on it), otherwise an `unclaimed_money` finding so the record is never
/// dropped. Each carries owner / amount / sender / date / reference as evidence.
pub(super) fn records_to_entities(
    records: &[Map<String, Value>],
    total: u64,
    seed: &str,
    broadened: bool,
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for rec in records.iter().take(MAX_RECORDS) {
        let owner = field_str(rec, "Owner").unwrap_or_else(|| "(unknown owner)".to_string());
        // The exact-vs-family split only has meaning when the query was
        // surname-*broadened* (a multi-token FullName). For a verbatim search
        // (organisation, single-token name) every row already AND-matched the
        // seed, so they're all direct hits — don't mislabel them as
        // `family-candidate` (which also under-weights them).
        let exact = !broadened || owner_matches_full_name(&owner, seed);
        let amount = field_str(rec, "Amount");
        let sender = field_str(rec, "SenderName");
        let date = field_str(rec, "DateRec");
        let reference = field_str(rec, "ClientId_ActNo");
        // Resolve the postcode once and reuse it for both the evidence attr and
        // the entity-kind decision below.
        let pc = postcode(rec);

        // Fold the optional money-trail fields into the evidence in a single
        // pass: only the present (`Some`) attributes are attached; owner /
        // register / total_matches always are.
        let ev = [
            ("amount_aud", amount.as_deref()),
            ("sender", sender.as_deref()),
            ("date_received", date.as_deref()),
            ("reference", reference.as_deref()),
            ("postcode", pc.as_deref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|val| (k, val)))
        .fold(
            Evidence::new(SRC, format!("QLD unclaimed money: {owner}")).with_attr("owner", &owner),
            |ev, (k, val)| ev.with_attr(k, val),
        )
        .with_attr("register", "QLD Public Trustee unclaimed monies")
        .with_attr("total_matches", total.to_string());

        // A bare postcode is a COARSE locator, not a residence, so even an
        // exact-name register hit stays a Candidate-tier `Address` (it must not
        // masquerade as a precise, Probable address) — its evidentiary weight
        // lives in the unclaimed-money evidence chain and in ranking above the
        // family/suburb guesses, where exact (0.38) still outranks family
        // (0.32). The `find_conf` for the non-geo `unclaimed_money` finding /
        // company Organisation keeps its full weight: those are real records,
        // not coarse geo.
        // Non-exact surname-only matches must stay below the 0.50 expansion
        // floor so unrelated family members (e.g. "MS DAWN BAMFORD") never
        // trigger pivots when scanning a specific individual.
        let (addr_conf, find_conf) = if exact { (0.38, 0.60) } else { (0.32, 0.35) };

        // Geo pivot when we have a usable postcode; otherwise a plain finding.
        // Borrow `pc` (don't move it) so the owner-Person pass below can still read
        // the postcode for its residency evidence.
        let mut entity = match &pc {
            Some(p) => {
                // Derive the OWNER's state from THEIR postcode, not the register's
                // jurisdiction. The QLD Public Trustee holds the money, but the
                // record carries the owner's last-known postcode, which spans every
                // state — the real data lists NSW 2xxx postcodes (a Brisbane family
                // member who moved to Sydney). Hardcoding "QLD" mis-placed them
                // geographically and tripped the AU-056 jurisdiction cross-check
                // (postcode-derived NSW vs a "QLD" tag). Fall back to QLD only when
                // the postcode resolves to no state.
                let state = crate::util::address_au::state_for_postcode(p).unwrap_or("QLD");
                let mut e = Entity::new(
                    EntityKind::Address,
                    format!("{state} {p}, Australia"),
                    addr_conf,
                    scan_id,
                );
                e.tag("postcode-only");
                // `geoint` only belongs on actual geo entities (Address/Coords);
                // the no-postcode finding below is not geographic.
                e.tag("geoint");
                // A postcode spans many localities — flag the coarseness so the
                // UI and geo rules treat it as a region, not a pinned address.
                e.tag("coarse");
                // Tag the owner's true state (postcode-derived) so the AU-056
                // jurisdiction cross-check compares like with like.
                e.tag(format!("au-state:{state}"));
                e
            }
            None => {
                let amt = amount.as_deref().unwrap_or("?");
                Entity::new(
                    EntityKind::Other("unclaimed_money".to_string()),
                    format!("{owner} — ${amt}"),
                    find_conf,
                    scan_id,
                )
            }
        };
        entity.tag(SRC);
        entity.tag("unclaimed-money");
        entity.tag("country:AU");
        entity.tag(if exact {
            "exact-name-match"
        } else {
            "family-candidate"
        });
        entity.add_evidence(ev);
        out.push(entity);

        // Emit each HUMAN owner as a first-class Person so the family/identity
        // graph has people to connect. The relation layer then binds them: the
        // shared surname links relatives from ANY seed angle (free), and a joint
        // record's co-owners are linked explicitly via the declared `co_owner`
        // attribute. Family-candidate Persons stay below the 0.50 expansion floor
        // (find_conf 0.35) so a relative is recorded and connected but never
        // pivot-scanned as if they were the subject; an exact register hit on the
        // seed merges with the name_intel subject anchor by its title-cased value.
        let owner_persons = owner_person_names(&owner);
        for (i, person) in owner_persons.iter().enumerate() {
            // Exactness is PER-PERSON, not per-record: on a joint "HAYLEY & CURT"
            // record seeded with "Curt", Curt is the exact subject while Hayley is
            // a surname-only family candidate — so each co-owner is judged on its
            // own name, and a family candidate stays below the 0.50 pivot floor.
            let person_exact = owner_matches_full_name(person, seed);
            let pconf = if person_exact { 0.60 } else { 0.35 };
            let mut p = Entity::new(EntityKind::Person, person, pconf, scan_id);
            p.tag(SRC);
            p.tag("unclaimed-money");
            p.tag("country:AU");
            p.tag(if person_exact {
                "exact-name-match"
            } else {
                "family-candidate"
            });
            let mut pev = Evidence::new(SRC, format!("QLD unclaimed money owner: {person}"))
                .with_attr("owner_name", person)
                .with_attr("register", "QLD Public Trustee unclaimed monies");
            if let Some(p4) = pc.as_deref() {
                pev = pev.with_attr("postcode", p4);
            }
            // Joint record → declare the co-owner association (cyclic over the
            // owners, so all co-owners on one record connect, not just a pair).
            if owner_persons.len() > 1 {
                pev = pev.with_attr("co_owner", &owner_persons[(i + 1) % owner_persons.len()]);
            }
            p.add_evidence(pev);
            out.push(p);
        }

        // Unclaimed money is often owed to *companies* (dividends, refunds) — and
        // frequently to joint syndicates of several companies. Emit one
        // `Organisation` per individually-resolvable company name so the engine's
        // expansion pivots each into abn_lookup / opencorporates and resolves its
        // ABN/ACN, connecting the unclaimed-money graph to the business registry.
        out.extend(
            crate::util::abn::company_names(&owner)
                .into_iter()
                .map(|company| {
                    let mut org =
                        Entity::new(EntityKind::Organisation, &company, find_conf, scan_id);
                    org.tag(SRC);
                    org.tag("unclaimed-money");
                    org.tag("country:AU");
                    org.tag("company-owner");
                    let mut oev =
                        Evidence::new(SRC, format!("Company owed unclaimed money: {company}"))
                            .with_attr("register", "QLD Public Trustee unclaimed monies");
                    if company != owner {
                        oev = oev.with_attr("joint_owner", &owner);
                    }
                    org.add_evidence(oev);
                    org
                }),
        );
    }
    out
}

/// Depth-of-enumeration: turn each resolved postcode→localities set into geo
/// entities — one rough `Coordinates` anchor at the postcode centroid plus a
/// suburb-precise, individually geocodable `Address` per locality
/// (`"Maleny, QLD 4552, Australia"`). These are *candidate* localities (the
/// owner is in one of them), so confidence is low and they carry a
/// `candidate-suburb` tag; the engine surfaces them as enumeration without
/// auto-expanding (below the 0.50 floor). Pure: takes the already-fetched map.
pub(super) fn suburbs_to_entities(
    pc_localities: &[(String, Vec<Locality>)],
    scan_id: &str,
) -> Vec<Entity> {
    let mut out = Vec::new();
    for (pc, locs) in pc_localities {
        // The owner's true state from their postcode (these are the seed's OWN
        // exact-match postcodes, normally QLD, but a NSW subject with QLD-held
        // money would otherwise be mis-stated). Fall back to QLD.
        let state = crate::util::address_au::state_for_postcode(pc).unwrap_or("QLD");
        if let Some(first) = locs.first() {
            let coords = format!("{:.5},{:.5}", first.lat, first.lon);
            let mut c = Entity::new(EntityKind::Coordinates, coords, 0.30, scan_id);
            c.tag(SRC);
            c.tag("country:AU");
            c.tag(format!("au-state:{state}"));
            c.tag("geoint");
            c.tag("postcode-centroid");
            c.tag("coarse");
            c.add_evidence(
                Evidence::new(SRC, format!("Centroid of postcode {pc}"))
                    .with_attr("postcode", pc)
                    .with_attr("source", "zippopotam"),
            );
            out.push(c);
        }
        for loc in locs.iter().take(SUBURB_CAP) {
            let mut a = Entity::new(
                EntityKind::Address,
                format!("{}, {state} {pc}, Australia", loc.suburb),
                0.30,
                scan_id,
            );
            a.tag(SRC);
            a.tag("country:AU");
            a.tag("geoint");
            a.tag("candidate-suburb");
            a.tag("coarse");
            a.add_evidence(
                Evidence::new(
                    SRC,
                    format!("Locality within postcode {pc}: {}", loc.suburb),
                )
                .with_attr("suburb", &loc.suburb)
                .with_attr("postcode", pc)
                .with_attr("lat", format!("{:.5}", loc.lat))
                .with_attr("lon", format!("{:.5}", loc.lon))
                .with_attr("source", "zippopotam"),
            );
            out.push(a);
        }
    }
    out
}

/// Postcodes of records that match the seed *exactly* — the seeded person's own
/// lodged postcode(s) — deduplicated in first-seen order and capped at
/// [`POSTCODE_CAP`]. Suburb enumeration is restricted to these so a surname-
/// broadened search doesn't fan every relative's postcode out into a pile of
/// candidate suburbs (the explosion this collapses). A verbatim
/// (non-broadened) search has no family/exact split, so every row qualifies.
pub(super) fn exact_postcodes(
    records: &[Map<String, Value>],
    seed: &str,
    broadened: bool,
) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for rec in records {
        let exact = !broadened
            || field_str(rec, "Owner").is_some_and(|o| owner_matches_full_name(&o, seed));
        if !exact {
            continue;
        }
        if let Some(pc) = postcode(rec)
            && seen.insert(pc.clone())
        {
            out.push(pc);
            if out.len() >= POSTCODE_CAP {
                break;
            }
        }
    }
    out
}
