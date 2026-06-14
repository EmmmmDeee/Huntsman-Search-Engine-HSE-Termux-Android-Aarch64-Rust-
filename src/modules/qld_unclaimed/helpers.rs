//! Pure helper functions: query derivation, record parsing, entity building.

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
        let mut entity = match pc {
            Some(p) => {
                let mut e = Entity::new(
                    EntityKind::Address,
                    format!("QLD {p}, Australia"),
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
                // This register is Queensland-only; tag state explicitly so
                // AU-056 jurisdiction cross-check can use it without re-parsing.
                e.tag("au-state:QLD");
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
        if let Some(first) = locs.first() {
            let coords = format!("{:.5},{:.5}", first.lat, first.lon);
            let mut c = Entity::new(EntityKind::Coordinates, coords, 0.30, scan_id);
            c.tag(SRC);
            c.tag("country:AU");
            c.tag("au-state:QLD");
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
                format!("{}, QLD {pc}, Australia", loc.suburb),
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
            || field_str(rec, "Owner")
                .map(|o| owner_matches_full_name(&o, seed))
                .unwrap_or(false);
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
