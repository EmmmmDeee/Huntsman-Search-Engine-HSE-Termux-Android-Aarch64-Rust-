//! Queensland Public Trustee unclaimed-money lookup (keyless, free).
//!
//! Endpoint: `GET https://www.data.qld.gov.au/api/3/action/datastore_search`
//!           `?resource_id={RESOURCE_ID}&q={name}&limit=20`
//! Auth:     none — the Queensland Government Open Data Portal (CKAN) exposes
//!           the Public Trustee's unclaimed-monies register as a public,
//!           datastore-active resource refreshed weekly.
//!
//! The register lists money owed to people from deceased estates and lodged
//! unclaimed funds (insurance refunds, payroll remainders, government refunds,
//! …). For a person/organisation seed we full-text search the register and, for
//! every matching record, emit the owner's lodged postcode as a geocodable
//! `Address` (so the GEOINT pipeline can pivot on it) carrying the owner, amount,
//! sender, date and reference number as evidence. Records with no usable
//! postcode still surface as an `unclaimed_money` finding so the money is never
//! silently dropped.
//!
//! This is exactly the Australian people-centric public-records source the
//! charter targets: free, keyless, structured JSON, and it chains into geocode →
//! coordinates.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::ckan::{Response as CkanResp, field_str};
use crate::util::http::fetch_json;
use crate::util::postcode_au::Locality;

const SRC: &str = "qld_unclaimed";

/// CKAN action-endpoint base for the Queensland Government Open Data Portal.
const ACTION_BASE: &str = "https://www.data.qld.gov.au/api/3/action";

/// CKAN resource id of the Public Trustee "Unclaimed monies" register on
/// `data.qld.gov.au`. Stable per-resource; if the portal ever re-publishes the
/// register under a new resource this is the single value to update.
const RESOURCE_ID: &str = "872065ae-ddfd-4b5f-ad15-e1935dadd883";

/// Cap on records turned into entities for one seed — common surnames can match
/// hundreds of rows; we keep the highest-ranked handful so a single name doesn't
/// flood the graph.
const MAX_RECORDS: usize = 20;

/// Max distinct postcodes resolved to suburb-sets per scan (each is one HTTP
/// call to Zippopotam), and max suburbs enumerated per postcode.
const POSTCODE_CAP: usize = 6;
const SUBURB_CAP: usize = 8;

pub struct QldUnclaimed;

/// A 4-digit Australian postcode, else `None`.
fn postcode(rec: &Map<String, Value>) -> Option<String> {
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
fn derive_query(target: &Target) -> &str {
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
fn owner_matches_full_name(owner: &str, seed: &str) -> bool {
    let owner_words: Vec<&str> = owner
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect();
    let mut any = false;
    for tok in seed
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
    {
        any = true;
        if !owner_words.iter().any(|w| w.eq_ignore_ascii_case(tok)) {
            return false;
        }
    }
    any
}

/// The datastore_search URL for one full-text query.
fn query_url(q: &str) -> String {
    crate::util::ckan::datastore_search_url(ACTION_BASE, RESOURCE_ID, q, MAX_RECORDS)
}

/// Merge an exact-name (`primary`) record set *ahead of* a broad surname
/// (`secondary`) set, de-duplicating on the CKAN row `_id`. Exact rows lead so
/// the seeded person's own record survives the `MAX_RECORDS` cap even when a
/// common surname returns a flood of unrelated namesakes ranked above them.
fn merge_records(
    primary: Vec<Map<String, Value>>,
    secondary: Vec<Map<String, Value>>,
) -> Vec<Map<String, Value>> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(primary.len() + secondary.len());
    for rec in primary.into_iter().chain(secondary) {
        let id = field_str(&rec, "_id").unwrap_or_default();
        // Keep id-less rows (CKAN always sets `_id`, so this is just defensive)
        // and any id not seen before.
        if id.is_empty() || seen.insert(id) {
            out.push(rec);
        }
    }
    out
}

/// Pure transform: CKAN records → entities. One entity per record — a geocodable
/// `Address` built from the lodged postcode when present (so geocode/coords can
/// pivot on it), otherwise an `unclaimed_money` finding so the record is never
/// dropped. Each carries owner / amount / sender / date / reference as evidence.
fn records_to_entities(
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

        let mut ev = Evidence::new(SRC, format!("QLD unclaimed money: {owner}"));
        ev = ev.with_attr("owner", &owner);
        if let Some(a) = amount.as_deref() {
            ev = ev.with_attr("amount_aud", a);
        }
        if let Some(s) = sender.as_deref() {
            ev = ev.with_attr("sender", s);
        }
        if let Some(d) = date.as_deref() {
            ev = ev.with_attr("date_received", d);
        }
        if let Some(r) = reference.as_deref() {
            ev = ev.with_attr("reference", r);
        }
        // Resolve the postcode once and reuse it for both the evidence attr and
        // the entity-kind decision below.
        let pc = postcode(rec);
        if let Some(ref p) = pc {
            ev = ev.with_attr("postcode", p);
        }
        ev = ev
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
        for company in crate::util::abn::company_names(&owner) {
            let mut org = Entity::new(EntityKind::Organisation, &company, find_conf, scan_id);
            org.tag(SRC);
            org.tag("unclaimed-money");
            org.tag("country:AU");
            org.tag("company-owner");
            let mut oev = Evidence::new(SRC, format!("Company owed unclaimed money: {company}"))
                .with_attr("register", "QLD Public Trustee unclaimed monies");
            if company != owner {
                oev = oev.with_attr("joint_owner", &owner);
            }
            org.add_evidence(oev);
            out.push(org);
        }
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
fn suburbs_to_entities(pc_localities: &[(String, Vec<Locality>)], scan_id: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for (pc, locs) in pc_localities {
        if let Some(first) = locs.first() {
            let coords = format!("{:.5},{:.5}", first.lat, first.lon);
            let mut c = Entity::new(EntityKind::Coordinates, coords, 0.30, scan_id);
            c.tag(SRC);
            c.tag("country:AU");
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
fn exact_postcodes(records: &[Map<String, Value>], seed: &str, broadened: bool) -> Vec<String> {
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

#[async_trait]
impl Module for QldUnclaimed {
    fn name(&self) -> &'static str {
        "qld_unclaimed"
    }

    fn description(&self) -> &'static str {
        "Queensland Public Trustee unclaimed-money register lookup (free, keyless)"
    }

    fn priority(&self) -> u8 {
        // Government / public-records band (110-118): unclaimed-money registry,
        // dispatched with the other AU gov sources, above the generic free band.
        114
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn category(&self) -> ModuleCategory {
        // Person-centric record lookup: resolves a name to a government
        // register entry and its Address/Coordinates. Previously uncategorised
        // (defaulted to `Other`), which excluded it from any category-focused
        // scan (e.g. `skiptrace`) despite being a direct person-locator.
        ModuleCategory::People
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::FullName | TargetKind::Organisation)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[
            EntityKind::Address,
            EntityKind::Coordinates,
            EntityKind::Organisation,
        ];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        10_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let full = target.value.trim();
        // The register full-text search needs a meaningful token; a 1–2 char
        // query would match noise across a 240 MB dataset.
        if full.len() < 3 {
            return Ok(ModuleResult::new());
        }
        // `derive_query` broadens a multi-token full name to its surname so
        // relatives' deceased-estate funds surface; equals `full` otherwise.
        let surname = derive_query(target);

        // Broad query (surname, or the verbatim value): family-level recall.
        let broad: CkanResp = fetch_json(&ctx.http, SRC, &query_url(surname)).await?;
        // Surface an application-level CKAN failure (success=false) as a module
        // error rather than masquerading as "no findings".
        if broad.success == Some(false) {
            return Err(crate::core::error::Error::module(
                SRC,
                "CKAN datastore_search returned success=false (bad resource id or portal error)",
            ));
        }
        let Some(broad_res) = broad.result else {
            return Ok(ModuleResult::new());
        };
        let total = broad_res.total.unwrap_or(broad_res.records.len() as u64);
        let mut records = broad_res.records;

        // Two-tier precision: when we broadened to a surname, also run the exact
        // full-name query (AND-matched) and place those rows FIRST, so the
        // seeded person's own record is never capped out behind a common
        // surname's namesakes. A failed exact probe is non-fatal — broad stands.
        if surname != full
            && let Ok(exact) = fetch_json::<CkanResp>(&ctx.http, SRC, &query_url(full)).await
            && let Some(exact_res) = exact.result
        {
            records = merge_records(exact_res.records, records);
        }

        // `surname != full` ⇔ derive_query broadened a multi-token FullName to
        // its surname, which is exactly when the exact-vs-family split applies.
        let broadened = surname != full;

        // Depth-of-enumeration: resolve the seeded person's *own* postcode(s) to
        // their constituent suburbs (Zippopotam, keyless). A bare postcode is a
        // coarse signal — a QLD postcode spans many localities — so we expand it
        // into suburb-precise, geocodable Address candidates. Restricted to
        // exact-name records so relatives' surname-only postcodes don't fan out;
        // best-effort and capped, each lookup non-fatal.
        let mut pc_localities: Vec<(String, Vec<Locality>)> = Vec::new();
        for pc in exact_postcodes(&records, full, broadened) {
            let locs = crate::util::postcode_au::localities(&ctx.http, &pc).await;
            if !locs.is_empty() {
                pc_localities.push((pc, locs));
            }
        }

        let mut out = ModuleResult::new();
        out.extend(records_to_entities(
            &records,
            total,
            full,
            broadened,
            &ctx.scan_id,
        ));
        out.extend(suburbs_to_entities(&pc_localities, &ctx.scan_id));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CkanResp {
        // The exact shape returned by datastore_search for q=Avery.
        let raw = r#"{
            "result": {
                "total": 3,
                "records": [
                    {"_id":1938437,"ClientId_ActNo":"210580670460","Owner":"HAYLEY AVERY & CURT AVERY","Amount":"545.74","SenderName":"INSURANCE AUSTRALIA GROUP LIMITED","DateRec":"2024-03-14","PCode":"4557","rank":0.0706241},
                    {"_id":913780,"ClientId_ActNo":"207768336631","Owner":"CURT AVERY","Amount":"0.92","SenderName":"REMUNERATION SERVICES","DateRec":"2015-03-31","PCode":"4555","rank":0.057308756},
                    {"_id":1082370,"ClientId_ActNo":"208285682789","Owner":"ERIK AVERY","Amount":"115.45","SenderName":"UNCM DEPT OF TPT AND MAIN ROADS - MAIN ROAD","DateRec":"2016-10-17","PCode":"4552","rank":0.057308756}
                ]
            }
        }"#;
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn accepts_fullname_and_org_only() {
        let m = QldUnclaimed;
        assert!(m.accepts(&Target::new(TargetKind::FullName, "Jordan Avery")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "ACME Pty Ltd")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_metadata() {
        let m = QldUnclaimed;
        assert_eq!(m.name(), "qld_unclaimed");
        assert!(!m.description().is_empty());
        assert_eq!(m.cost(), ModuleCost::Free);
    }

    #[test]
    fn derive_query_broadens_full_name_to_surname() {
        // Full name → surname (so the AND search surfaces relatives' estate funds).
        assert_eq!(
            derive_query(&Target::new(TargetKind::FullName, "Jordan Avery")),
            "Avery"
        );
        assert_eq!(
            derive_query(&Target::new(TargetKind::FullName, "  Curt   Avery  ")),
            "Avery"
        );
        // Single-token name → verbatim.
        assert_eq!(
            derive_query(&Target::new(TargetKind::FullName, "Cher")),
            "Cher"
        );
        // Organisation → verbatim (no surname semantics).
        assert_eq!(
            derive_query(&Target::new(TargetKind::Organisation, "ACME Pty Ltd")),
            "ACME Pty Ltd"
        );
    }

    #[test]
    fn classifies_exact_person_vs_surname_only_family() {
        let resp = sample();
        let result = resp.result.unwrap();

        // Seeding the user's full name (no register row contains "MATTHEW"):
        // every Avery row is a family candidate, none an exact match.
        let fam = records_to_entities(&result.records, 3, "Jordan Avery", true, "s");
        assert!(
            fam.iter()
                .all(|e| e.tags.iter().any(|t| t.as_str() == "family-candidate")),
            "surname-only relatives must be tagged family-candidate"
        );
        assert!(
            fam.iter()
                .all(|e| !e.tags.iter().any(|t| t.as_str() == "exact-name-match"))
        );

        // Seeding "Curt Avery": the two Curt rows are exact, Erik is family.
        let resp2 = sample();
        let result2 = resp2.result.unwrap();
        let curt = records_to_entities(&result2.records, 3, "Curt Avery", true, "s");
        let exact = |e: &Entity| e.tags.iter().any(|t| t.as_str() == "exact-name-match");
        assert!(exact(&curt[0]), "HAYLEY & CURT row is an exact Curt match");
        assert!(exact(&curt[1]), "CURT AVERY row is an exact Curt match");
        assert!(!exact(&curt[2]), "ERIK row is only a surname match");
        // Exact hits outrank family candidates on confidence.
        assert!(curt[1].confidence > curt[2].confidence);
    }

    #[test]
    fn company_owner_emits_organisation_for_abn_pivot() {
        // Unclaimed money owed to a company → an extra Organisation entity that
        // the engine will expand into abn_lookup / opencorporates.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":7,"Owner":"ACME WIDGETS PTY LTD","Amount":"1200.00","SenderName":"ASX","PCode":"4000"}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let recs = resp.result.unwrap().records;
        let ents = records_to_entities(&recs, 1, "ACME Widgets", true, "s");
        // Address (geo) + Organisation (ABN pivot).
        assert_eq!(ents.len(), 2);
        assert!(ents.iter().any(|e| e.kind == EntityKind::Address));
        let org = ents
            .iter()
            .find(|e| e.kind == EntityKind::Organisation)
            .expect("company owner must emit an Organisation");
        assert_eq!(org.value, "ACME WIDGETS PTY LTD");
        assert!(org.tags.iter().any(|t| t.as_str() == "company-owner"));

        // An individual owner emits no Organisation (no ABN pivot noise).
        let raw2 = r#"{"result":{"total":1,"records":[
            {"_id":8,"Owner":"JANE CITIZEN","Amount":"5.00","PCode":"4000"}
        ]}}"#;
        let recs2: Vec<Map<String, Value>> = serde_json::from_str::<CkanResp>(raw2)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents2 = records_to_entities(&recs2, 1, "Jane Citizen", true, "s");
        assert_eq!(ents2.len(), 1, "individual owner → no Organisation");
        assert!(ents2.iter().all(|e| e.kind != EntityKind::Organisation));

        // A real joint syndicate splits into one resolvable Organisation each.
        let raw3 = r#"{"result":{"total":1,"records":[
            {"_id":9,"Owner":"DEV PTY LTD & GWAD PTY LTD & GWAD2 PTY LTD","Amount":"508.80","SenderName":"QLD URBAN UTILITIES","PCode":"4051"}
        ]}}"#;
        let recs3: Vec<Map<String, Value>> = serde_json::from_str::<CkanResp>(raw3)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents3 = records_to_entities(&recs3, 1, "DEV", true, "s");
        let orgs: Vec<&str> = ents3
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(orgs, vec!["DEV PTY LTD", "GWAD PTY LTD", "GWAD2 PTY LTD"]);
        // Split orgs carry the original joint owner in evidence for context.
        let dev = ents3.iter().find(|e| e.value == "DEV PTY LTD").unwrap();
        assert!(
            dev.evidence[0]
                .attributes
                .iter()
                .any(|(k, _)| k.as_str() == "joint_owner")
        );
    }

    #[test]
    fn suburbs_enumerate_into_geocodable_candidates() {
        // Postcode 4552 → its localities (incl. the user's home, Booroobin).
        let locs = vec![
            Locality {
                suburb: "Maleny".into(),
                lat: -26.729,
                lon: 152.7554,
            },
            Locality {
                suburb: "Booroobin".into(),
                lat: -26.729,
                lon: 152.7554,
            },
            Locality {
                suburb: "Conondale".into(),
                lat: -26.7333,
                lon: 152.7167,
            },
        ];
        let ents = suburbs_to_entities(&[("4552".to_string(), locs)], "s");
        // One centroid Coordinates + one Address per locality.
        let coords: Vec<&Entity> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Coordinates)
            .collect();
        assert_eq!(coords.len(), 1);
        assert!(
            coords[0]
                .tags
                .iter()
                .any(|t| t.as_str() == "postcode-centroid")
        );

        let addrs: Vec<&str> = ents
            .iter()
            .filter(|e| e.kind == EntityKind::Address)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            addrs,
            vec![
                "Maleny, QLD 4552, Australia",
                "Booroobin, QLD 4552, Australia",
                "Conondale, QLD 4552, Australia",
            ]
        );
        // Candidate suburbs stay below the 0.50 expansion floor.
        assert!(
            ents.iter()
                .all(|e| e.confidence < 0.50 && e.tags.iter().any(|t| t.as_str() == SRC))
        );
        // The Address evidence carries the suburb + per-locality coordinates.
        let maleny = ents.iter().find(|e| e.value.starts_with("Maleny")).unwrap();
        let attr = |k: &str| {
            maleny.evidence[0]
                .attributes
                .iter()
                .find(|(a, _)| a.as_str() == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("suburb"), Some("Maleny"));
        assert_eq!(attr("postcode"), Some("4552"));
    }

    #[test]
    fn suburbs_enumerated_only_for_exact_match_postcodes() {
        // The fan-out collapse: a surname-broadened search enumerates suburbs
        // ONLY for the seeded person's own (exact-name) postcode — never every
        // relative's. With the sample register (ERIK@4552, CURT@4555,
        // HAYLEY&CURT@4557), seeding "Erik Avery" yields just 4552.
        let recs = sample().result.unwrap().records;
        assert_eq!(exact_postcodes(&recs, "Erik Avery", true), vec!["4552"]);
        // Seeding a surname whose full name matches no row → no suburb fan-out
        // at all (relatives' postcodes are not the seed's residence).
        assert!(exact_postcodes(&recs, "Jordan Avery", true).is_empty());
        // A verbatim (non-broadened) search treats every row as a direct hit,
        // so all distinct postcodes qualify (first-seen order).
        assert_eq!(
            exact_postcodes(&recs, "Avery", false),
            vec!["4557", "4555", "4552"]
        );
    }

    #[test]
    fn postcode_only_address_is_coarse_candidate_not_probable() {
        // #3: a bare postcode must not rank as a precise (Probable) address.
        // Even an exact-name hit is a Candidate-tier, `coarse`-tagged Address;
        // its register evidence carries the actual weight.
        let recs = sample().result.unwrap().records;
        let erik = records_to_entities(&recs, 3, "Erik Avery", true, "s");
        let addr = erik
            .iter()
            .find(|e| e.kind == EntityKind::Address && e.value.contains("4552"))
            .expect("Erik's exact postcode Address");
        assert!(addr.tags.iter().any(|t| t == "exact-name-match"));
        assert!(addr.tags.iter().any(|t| t == "postcode-only"));
        assert!(addr.tags.iter().any(|t| t == "coarse"));
        // No geo_normalize in a unit context → c_eff == base (0.38) → Candidate.
        assert!(
            addr.confidence < 0.40,
            "coarse postcode must be sub-Probable"
        );
        assert_eq!(
            addr.classify(),
            crate::core::entity::Classification::Candidate
        );
    }

    #[test]
    fn ckan_success_false_is_captured() {
        // A CKAN application error (HTTP 200, success=false) must be visible so
        // process() can surface it instead of treating it as "no findings".
        let err: CkanResp =
            serde_json::from_str(r#"{"success":false,"error":{"message":"Resource not found"}}"#)
                .unwrap();
        assert_eq!(err.success, Some(false));
        assert!(err.result.is_none());
        // A normal empty result is success=true with an empty record set.
        let ok: CkanResp =
            serde_json::from_str(r#"{"success":true,"result":{"total":0,"records":[]}}"#).unwrap();
        assert_eq!(ok.success, Some(true));
        assert_eq!(ok.result.unwrap().records.len(), 0);
    }

    #[test]
    fn verbatim_search_never_tags_family_candidate() {
        // Organisation / single-token seeds are searched verbatim (not surname-
        // broadened), so every returned row is a direct AND-match — classify all
        // as exact, never `family-candidate` (which would under-weight a genuine
        // hit). broadened = false here.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":1,"Owner":"ACME WIDGETS PTY LTD","Amount":"10.00","PCode":"4000"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .unwrap()
            .result
            .unwrap()
            .records;
        // Seed "ACME PTY LTD" doesn't whole-word-match all of the owner, but for a
        // verbatim (non-broadened) search it's still a direct hit, not family.
        let ents = records_to_entities(&recs, 1, "ACME PTY LTD", false, "s");
        let addr = ents.iter().find(|e| e.kind == EntityKind::Address).unwrap();
        assert!(addr.tags.iter().any(|t| t.as_str() == "exact-name-match"));
        assert!(!addr.tags.iter().any(|t| t.as_str() == "family-candidate"));
    }

    #[test]
    fn owner_match_is_whole_word_not_substring() {
        // Whole-word matching: a short seed token must NOT substring-match inside
        // an owner word (the bug flagged in review).
        assert!(!owner_matches_full_name("CURT AVERY", "M Avery")); // "M" ⊄ word
        assert!(!owner_matches_full_name("JOANNE CITIZEN", "Ann Citizen")); // "ANN" ⊄ JOANNE
        // True whole-word matches still hold, order-independent, punctuation-split.
        assert!(owner_matches_full_name(
            "HAYLEY AVERY & CURT AVERY",
            "Curt Avery"
        ));
        assert!(owner_matches_full_name("MS SILVA KAREEM", "silva kareem"));
        // A relative (surname only) is not an exact match.
        assert!(!owner_matches_full_name("ERIK AVERY", "Curt Avery"));
    }

    #[test]
    fn no_postcode_finding_is_not_tagged_geoint() {
        // The Other("unclaimed_money") fallback is not a geo entity → no geoint.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":1,"Owner":"NO POSTCODE PERSON","Amount":"42.00","SenderName":"X"}
        ]}}"#;
        let recs = serde_json::from_str::<CkanResp>(raw)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents = records_to_entities(&recs, 1, "No Postcode Person", true, "s");
        assert_eq!(
            ents[0].kind,
            EntityKind::Other("unclaimed_money".to_string())
        );
        assert!(!ents[0].tags.iter().any(|t| t.as_str() == "geoint"));
        // …but a postcode-bearing Address still is.
        let raw2 = r#"{"result":{"total":1,"records":[
            {"_id":2,"Owner":"GEO PERSON","Amount":"1.00","PCode":"4000"}
        ]}}"#;
        let recs2 = serde_json::from_str::<CkanResp>(raw2)
            .unwrap()
            .result
            .unwrap()
            .records;
        let ents2 = records_to_entities(&recs2, 1, "Geo Person", true, "s");
        assert!(ents2[0].tags.iter().any(|t| t.as_str() == "geoint"));
    }

    #[test]
    fn merge_records_puts_exact_first_and_dedups_on_id() {
        // Exact probe returns the seeded person (id 50); broad surname probe
        // returns a flood including that same row (id 50) plus namesakes.
        let exact: Vec<Map<String, Value>> =
            serde_json::from_str(r#"[{"_id":50,"Owner":"JOHN SMITH","PCode":"4000"}]"#).unwrap();
        let broad: Vec<Map<String, Value>> = serde_json::from_str(
            r#"[{"_id":11,"Owner":"ALICE SMITH"},{"_id":50,"Owner":"JOHN SMITH"},{"_id":12,"Owner":"BOB SMITH"}]"#,
        )
        .unwrap();
        let merged = merge_records(exact, broad);
        // id 50 appears once, and FIRST (survives the cap ahead of namesakes).
        assert_eq!(merged.len(), 3, "the duplicate id 50 is collapsed");
        assert_eq!(field_str(&merged[0], "_id").as_deref(), Some("50"));
        let ids: Vec<String> = merged.iter().filter_map(|r| field_str(r, "_id")).collect();
        assert_eq!(ids, vec!["50", "11", "12"]);
    }

    #[test]
    fn common_polysemous_surname_produces_no_false_exact_matches() {
        // Real rows from q=Kareem — a common name appearing as given name, surname
        // and middle element across UNRELATED people state-wide. Seeding "Ali
        // Kareem" (no row contains "ALI") must classify every row as a low-weight
        // family-candidate and zero as an exact match, so a common surname can't
        // masquerade as the seeded person or auto-expand (0.40 C_eff < 0.50 floor).
        let raw = r#"{"result":{"total":17,"records":[
            {"_id":1,"Owner":"KAREEM AYALA","Amount":"4.45","SenderName":"GOLDEN CASKET","DateRec":"2024-03-19","PCode":"4740"},
            {"_id":2,"Owner":"MS SILVA KAREEM","Amount":"387.54","SenderName":"QLD URBAN UTILITIES","DateRec":"2024-07-25","PCode":"4305"},
            {"_id":3,"Owner":"HUSSEIN KHALEEL KAREEM","Amount":"267.45","SenderName":"DEPT TPT MAIN ROADS","DateRec":"2021-02-18","PCode":"4118"},
            {"_id":4,"Owner":"MR J KAREEM","Amount":"1.95","SenderName":"ENERGEX","DateRec":"2006-02-16","PCode":"2880"}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let recs = resp.result.unwrap().records;
        let ents = records_to_entities(&recs, 17, "Ali Kareem", true, "s");
        // All four Kareem owners are individuals → no Organisation/ABN pivots:
        // four entities exactly, none a company (the ABN incorporation stays
        // silent on a non-business family).
        assert_eq!(ents.len(), 4);
        assert!(
            ents.iter().all(|e| e.kind != EntityKind::Organisation),
            "individual owners must not manufacture company/ABN entities"
        );
        for e in &ents {
            assert!(
                e.tags.iter().any(|t| t.as_str() == "family-candidate"),
                "common-surname row must be a family candidate, not the seed"
            );
            assert!(!e.tags.iter().any(|t| t.as_str() == "exact-name-match"));
            // Below the 0.50 expansion floor, so state-wide name noise can't pivot.
            assert!(e.confidence < 0.50);
        }
        // The interstate row (Broken Hill, NSW 2880) is still surfaced, not dropped.
        assert!(ents.iter().any(|e| e.value.contains("2880")));

        // Control: a seed that genuinely matches one row ("Silva Kareem") flips
        // exactly that row to an exact match — the classifier is not just always-family.
        let silva = records_to_entities(&recs, 17, "Silva Kareem", true, "s");
        assert!(
            silva[1]
                .tags
                .iter()
                .any(|t| t.as_str() == "exact-name-match"),
            "MS SILVA KAREEM must be exact for seed 'Silva Kareem'"
        );
        assert!(
            !silva[0]
                .tags
                .iter()
                .any(|t| t.as_str() == "exact-name-match"),
            "KAREEM AYALA must stay a family candidate for seed 'Silva Kareem'"
        );
    }

    #[test]
    fn parses_records_into_geo_addresses() {
        let resp = sample();
        let result = resp.result.unwrap();
        let ents = records_to_entities(
            &result.records,
            result.total.unwrap(),
            "Avery",
            true,
            "scan-1",
        );
        assert_eq!(ents.len(), 3, "one entity per record");

        // All three rows have valid 4-digit postcodes → geocodable Address entities.
        for e in &ents {
            assert_eq!(e.kind, EntityKind::Address);
            assert!(e.value.contains("QLD"));
            assert!(e.value.ends_with(", Australia"));
            assert!(e.tags.iter().any(|t| t.as_str() == "unclaimed-money"));
            assert!(e.tags.iter().any(|t| t.as_str() == "country:AU"));
        }
        assert_eq!(ents[0].value, "QLD 4557, Australia");

        // Evidence preserves the money trail verbatim (owner / amount / sender).
        let ev0 = &ents[0].evidence[0];
        let attr = |k: &str| {
            ev0.attributes
                .iter()
                .find(|(a, _)| a.as_str() == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(attr("owner"), Some("HAYLEY AVERY & CURT AVERY"));
        assert_eq!(attr("amount_aud"), Some("545.74"));
        assert_eq!(attr("sender"), Some("INSURANCE AUSTRALIA GROUP LIMITED"));
        assert_eq!(attr("postcode"), Some("4557"));
        assert_eq!(attr("reference"), Some("210580670460"));
        assert_eq!(attr("total_matches"), Some("3"));
    }

    #[test]
    fn record_without_postcode_becomes_finding_not_dropped() {
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":1,"Owner":"NO POSTCODE PERSON","Amount":"42.00","SenderName":"SOME SENDER"}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let result = resp.result.unwrap();
        let ents = records_to_entities(&result.records, 1, "NO POSTCODE PERSON", true, "scan-1");
        assert_eq!(ents.len(), 1, "no-postcode record must still surface");
        assert_eq!(
            ents[0].kind,
            EntityKind::Other("unclaimed_money".to_string())
        );
        assert!(ents[0].value.contains("NO POSTCODE PERSON"));
        assert!(ents[0].value.contains("42.00"));
    }

    #[test]
    fn numeric_ckan_fields_are_stringified_not_dropped() {
        // CKAN may type Amount/PCode as numbers; field_str must still render them.
        let raw = r#"{"result":{"total":1,"records":[
            {"_id":2,"Owner":"NUMERIC FIELDS","Amount":99.5,"SenderName":"X","PCode":4000}
        ]}}"#;
        let resp: CkanResp = serde_json::from_str(raw).unwrap();
        let result = resp.result.unwrap();
        let ents = records_to_entities(&result.records, 1, "NUMERIC FIELDS", true, "scan-1");
        assert_eq!(ents.len(), 1);
        // PCode 4000 (numeric) is recognised as a valid postcode → Address.
        assert_eq!(ents[0].kind, EntityKind::Address);
        assert_eq!(ents[0].value, "QLD 4000, Australia");
        let ev = &ents[0].evidence[0];
        let amt = ev
            .attributes
            .iter()
            .find(|(a, _)| a.as_str() == "amount_aud")
            .map(|(_, v)| v.as_str());
        assert_eq!(amt, Some("99.5"));
    }
}
